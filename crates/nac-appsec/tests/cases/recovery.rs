use crate::support::*;
use nac_appsec::*;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct CrashRepository {
    inner: SqliteRepository,
    phase: String,
    marker: PathBuf,
    updates: std::sync::atomic::AtomicUsize,
}

fn gate(marker: &std::path::Path) -> Result<()> {
    std::fs::write(marker, b"worker reached crash boundary")?;
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

impl Repository for CrashRepository {
    fn insert(&self, campaign: &Campaign) -> Result<()> {
        self.inner.insert(campaign)
    }
    fn read(&self, run: Id) -> Result<Campaign> {
        self.inner.read(run)
    }
    fn update(
        &self,
        run: Id,
        revision: Option<u64>,
        operation: &mut dyn FnMut(&mut Campaign, u32) -> Result<()>,
    ) -> Result<Campaign> {
        let update = self
            .updates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.phase == "after_upload" && update == 1 {
            gate(&self.marker)?;
        }
        let campaign = self.inner.update(run, revision, operation)?;
        if self.phase == "after_commit" && update == 1 {
            gate(&self.marker)?;
        }
        Ok(campaign)
    }
}

#[test]
#[ignore = "child-process entry point, launched by recovery test"]
fn crash_worker_entry() -> Result<()> {
    let state = PathBuf::from(std::env::var("APPSEC_TEST_STATE")?);
    let marker = PathBuf::from(std::env::var("APPSEC_TEST_MARKER")?);
    let phase = std::env::var("APPSEC_TEST_PHASE")?;
    let lease: Lease = serde_json::from_str(&std::env::var("APPSEC_TEST_LEASE")?)?;
    let repository = CrashRepository {
        inner: SqliteRepository::open(&state, 1)?,
        phase: phase.clone(),
        marker: marker.clone(),
        updates: std::sync::atomic::AtomicUsize::new(0),
    };
    let controller = Controller::new(repository, ArtifactStore::open(&state)?, SystemClock);
    let campaign = controller.status(lease.run_id)?;
    let submission = candidate(&campaign.manifest)?;
    if phase == "before_upload" {
        gate(&marker)?;
    }
    controller.submit(&lease, "worker-observation", submission)?;
    if phase == "before_ack" {
        gate(&marker)?;
    }
    Ok(())
}

struct ProcessWorker {
    state: PathBuf,
    marker: PathBuf,
    phase: String,
    child: Option<Child>,
}

impl Drop for ProcessWorker {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Runtime for ProcessWorker {
    fn check_capabilities(&self) -> Result<()> {
        Ok(())
    }
    fn start(&mut self, assignment: &Assignment) -> Result<()> {
        self.child = Some(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "recovery::crash_worker_entry",
                    "--ignored",
                    "--nocapture",
                ])
                .env("APPSEC_TEST_STATE", &self.state)
                .env("APPSEC_TEST_MARKER", &self.marker)
                .env("APPSEC_TEST_PHASE", &self.phase)
                .env(
                    "APPSEC_TEST_LEASE",
                    serde_json::to_string(&assignment.lease)?,
                )
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        Ok(())
    }
    fn observe(&mut self, _: Id) -> Result<RuntimeObservation> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing worker"))?;
        if child.try_wait()?.is_some() {
            Ok(RuntimeObservation::Terminated {
                usage: Usage::default(),
                exit: RuntimeExit::ProviderFailure,
                progress: None,
            })
        } else {
            Ok(RuntimeObservation::Live {
                usage: Usage::default(),
                progress: None,
                oldest_active_operation: None,
            })
        }
    }
    fn cancel(&mut self, _: Id) -> Result<()> {
        if let Some(child) = &mut self.child {
            if child.try_wait()?.is_none() {
                child.kill()?;
                child.wait()?;
            }
        }
        Ok(())
    }
    fn diagnose(&mut self, _: Id) -> Result<ArtifactRef> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing process handle"))?;
        let evidence = format!(
            "owned PID {}; exited: {}",
            child.id(),
            child.try_wait()?.is_some()
        );
        ArtifactStore::open(&self.state)?.write(evidence.as_bytes(), 4096)
    }
}

#[test]
fn actual_worker_crashes_recover_at_all_four_submission_boundaries() -> Result<()> {
    for phase in [
        "before_upload",
        "after_upload",
        "after_commit",
        "before_ack",
    ] {
        let directory = Directory::new()?;
        let state = directory.0.join("state");
        let controller = Controller::new(
            SqliteRepository::open(&state, 1)?,
            ArtifactStore::open(&state)?,
            SystemClock,
        );
        let input = manifest(1)?;
        let submission = candidate(&input)?;
        let campaign = controller.create(input)?;
        let marker = directory.0.join("ready");
        let mut worker = ProcessWorker {
            state: state.clone(),
            marker: marker.clone(),
            phase: phase.into(),
            child: None,
        };
        let assignment = controller
            .dispatch_next(campaign.id, 0, &mut worker)?
            .ok_or_else(|| anyhow::anyhow!("worker not admitted"))?;
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "worker must reach {phase} boundary");
        let child = worker
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no child"))?;
        child.kill()?;
        assert!(!child.wait()?.success(), "worker must actually be killed");
        drop(controller);
        let controller = Controller::new(
            SqliteRepository::open(&state, 1)?,
            ArtifactStore::open(&state)?,
            SystemClock,
        );
        let reopened = controller.status(campaign.id)?;
        let committed = matches!(phase, "after_commit" | "before_ack");
        assert_eq!(
            reopened.accepted.len(),
            usize::from(committed),
            "commit durability at {phase}"
        );
        assert_eq!(
            reopened.tasks[0].state,
            ExecutionState::Running,
            "candidate upload is not task completion"
        );
        let artifacts = std::fs::read_dir(&state)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("evidence-"))
            .count();
        assert_eq!(
            artifacts,
            usize::from(phase != "before_upload"),
            "artifact durability at {phase}"
        );
        if committed {
            let replay =
                controller.submit(&assignment.lease, "worker-observation", submission.clone())?;
            assert_eq!(
                replay.id, reopened.accepted[0].id,
                "lost acknowledgment returns the committed ID"
            );
            assert_eq!(controller.status(campaign.id)?.accepted.len(), 1);
        }
        let failed = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(failed.tasks[0].state, ExecutionState::Failed);
        assert!(
            !failed.tasks[0].attempts[0].runtime_slot_held,
            "confirmed dead process frees slot"
        );
        assert_eq!(failed.tasks[0].attempts[0].usage.tokens, None);
        assert!(
            !failed.tasks[0].attempts[0].usage.complete,
            "interrupted usage remains uncertain"
        );
        assert_eq!(failed.accepted.len(), usize::from(committed));
        let queued = controller.resume(
            campaign.id,
            failed.revision,
            assignment.lease.task_id,
            "resume after SIGKILL",
        )?;
        let retry = controller
            .dispatch_next(campaign.id, queued.revision, &mut Worker::default())?
            .ok_or_else(|| anyhow::anyhow!("retry not admitted"))?;
        assert_eq!(retry.lease.generation, 2);
        assert!(
            controller
                .submit(&assignment.lease, "late", submission.clone())
                .is_err(),
            "crashed worker is fenced"
        );
        controller.submit(&retry.lease, "worker-observation", submission)?;
        assert_eq!(
            controller.status(campaign.id)?.accepted.len(),
            1,
            "resumed work cannot duplicate the accepted candidate"
        );
    }
    Ok(())
}
