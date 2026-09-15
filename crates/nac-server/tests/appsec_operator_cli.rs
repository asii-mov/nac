use anyhow::{ensure, Context, Result};
use nac_appsec::{
    ArtifactRef, ArtifactStore, Assignment, Campaign, Clock, Controller, Id, Manifest, Runtime,
    RuntimeObservation, SqliteRepository, SystemClock,
};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};

struct RecordedRuntime;

impl Runtime for RecordedRuntime {
    fn check_capabilities(&self) -> Result<()> {
        Ok(())
    }
    fn start(&mut self, _: &Assignment) -> Result<()> {
        Ok(())
    }
    fn observe(&mut self, _: Id) -> Result<RuntimeObservation> {
        anyhow::bail!("fixture observations are read by the native adapter")
    }
    fn cancel(&mut self, _: Id) -> Result<()> {
        Ok(())
    }
    fn diagnose(&mut self, _: Id) -> Result<ArtifactRef> {
        anyhow::bail!("fixture diagnostics are read by the native adapter")
    }
}

struct Fixture {
    directory: PathBuf,
    state: PathBuf,
    controller: Controller<SqliteRepository>,
    run: Id,
    ownership: Vec<File>,
}

impl Fixture {
    fn new(task_count: usize) -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("nac-operator-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = directory.join("state");
        let controller = Controller::new(
            SqliteRepository::open(&state, 4)?,
            ArtifactStore::open(&state)?,
            SystemClock,
        );
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let commit = Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["rev-parse", "HEAD"])
            .output()?;
        ensure!(commit.status.success(), "fixture commit lookup failed");
        let manifest: Manifest = serde_json::from_value(json!({
            "schema_version":1,
            "repositories":[{"identity":"fixture","checkout":repository,"commit":String::from_utf8(commit.stdout)?.trim()}],
            "declared_inputs":{"environment":null,"dependencies":null,"fixtures":null,"deployment":null,"harness_commit":null,"runtime_version":null,"model_configuration":null,"skill_bundle":null}, "monetary_policy":"uncapped", "token_policy":"observe_only",
            "watchdog":{"warn_after_ms":50,"stall_after_ms":100,"diagnostic_grace_ms":1000,"lease_ms":30000,"max_failed_recoveries":2},
            "max_concurrency":task_count,
            "tasks":(0..task_count).map(|index| json!({"key":format!("fixture-{index}"),"scope":"scripted observer fixture, no model","dependencies":[],"operation_limits":{"wall_ms":30000,"output_bytes":65536}})).collect::<Vec<_>>()
        }))?;
        let campaign = controller.create(manifest)?;
        let mut ownership = Vec::new();
        let workers = state.join("workers");
        std::fs::create_dir(&workers)?;
        std::fs::set_permissions(&workers, std::fs::Permissions::from_mode(0o700))?;
        for _ in 0..task_count {
            let revision = controller.status(campaign.id)?.revision;
            let assignment = controller
                .dispatch_next(campaign.id, revision, &mut RecordedRuntime)?
                .context("fixture admission missing")?;
            let directory = workers.join(assignment.lease.attempt_id.to_string());
            std::fs::create_dir(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(
                directory.join("child-admission.json"),
                b"\"child_may_exist\"",
            )?;
            let lock = File::create(directory.join("supervisor.lock"))?;
            fs2::FileExt::lock_exclusive(&lock)?;
            ownership.push(lock);
            std::fs::write(
                directory.join("observation.json"),
                serde_json::to_vec(&json!({
                    "observed_ms":SystemClock.now_ms()?,
                    "control":{"active":{},"observed_tokens":null,"observed_output_bytes":null,"usage_incomplete":true},
                    "loaded":null,"progress":null,"exit":null
                }))?,
            )?;
        }
        Ok(Self {
            directory,
            state,
            controller,
            run: campaign.id,
            ownership,
        })
    }

    fn status(&self) -> Result<Campaign> {
        self.controller.status(self.run)
    }

    fn worker(&self, index: usize) -> Result<PathBuf> {
        Ok(self.state.join("workers").join(
            self.status()?.tasks[index].attempts[0]
                .lease
                .attempt_id
                .to_string(),
        ))
    }

    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nac-web"));
        command
            .args(["appsec", action, "--state"])
            .arg(&self.state)
            .arg("--run-id")
            .arg(self.run.to_string());
        command
    }

    fn recover(&self, revision: u64) -> Result<Output> {
        Ok(self
            .command("recover")
            .arg("--task-id")
            .arg(self.status()?.tasks[0].id.to_string())
            .arg("--revision")
            .arg(revision.to_string())
            .output()?)
    }

    fn observation(&self, progress: Option<ArtifactRef>, exit: Option<&str>) -> Result<()> {
        let path = self.worker(0)?.join("observation.json");
        let mut value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        value["progress"] = serde_json::to_value(progress)?;
        value["exit"] = serde_json::to_value(exit)?;
        value["observed_ms"] = json!(SystemClock.now_ms()?);
        let temporary = path.with_extension("next");
        std::fs::write(&temporary, serde_json::to_vec(&value)?)?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn appsec_watch_prints_transitions_without_status_polling_or_poll_spam() -> Result<()> {
    let fixture = Fixture::new(1)?;
    let mut child = fixture
        .command("watch")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().context("watch stderr missing")?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let result = (|| -> Result<()> {
        let warning = receiver.recv_timeout(Duration::from_secs(5))??;
        assert!(
            warning.contains("warning: meaningful progress is overdue"),
            "{warning}"
        );
        let suspected = receiver.recv_timeout(Duration::from_secs(5))??;
        assert!(
            suspected.contains("suspected stall: diagnostic grace elapsed"),
            "{suspected}"
        );
        let receipt = ArtifactStore::open(&fixture.state)?
            .write(b"scripted trusted source progress receipt", 65536)?;
        fixture.observation(Some(receipt), None)?;
        let healthy = receiver.recv_timeout(Duration::from_secs(5))??;
        assert!(
            healthy.contains("healthy: verified meaningful progress resumed"),
            "{healthy}"
        );
        fixture.observation(None, Some("cancelled"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    for _ in 0..100 {
        if child.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let finished = child.try_wait()?;
    if finished.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    reader.join().expect("stderr reader panicked");
    result?;
    ensure!(
        finished.is_some_and(|status| status.success()),
        "watch did not settle"
    );
    assert!(
        receiver.try_recv().is_err(),
        "unchanged polls must not repeat notices"
    );
    assert!(!fixture.status()?.tasks[0].attempts[0].runtime_slot_held);
    Ok(())
}

#[test]
fn appsec_recover_requires_revision_diagnosis_grace_and_termination_before_resume() -> Result<()> {
    let fixture = Fixture::new(1)?;
    let initial = fixture.status()?;
    let stale = fixture.recover(initial.revision - 1)?;
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("revision conflict"));
    let undiagnosed = fixture.recover(initial.revision)?;
    assert!(!undiagnosed.status.success());
    assert!(String::from_utf8_lossy(&undiagnosed.stderr)
        .contains("recovery requires a diagnosed suspected stall"));
    assert_eq!(fixture.status()?.revision, initial.revision);
    assert!(!fixture.worker(0)?.join("cancelled").exists());
    let mut runtime = nac_server::NacWorkerRuntime::new(
        &fixture.state,
        std::env::current_exe()?,
        nac_server::NativeResearchModel::default(),
    )?;
    std::thread::sleep(Duration::from_millis(100));
    let warning = fixture.controller.reconcile(fixture.run, &mut runtime)?;
    assert_eq!(
        warning.tasks[0].attempts[0].watchdog_state,
        nac_appsec::WatchdogState::Warning
    );
    assert!(warning.tasks[0].attempts[0].diagnostic_evidence.is_some());
    assert!(!fixture.recover(warning.revision)?.status.success());
    std::thread::sleep(Duration::from_millis(1050));
    fixture.observation(None, None)?;
    let suspected = fixture.controller.reconcile(fixture.run, &mut runtime)?;
    assert_eq!(
        suspected.tasks[0].attempts[0].watchdog_state,
        nac_appsec::WatchdogState::SuspectedStall
    );
    assert!(!fixture.recover(warning.revision)?.status.success());
    assert!(!fixture.worker(0)?.join("cancelled").exists());
    let recovered = fixture.recover(suspected.revision)?;
    ensure!(
        recovered.status.success(),
        "recover failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let status = fixture.status()?;
    assert!(fixture.worker(0)?.join("cancelled").is_file());
    assert!(status.tasks[0].attempts[0].revoked);
    assert!(status.tasks[0].attempts[0].runtime_slot_held);
    assert_eq!(
        status.tasks[0].attempts[0].stop_intent,
        Some(nac_appsec::StopIntent::WatchdogRecovery)
    );
    let control = nac_server::AppsecControl::open(&fixture.state)?;
    assert!(control
        .resume(
            fixture.run,
            status.revision,
            status.tasks[0].id,
            "operator handoff"
        )
        .is_err());
    fixture.observation(None, Some("cancelled"))?;
    let stopped = control.tick(fixture.run, &mut runtime)?;
    assert!(!stopped.tasks[0].attempts[0].runtime_slot_held);
    assert_eq!(stopped.tasks[0].failed_recoveries, 1);
    assert!(control
        .resume(
            fixture.run,
            stopped.revision,
            stopped.tasks[0].id,
            &"x".repeat(4097)
        )
        .is_err());
    let resumed = control.resume(
        fixture.run,
        stopped.revision,
        stopped.tasks[0].id,
        "operator verified the checkpoint",
    )?;
    assert_eq!(resumed.tasks[0].state, nac_appsec::ExecutionState::Queued);
    assert_eq!(
        resumed.tasks[0].handoff.as_deref(),
        Some("operator verified the checkpoint")
    );
    assert_eq!(
        resumed.tasks[0].attempts.len(),
        1,
        "resume alone must not launch another worker"
    );
    Ok(())
}

#[test]
fn appsec_cancel_without_watcher_tombstones_every_attempt_despite_uncertain_first_slot(
) -> Result<()> {
    let mut fixture = Fixture::new(2)?;
    fixture.ownership.clear();
    let before = fixture.status()?;
    let result = fixture
        .command("cancel")
        .arg("--revision")
        .arg(before.revision.to_string())
        .output()?;
    let status = fixture.status()?;
    assert!(status.cancelled);
    for index in 0..2 {
        assert!(
            fixture.worker(index)?.join("cancelled").is_file(),
            "all owned keys must be signalled even when first observation fails"
        );
        let attempt = &status.tasks[index].attempts[0];
        assert!(attempt.revoked && attempt.runtime_slot_held);
        assert_eq!(attempt.runtime_exit, None);
        assert_eq!(
            attempt.stop_intent,
            Some(nac_appsec::StopIntent::OperatorCancellation)
        );
    }
    assert!(
        !result.status.success(),
        "uncertain cleanup must remain visible"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("canonical cancellation recorded"));
    Ok(())
}
