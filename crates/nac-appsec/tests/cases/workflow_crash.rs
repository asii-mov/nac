use super::*;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

struct CrashRepository {
    inner: SqliteRepository,
    updates: AtomicUsize,
    marker: PathBuf,
    after_commit: bool,
}

fn gate(marker: &Path) -> Result<()> {
    std::fs::write(marker, "reached workflow transaction boundary")?;
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
        let final_accept = self.updates.fetch_add(1, Ordering::SeqCst) == 1;
        let result = self.inner.update(run, revision, &mut |campaign, slots| {
            operation(campaign, slots)?;
            if final_accept && !self.after_commit {
                gate(&self.marker)?;
            }
            Ok(())
        })?;
        if final_accept && self.after_commit {
            gate(&self.marker)?;
        }
        Ok(result)
    }
}

#[test]
#[ignore = "child-process crash entry"]
fn entry() -> Result<()> {
    let state = PathBuf::from(std::env::var_os("NAC_WORKFLOW_CRASH_STATE").unwrap());
    let (lease, submission): (Lease, Submission) =
        serde_json::from_slice(&std::fs::read(state.join("request.json"))?)?;
    let repository = CrashRepository {
        inner: SqliteRepository::open(&state, 4)?,
        updates: AtomicUsize::new(0),
        marker: state.join("boundary"),
        after_commit: std::env::var("NAC_WORKFLOW_CRASH_AFTER")? == "true",
    };
    let controller = Controller::new(repository, ArtifactStore::open(&state)?, TestClock::new());
    controller.submit(&lease, "crash-creation", submission)?;
    Ok(())
}

fn crash(state: &Path, lease: &Lease, submission: &Submission, after_commit: bool) -> Result<()> {
    std::fs::write(
        state.join("request.json"),
        serde_json::to_vec(&(lease, submission))?,
    )?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "crash::entry", "--ignored", "--nocapture"])
        .env("NAC_WORKFLOW_CRASH_STATE", state)
        .env("NAC_WORKFLOW_CRASH_AFTER", after_commit.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let started = Instant::now();
    while !state.join("boundary").exists() && started.elapsed() < Duration::from_secs(10) {
        if child.try_wait()?.is_some() {
            anyhow::bail!("crash worker exited before boundary");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let reached = state.join("boundary").exists();
    child.kill()?;
    child.wait()?;
    anyhow::ensure!(reached, "crash worker did not reach boundary");
    Ok(())
}

#[test]
fn real_process_death_cannot_duplicate_children_or_validators() -> Result<()> {
    for after_commit in [false, true] {
        for candidate_creation in [false, true] {
            let directory = Directory::new()?;
            let state = directory.0.join("state");
            let controller = open(&state, TestClock::new(), 4)?;
            let campaign = controller.create(workflow_manifest(None)?)?;
            let mut runtime = Worker::default();
            let root = dispatch(&controller, campaign.id, &mut runtime)?;
            let (assignment, submission) = if candidate_creation {
                map(&controller, &root.lease)?;
                settle(&controller, campaign.id, &mut runtime)?;
                let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
                let source = source(&controller, &discovery.lease)?;
                let submission = Submission {
                    schema_version: 1,
                    payload: Payload::Candidate {
                        candidate: Candidate {
                            claim: "source hypothesis".into(),
                            prerequisites: vec!["attacker control".into()],
                            unresolved_assumptions: vec![],
                            source,
                        },
                    },
                    evidence: vec![EvidenceInput::Upload {
                        bytes: b"retained source receipt".to_vec(),
                    }],
                };
                (discovery, submission)
            } else {
                inventory(&controller, &root.lease)?;
                let source = source(&controller, &root.lease)?;
                let action = WorkflowAction::Map {
                    areas: vec![Area {
                        key: "entry".into(),
                        description: "pinned boundary".into(),
                        sources: vec![source],
                        trust_boundaries: vec!["caller to state".into()],
                        unknowns: vec![],
                        applicability: vec![],
                    }],
                    unknowns: vec![],
                };
                let submission = Submission {
                    schema_version: 1,
                    payload: Payload::Workflow {
                        revision: controller.status(campaign.id)?.accepted.len() as u64,
                        action,
                    },
                    evidence: vec![],
                };
                (root, submission)
            };
            crash(&state, &assignment.lease, &submission, after_commit)?;
            drop(controller);
            let restarted = open(&state, TestClock::new(), 4)?;
            let accepted =
                restarted.submit(&assignment.lease, "crash-creation", submission.clone())?;
            assert_eq!(
                restarted
                    .submit(&assignment.lease, "crash-creation", submission)?
                    .id,
                accepted.id
            );
            let status = restarted.status(campaign.id)?;
            assert!(status.pending_submissions.is_empty());
            let workflow = status.workflow.unwrap();
            if candidate_creation {
                assert_eq!(workflow.candidate_validators.len(), 1);
                assert_eq!(workflow.jobs.len(), 9);
            } else {
                assert_eq!(workflow.cells.len(), 6);
                assert_eq!(workflow.jobs.len(), 8);
            }
        }
    }
    Ok(())
}
