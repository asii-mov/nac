use crate::support::*;
use nac_appsec::*;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct ProcessRuntime {
    state: PathBuf,
    child: Option<Child>,
    attempt: Option<Id>,
    cleanup_killed: bool,
    provider_failure: bool,
    progress: Option<ArtifactRef>,
}

impl ProcessRuntime {
    fn new(state: PathBuf) -> Self {
        Self {
            state,
            child: None,
            attempt: None,
            cleanup_killed: false,
            provider_failure: false,
            progress: None,
        }
    }

    fn child(&mut self, attempt: Id) -> Result<&mut Child> {
        anyhow::ensure!(
            self.attempt == Some(attempt),
            "runtime operation targets the exact owned attempt"
        );
        self.child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no owned child"))
    }
}

impl Drop for ProcessRuntime {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Runtime for ProcessRuntime {
    fn check_capabilities(&self) -> Result<()> {
        Ok(())
    }

    fn start(&mut self, assignment: &Assignment) -> Result<()> {
        if let Some(child) = &mut self.child {
            anyhow::ensure!(
                child.try_wait()?.is_some(),
                "previous process must have terminated before a continuation"
            );
        }
        let mut command = if self.provider_failure {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 17"]);
            command
        } else {
            let mut command = Command::new("sleep");
            command.arg("60");
            command
        };
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        if self.provider_failure {
            child.wait()?;
        }
        self.child = Some(child);
        self.attempt = Some(assignment.lease.attempt_id);
        self.cleanup_killed = false;
        Ok(())
    }

    fn observe(&mut self, attempt: Id) -> Result<RuntimeObservation> {
        if let Some(status) = self.child(attempt)?.try_wait()? {
            Ok(RuntimeObservation::Terminated {
                usage: Usage::default(),
                progress: self.progress.clone(),
                exit: if self.cleanup_killed {
                    RuntimeExit::Cancelled
                } else if status.success() {
                    RuntimeExit::Success
                } else {
                    RuntimeExit::ProviderFailure
                },
            })
        } else {
            Ok(RuntimeObservation::Live {
                usage: Usage::default(),
                progress: self.progress.clone(),
                oldest_active_operation: None,
            })
        }
    }

    fn cancel(&mut self, attempt: Id) -> Result<()> {
        let child = self.child(attempt)?;
        if child.try_wait()?.is_none() {
            child.kill()?;
            let status = child.wait()?;
            anyhow::ensure!(!status.success(), "cleanup must actually cancel the child");
            self.cleanup_killed = true;
        }
        Ok(())
    }

    fn diagnose(&mut self, attempt: Id) -> Result<ArtifactRef> {
        let child = self.child(attempt)?;
        let receipt = format!(
            "owned PID {}; live: {}",
            child.id(),
            child.try_wait()?.is_none()
        );
        ArtifactStore::open(&self.state)?.write(receipt.as_bytes(), 4096)
    }
}

fn partial(receipt: &ArtifactRef) -> Submission {
    Submission {
        schema_version: 1,
        payload: Payload::StageResult {
            result: StageResult::Partial {
                reason: "productive context checkpoint; continue remaining scope".into(),
            },
        },
        evidence: vec![EvidenceInput::Stored {
            artifact: receipt.clone(),
        }],
    }
}

#[test]
fn real_checkpoint_cleanup_cancellation_is_not_a_failed_recovery() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let mut controller = open(&state, clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 1;
    let mut campaign = controller.create(input)?;
    let mut runtime = ProcessRuntime::new(state.clone());
    for sequence in 0..3 {
        let assignment = controller
            .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
            .ok_or_else(|| anyhow::anyhow!("productive continuation blocked"))?;
        let receipt = ArtifactStore::open(&state)?.write(
            format!("trusted completed checkpoint operation {sequence}").as_bytes(),
            4096,
        )?;
        let accepted = controller.submit(
            &assignment.lease,
            &format!("checkpoint-{sequence}"),
            partial(&receipt),
        )?;
        controller = open(&state, clock.clone(), 4)?;
        let checkpoint = controller.status(campaign.id)?;
        assert_eq!(
            checkpoint.tasks[0].attempts[sequence].stop_intent,
            Some(StopIntent::AcceptedResultCleanup),
            "accepted checkpoint cleanup intent survives reopening SQLite"
        );
        assert!(
            runtime
                .child(assignment.lease.attempt_id)?
                .try_wait()?
                .is_none(),
            "checkpoint is accepted while the real child is still live"
        );
        runtime.progress = Some(receipt);
        if sequence == 0 {
            clock.advance(100001);
        }
        let settled = controller.reconcile(campaign.id, &mut runtime)?;
        assert!(
            runtime.cleanup_killed,
            "controller cleanup physically cancelled the child"
        );
        assert_eq!(settled.tasks[0].state, ExecutionState::Partial);
        assert_eq!(
            settled.tasks[0].failed_recoveries, 0,
            "physical cleanup is not an unsuccessful recovery"
        );
        assert_eq!(
            settled.tasks[0].attempts[sequence].runtime_exit,
            Some(RuntimeExit::Cancelled)
        );
        assert!(
            !settled.tasks[0].attempts[sequence].runtime_slot_held,
            "only confirmed termination releases the slot"
        );
        assert_eq!(settled.accepted[sequence].id, accepted.id);
        campaign = controller.resume(
            campaign.id,
            settled.revision,
            assignment.lease.task_id,
            "continue the accepted productive checkpoint",
        )?;
    }
    Ok(())
}

#[test]
fn real_provider_failure_after_partial_is_not_checkpoint_cleanup_success() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 1;
    let campaign = controller.create(input)?;
    let mut runtime = ProcessRuntime::new(state.clone());
    runtime.provider_failure = true;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut runtime)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let receipt = ArtifactStore::open(&state)?
        .write(b"new observation does not erase a provider failure", 4096)?;
    controller.submit(&assignment.lease, "partial", partial(&receipt))?;
    runtime.progress = Some(receipt);
    let failed = controller.reconcile(campaign.id, &mut runtime)?;
    let attempt = &failed.tasks[0].attempts[0];
    assert_eq!(failed.tasks[0].state, ExecutionState::Partial);
    assert_eq!(attempt.stop_intent, Some(StopIntent::AcceptedResultCleanup));
    assert_eq!(attempt.runtime_exit, Some(RuntimeExit::ProviderFailure));
    assert_eq!(failed.tasks[0].failed_recoveries, 1);
    assert!(
        controller
            .resume(
                campaign.id,
                failed.revision,
                assignment.lease.task_id,
                "retry failed provider"
            )
            .is_err(),
        "physical provider failure still consumes the failed-recovery allowance"
    );
    Ok(())
}

#[test]
fn real_cancellation_without_an_accepted_stage_is_not_a_checkpoint() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 1;
    let campaign = controller.create(input)?;
    let mut runtime = ProcessRuntime::new(state.clone());
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut runtime)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    runtime.progress = Some(ArtifactStore::open(&state)?.write(
        b"arbitrary cancelled runtime has progress but no accepted stage",
        4096,
    )?);
    runtime.cancel(assignment.lease.attempt_id)?;
    let cancelled = controller.reconcile(campaign.id, &mut runtime)?;
    assert_eq!(cancelled.tasks[0].state, ExecutionState::Cancelled);
    assert_eq!(cancelled.tasks[0].attempts[0].stop_intent, None);
    assert_eq!(
        cancelled.tasks[0].attempts[0].runtime_exit,
        Some(RuntimeExit::Cancelled)
    );
    assert_eq!(cancelled.tasks[0].failed_recoveries, 1);
    assert!(
        cancelled.accepted.is_empty(),
        "runtime progress is not a stage result"
    );
    assert!(
        controller
            .resume(
                campaign.id,
                cancelled.revision,
                assignment.lease.task_id,
                "not a checkpoint"
            )
            .is_err(),
        "unrequested cancellation must not grant free continuation"
    );
    Ok(())
}

#[test]
fn real_cleanup_with_duplicate_progress_still_exhausts_failed_recoveries() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 1;
    let mut campaign = controller.create(input)?;
    let mut runtime = ProcessRuntime::new(state.clone());
    let receipt = ArtifactStore::open(&state)?.write(
        b"one genuine observation reused by a later empty continuation",
        4096,
    )?;
    for generation in 0..2 {
        let assignment = controller
            .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
            .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
        controller.submit(
            &assignment.lease,
            &format!("partial-{generation}"),
            partial(&receipt),
        )?;
        runtime.progress = Some(receipt.clone());
        let settled = controller.reconcile(campaign.id, &mut runtime)?;
        assert_eq!(settled.tasks[0].failed_recoveries, generation);
        assert_eq!(
            settled.tasks[0].attempts[generation as usize].runtime_exit,
            Some(RuntimeExit::Cancelled)
        );
        let resumed = controller.resume(
            campaign.id,
            settled.revision,
            assignment.lease.task_id,
            "attempt another partial continuation",
        );
        if generation == 0 {
            campaign = resumed?;
        } else {
            assert!(
                resumed.is_err(),
                "cleanup cancellation cannot make duplicate output count as useful work"
            );
        }
    }
    Ok(())
}

#[test]
fn watchdog_recovery_overrides_partial_cleanup_and_ignores_late_progress() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let controller = open(&state, clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 1;
    let campaign = controller.create(input)?;
    let mut runtime = ProcessRuntime::new(state.clone());
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut runtime)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    controller.submit(
        &assignment.lease,
        "candidate-before-stall",
        candidate(&campaign.manifest)?,
    )?;
    clock.advance(10000);
    controller.reconcile(campaign.id, &mut runtime)?;
    clock.advance(10001);
    let suspected = controller.reconcile(campaign.id, &mut runtime)?;
    assert_eq!(
        suspected.tasks[0].attempts[0].watchdog_state,
        WatchdogState::SuspectedStall
    );
    let receipt = ArtifactStore::open(&state)?
        .write(b"late receipt does not reverse a watchdog revocation", 4096)?;
    controller.submit(
        &assignment.lease,
        "partial-before-recovery",
        partial(&receipt),
    )?;
    let late_hash = receipt.sha256.clone();
    runtime.progress = Some(receipt);
    let snapshot = controller.status(campaign.id)?;
    let failed = controller.recover(
        campaign.id,
        snapshot.revision,
        assignment.lease.task_id,
        &mut runtime,
    )?;
    let attempt = &failed.tasks[0].attempts[0];
    assert_eq!(attempt.stop_intent, Some(StopIntent::WatchdogRecovery));
    assert_eq!(attempt.runtime_exit, Some(RuntimeExit::Cancelled));
    assert!(
        attempt.made_meaningful_progress,
        "earlier useful work does not make watchdog recovery checkpoint cleanup"
    );
    assert!(
        !failed.tasks[0].progress_fingerprints.contains(&late_hash),
        "post-revocation progress cannot authorize continuation"
    );
    assert_eq!(failed.tasks[0].state, ExecutionState::Blocked);
    assert_eq!(failed.tasks[0].failed_recoveries, 1);
    assert_eq!(
        failed.accepted.len(),
        2,
        "watchdog recovery preserves the committed candidate and partial result"
    );
    assert!(
        controller
            .resume(
                campaign.id,
                failed.revision,
                assignment.lease.task_id,
                "failed watchdog recovery"
            )
            .is_err(),
        "watchdog termination is not checkpoint cleanup"
    );
    Ok(())
}

#[test]
fn lease_expiry_and_operator_cancellation_keep_their_own_stop_intents() -> Result<()> {
    for operator in [false, true] {
        let directory = Directory::new()?;
        let state = directory.0.join("state");
        let clock = TestClock::new();
        let controller = open(&state, clock.clone(), 4)?;
        let mut input = manifest(1)?;
        input.watchdog.max_failed_recoveries = 1;
        let campaign = controller.create(input)?;
        let mut runtime = ProcessRuntime::new(state.clone());
        let assignment = controller
            .dispatch_next(campaign.id, 0, &mut runtime)?
            .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
        let receipt = ArtifactStore::open(&state)?.write(
            b"late progress cannot erase lease or operator stop intent",
            4096,
        )?;
        if operator {
            controller.submit(
                &assignment.lease,
                "partial-before-operator-cancel",
                partial(&receipt),
            )?;
            let snapshot = controller.status(campaign.id)?;
            controller.cancel(campaign.id, snapshot.revision)?;
        } else {
            clock.advance(100001);
        }
        runtime.progress = Some(receipt);
        let first = controller.reconcile(campaign.id, &mut runtime)?;
        if !operator {
            assert!(
                first.tasks[0].attempts[0].runtime_slot_held,
                "requesting lease cancellation does not itself prove termination"
            );
        }
        let stopped = controller.reconcile(campaign.id, &mut runtime)?;
        let attempt = &stopped.tasks[0].attempts[0];
        assert_eq!(
            attempt.stop_intent,
            Some(if operator {
                StopIntent::OperatorCancellation
            } else {
                StopIntent::LeaseExpired
            })
        );
        assert_eq!(attempt.runtime_exit, Some(RuntimeExit::Cancelled));
        assert!(
            !attempt.made_meaningful_progress,
            "late receipts after explicit revocation are not checkpoint progress"
        );
        assert_eq!(
            stopped.tasks[0].state,
            if operator {
                ExecutionState::Cancelled
            } else {
                ExecutionState::Blocked
            }
        );
        assert_eq!(stopped.tasks[0].failed_recoveries, u32::from(!operator));
    }
    Ok(())
}
