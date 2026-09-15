use crate::support::*;
use nac_appsec::*;

#[test]
fn adjacent_productive_operations_do_not_share_a_timeout() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let controller = open(&state, clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.tasks[0].operation_limits.wall_ms = 30000;
    let campaign = controller.create(input)?;
    let mut worker = Worker {
        diagnostic_evidence: Some(diagnostic(&state)?),
        ..Worker::default()
    };
    controller.dispatch_next(campaign.id, 0, &mut worker)?;
    for sequence in 0..8 {
        worker.operation = Some(RuntimeOperation {
            id: format!("bounded-operation-{sequence}"),
            started_ms: clock.now_ms()?,
        });
        worker.progress = Some(ArtifactStore::open(&state)?.write(
            format!("trusted operation {sequence} produced a distinct observation").as_bytes(),
            4096,
        )?);
        let snapshot = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(
            snapshot.tasks[0].state,
            ExecutionState::Running,
            "adjacent bounded operations are not one long operation"
        );
        assert!(
            worker.cancelled.is_empty(),
            "individual operation limits cannot become a cumulative ceiling"
        );
        clock.advance(10000);
    }
    Ok(())
}

#[test]
fn productive_partial_checkpoints_between_polls_do_not_exhaust_recovery() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 2;
    let mut campaign = controller.create(input)?;
    let mut worker = Worker::default();
    for sequence in 0..6 {
        let assignment = controller
            .dispatch_next(campaign.id, campaign.revision, &mut worker)?
            .ok_or_else(|| anyhow::anyhow!("productive continuation was not admitted"))?;
        let progress = ArtifactStore::open(&state)?.write(
            format!("trusted completed operation for checkpoint {sequence}").as_bytes(),
            4096,
        )?;
        controller.submit(
            &assignment.lease,
            &format!("checkpoint-{sequence}"),
            Submission {
                schema_version: 1,
                payload: Payload::StageResult {
                    result: StageResult::Partial {
                        reason: "context checkpoint; continue remaining scope".into(),
                    },
                },
                evidence: vec![EvidenceInput::Stored {
                    artifact: progress.clone(),
                }],
            },
        )?;
        worker.progress = Some(progress);
        worker.terminated.insert(assignment.lease.attempt_id, true);
        let checkpoint = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(checkpoint.tasks[0].state, ExecutionState::Partial);
        assert_eq!(
            checkpoint.tasks[0].failed_recoveries, 0,
            "a successful productive checkpoint is not an unsuccessful recovery"
        );
        assert_eq!(checkpoint.accepted.len(), sequence + 1);
        campaign = controller.resume(
            campaign.id,
            checkpoint.revision,
            assignment.lease.task_id,
            "continue after productive context checkpoint",
        )?;
    }
    Ok(())
}

#[test]
fn same_operation_keeps_its_deadline_through_progress_and_controller_restart() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let controller = open(&state, clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.tasks[0].operation_limits.wall_ms = 30000;
    let campaign = controller.create(input)?;
    let operation = RuntimeOperation {
        id: "persistent-operation".into(),
        started_ms: clock.now_ms()?,
    };
    let mut worker = Worker {
        operation: Some(operation.clone()),
        ..Worker::default()
    };
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    controller.reconcile(campaign.id, &mut worker)?;
    clock.advance(10000);
    worker.progress =
        Some(ArtifactStore::open(&state)?.write(b"trusted intermediate operation result", 4096)?);
    let active = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(active.tasks[0].state, ExecutionState::Running);
    assert_eq!(
        active.tasks[0].attempts[0].last_operation.as_ref(),
        Some(&operation)
    );
    drop(controller);
    let controller = open(&state, clock.clone(), 4)?;
    assert_eq!(
        controller.status(campaign.id)?.tasks[0].attempts[0]
            .last_operation
            .as_ref(),
        Some(&operation)
    );
    worker.operation = Some(RuntimeOperation {
        id: operation.id.clone(),
        started_ms: clock.now_ms()?,
    });
    assert!(
        controller.reconcile(campaign.id, &mut worker).is_err(),
        "a same-ID timestamp change is rejected, not treated as a renewed operation"
    );
    worker.operation = Some(operation);
    clock.advance(20000);
    worker.progress = Some(ArtifactStore::open(&state)?.write(
        b"trusted new result does not extend the physical operation",
        4096,
    )?);
    let expired = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(expired.tasks[0].state, ExecutionState::Blocked);
    assert_eq!(worker.cancelled, vec![assignment.lease.attempt_id]);
    assert!(
        expired.tasks[0].attempts[0].runtime_slot_held,
        "timeout still requires exact termination reconciliation"
    );
    Ok(())
}

#[test]
fn short_overlapping_calls_cannot_extend_the_oldest_active_operation() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let controller = open(&state, clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.tasks[0].operation_limits.wall_ms = 30000;
    let campaign = controller.create(input)?;
    let longest = RuntimeOperation {
        id: "long-lived-tool-call".into(),
        started_ms: clock.now_ms()?,
    };
    let mut worker = Worker::default();
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    for sequence in 0..4 {
        let active_calls = [
            longest.clone(),
            RuntimeOperation {
                id: format!("short-tool-{sequence}"),
                started_ms: clock.now_ms()?,
            },
        ];
        worker.operation = active_calls
            .into_iter()
            .min_by_key(|operation| operation.started_ms);
        worker.progress = Some(ArtifactStore::open(&state)?.write(
            format!("trusted result from neighboring call {sequence}").as_bytes(),
            4096,
        )?);
        let observed = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(
            observed.tasks[0].attempts[0].last_operation.as_ref(),
            Some(&longest)
        );
        assert_eq!(
            observed.tasks[0].state,
            if sequence == 3 {
                ExecutionState::Blocked
            } else {
                ExecutionState::Running
            }
        );
        clock.advance(10000);
    }
    assert_eq!(worker.cancelled, vec![assignment.lease.attempt_id]);
    Ok(())
}

#[test]
fn duplicate_checkpoint_receipts_still_bound_unsuccessful_continuations() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 2;
    let mut campaign = controller.create(input)?;
    let receipt = ArtifactStore::open(&state)?.write(
        b"one real observation replayed by an unproductive continuation",
        4096,
    )?;
    let mut worker = Worker {
        progress: Some(receipt.clone()),
        ..Worker::default()
    };
    for sequence in 0..3 {
        let assignment = controller
            .dispatch_next(campaign.id, campaign.revision, &mut worker)?
            .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
        controller.submit(
            &assignment.lease,
            &format!("checkpoint-{sequence}"),
            Submission {
                schema_version: 1,
                payload: Payload::StageResult {
                    result: StageResult::Partial {
                        reason: "checkpoint with no new observation".into(),
                    },
                },
                evidence: vec![EvidenceInput::Stored {
                    artifact: receipt.clone(),
                }],
            },
        )?;
        worker.terminated.insert(assignment.lease.attempt_id, true);
        let checkpoint = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(checkpoint.tasks[0].failed_recoveries, sequence);
        let resumed = controller.resume(
            campaign.id,
            checkpoint.revision,
            assignment.lease.task_id,
            "attempt another continuation",
        );
        if sequence == 2 {
            assert!(
                resumed.is_err(),
                "duplicate receipts cannot produce unlimited unsuccessful continuations"
            );
        } else {
            campaign = resumed?;
        }
    }
    Ok(())
}
