use crate::support::*;
use nac_appsec::*;

#[test]
fn liveness_and_token_volume_do_not_hide_a_semantic_stall() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 4)?;
    let input = manifest(1)?;
    let candidate = candidate(&input)?;
    let campaign = controller.create(input)?;
    let mut worker = Worker {
        diagnostic_evidence: Some(diagnostic(&directory.0.join("state"))?),
        ..Worker::default()
    };
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let accepted = controller.submit(&assignment.lease, "candidate", candidate.clone())?;
    worker.progress = Some(accepted.evidence[0].clone());
    worker.usage = Usage {
        tokens: Some(1_000_000_000),
        output_bytes: Some(1_000_000_000),
        complete: false,
    };
    clock.advance(10000);
    let warning = controller.reconcile(campaign.id, &mut worker)?;
    let attempt = &warning.tasks[0].attempts[0];
    assert_eq!(attempt.last_liveness_ms, 11000);
    assert_eq!(attempt.last_progress_ms, 1000);
    assert_eq!(attempt.watchdog_state, WatchdogState::Warning);
    assert_eq!(worker.diagnostics, vec![assignment.lease.attempt_id]);
    assert!(
        worker.cancelled.is_empty(),
        "usage volume is not a stopping condition"
    );
    assert_eq!(warning.tasks[0].state, ExecutionState::Running);
    controller.submit(&assignment.lease, "duplicate-payload-new-key", candidate)?;
    clock.advance(10001);
    let stalled = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(
        stalled.tasks[0].attempts[0].watchdog_state,
        WatchdogState::SuspectedStall
    );
    assert_eq!(stalled.tasks[0].attempts[0].last_progress_ms, 1000);
    assert_eq!(stalled.tasks[0].state, ExecutionState::Running);
    assert!(
        worker.cancelled.is_empty(),
        "suspected stall is not proof of a dead process"
    );
    let recovering = controller.recover(
        campaign.id,
        stalled.revision,
        assignment.lease.task_id,
        &mut worker,
    )?;
    assert_eq!(recovering.tasks[0].state, ExecutionState::Blocked);
    assert!(
        recovering.tasks[0].attempts[0].runtime_slot_held,
        "recovery does not pretend the live process stopped"
    );
    assert!(
        controller
            .submit(&assignment.lease, "late", completed(&assignment.scope))
            .is_err(),
        "recovery fences submission"
    );
    worker.terminated.insert(assignment.lease.attempt_id, true);
    let stopped = controller.reconcile(campaign.id, &mut worker)?;
    assert!(
        !stopped.tasks[0].attempts[0].runtime_slot_held,
        "confirmed termination releases slot"
    );
    assert_eq!(stopped.tasks[0].failed_recoveries, 1);
    assert_eq!(stopped.accepted.len(), 2);
    Ok(())
}

#[test]
fn real_new_evidence_resets_watchdog_and_failed_recovery_streak() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 4)?;
    let input = manifest(1)?;
    let evidence = candidate(&input)?;
    let campaign = controller.create(input)?;
    let mut worker = Worker {
        diagnostic_evidence: Some(diagnostic(&directory.0.join("state"))?),
        ..Worker::default()
    };
    let first = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    worker.terminated.insert(first.lease.attempt_id, true);
    let failed = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(failed.tasks[0].failed_recoveries, 1);
    let queued = controller.resume(campaign.id, failed.revision, first.lease.task_id, "retry")?;
    let second = controller
        .dispatch_next(campaign.id, queued.revision, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    clock.advance(10000);
    assert_eq!(
        controller.reconcile(campaign.id, &mut worker)?.tasks[0].attempts[1].watchdog_state,
        WatchdogState::Warning
    );
    controller.submit(&second.lease, "new-evidence", evidence)?;
    let productive = controller.status(campaign.id)?;
    assert_eq!(productive.tasks[0].failed_recoveries, 0);
    assert_eq!(
        productive.tasks[0].attempts[1].watchdog_state,
        WatchdogState::Healthy
    );
    assert_eq!(productive.tasks[0].attempts[1].last_progress_ms, 11000);
    assert_eq!(productive.tasks[0].attempts[1].diagnostic_ms, None);
    Ok(())
}

#[test]
fn quiet_bounded_operation_warns_before_recovery_and_expires_individually() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 4)?;
    let mut input = manifest(1)?;
    input.tasks[0].operation_limits.wall_ms = 30000;
    let campaign = controller.create(input)?;
    let mut worker = Worker {
        operation: Some(RuntimeOperation {
            id: "quiet-operation".into(),
            started_ms: clock.now_ms()?,
        }),
        diagnostic_evidence: Some(diagnostic(&directory.0.join("state"))?),
        ..Worker::default()
    };
    let first = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    controller.reconcile(campaign.id, &mut worker)?;
    clock.advance(20001);
    let warning = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(
        warning.tasks[0].attempts[0].watchdog_state,
        WatchdogState::Warning
    );
    assert!(
        controller
            .recover(
                campaign.id,
                warning.revision,
                first.lease.task_id,
                &mut worker
            )
            .is_err(),
        "warning and diagnosis precede suspected stall"
    );
    clock.advance(5000);
    let suspected = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(
        suspected.tasks[0].attempts[0].watchdog_state,
        WatchdogState::SuspectedStall
    );
    assert!(
        worker.cancelled.is_empty(),
        "quiet legitimate operation is not killed merely for lack of semantic progress"
    );
    clock.advance(5000);
    let expired = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(expired.tasks[0].state, ExecutionState::Blocked);
    assert_eq!(worker.cancelled, vec![first.lease.attempt_id]);
    assert!(
        expired.tasks[0].attempts[0].runtime_slot_held,
        "operation timeout does not prove termination"
    );
    Ok(())
}

#[test]
fn only_consecutive_failed_recoveries_and_individual_response_sizes_are_bounded() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let mut input = manifest(1)?;
    input.watchdog.max_failed_recoveries = 2;
    input.tasks[0].operation_limits.output_bytes = 200;
    let campaign = controller.create(input)?;
    let mut worker = Worker {
        diagnostic_evidence: Some(diagnostic(&directory.0.join("state"))?),
        ..Worker::default()
    };
    let first = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let huge = Submission {
        schema_version: 1,
        payload: Payload::StageResult {
            result: StageResult::Completed {
                scope: first.scope.clone(),
            },
        },
        evidence: vec![EvidenceInput::Upload {
            bytes: vec![b'x'; 201],
        }],
    };
    assert!(
        controller.submit(&first.lease, "huge", huge).is_err(),
        "individual response bound applies before upload"
    );
    worker.terminated.insert(first.lease.attempt_id, true);
    let failed = controller.reconcile(campaign.id, &mut worker)?;
    let queued = controller.resume(
        campaign.id,
        failed.revision,
        first.lease.task_id,
        "first recovery",
    )?;
    let second = controller
        .dispatch_next(campaign.id, queued.revision, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    worker.terminated.insert(second.lease.attempt_id, true);
    let failed = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(failed.tasks[0].failed_recoveries, 2);
    assert!(
        controller
            .resume(
                campaign.id,
                failed.revision,
                first.lease.task_id,
                "unbounded retries"
            )
            .is_err(),
        "consecutive failures are bounded"
    );
    assert_eq!(failed.tasks[0].attempts[1].usage.tokens, None);
    Ok(())
}

#[test]
fn trusted_progress_survives_former_totals_and_diagnostic_state_survives_restart() -> Result<()> {
    let directory = Directory::new()?;
    let state = directory.0.join("state");
    let clock = TestClock::new();
    let controller = open(&state, clock.clone(), 4)?;
    let campaign = controller.create(manifest(1)?)?;
    let mut worker = Worker {
        diagnostic_evidence: Some(diagnostic(&state)?),
        operation: Some(RuntimeOperation {
            id: "initial-operation".into(),
            started_ms: clock.now_ms()?,
        }),
        ..Worker::default()
    };
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let artifacts = ArtifactStore::open(&state)?;
    for sequence in 0..110 {
        clock.advance(9999);
        worker.operation = if sequence % 2 == 0 {
            Some(RuntimeOperation {
                id: format!("operation-{sequence}"),
                started_ms: clock.now_ms()?,
            })
        } else {
            None
        };
        let receipt = format!("trusted deterministic experiment produced observation {sequence}");
        worker.progress = Some(artifacts.write(receipt.as_bytes(), 4096)?);
        worker.usage.tokens = Some(2_000_000 + sequence);
        let progressing = controller.reconcile(campaign.id, &mut worker)?;
        assert_eq!(progressing.tasks[0].state, ExecutionState::Running);
        assert_eq!(
            progressing.tasks[0].attempts[0].watchdog_state,
            WatchdogState::Healthy
        );
    }
    assert!(
        worker.cancelled.is_empty(),
        "productive work crosses former token and elapsed-time totals without cancellation"
    );
    worker.operation = None;
    clock.advance(10000);
    let warning = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(
        warning.tasks[0].attempts[0].watchdog_state,
        WatchdogState::Warning
    );
    let diagnostic_hash = warning.tasks[0].attempts[0]
        .diagnostic_evidence
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing diagnostic receipt"))?
        .sha256
        .clone();
    drop(controller);
    let controller = open(&state, clock.clone(), 4)?;
    let reopened = controller.status(campaign.id)?;
    assert_eq!(
        reopened.tasks[0].attempts[0]
            .diagnostic_evidence
            .as_ref()
            .map(|e| &e.sha256),
        Some(&diagnostic_hash)
    );
    clock.advance(10001);
    let stalled = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(
        stalled.tasks[0].attempts[0].watchdog_state,
        WatchdogState::SuspectedStall
    );
    assert_eq!(worker.diagnostics.len(), 1);
    controller.recover(
        campaign.id,
        stalled.revision,
        assignment.lease.task_id,
        &mut worker,
    )?;
    assert!(
        controller
            .recover(
                campaign.id,
                stalled.revision,
                assignment.lease.task_id,
                &mut worker
            )
            .is_err(),
        "lost recovery acknowledgment cannot repeat a revision-checked mutation"
    );
    Ok(())
}
