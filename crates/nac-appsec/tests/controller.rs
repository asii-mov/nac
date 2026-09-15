#[path = "cases/budgets.rs"]
mod budgets;
#[path = "cases/checkpoint_cleanup.rs"]
mod checkpoint_cleanup;
#[path = "cases/offline_source.rs"]
mod offline_source;
#[path = "cases/recovery.rs"]
mod recovery;
#[path = "cases/runtime_lifecycle.rs"]
mod runtime_lifecycle;
mod support;
#[path = "cases/validation.rs"]
mod validation;
#[path = "cases/watchdog.rs"]
mod watchdog;

use nac_appsec::*;
use support::*;

#[test]
fn pinned_graph_reopens_with_unknown_inputs_and_strict_schema() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let controller = open(&path, TestClock::new(), 4)?;
    let mut input = manifest(2)?;
    input.tasks[1].dependencies.push("cell-0".into());
    let campaign = controller.create(input.clone())?;
    let reopened = open(&path, TestClock::new(), 4)?.status(campaign.id)?;
    assert_eq!(reopened.revision, 0);
    assert_eq!(reopened.tasks.len(), 2);
    assert_eq!(reopened.state(), ExecutionState::Queued);
    assert!(
        reopened.markdown().contains("environment: unknown"),
        "unknown inputs must be visible"
    );
    assert!(
        reopened
            .markdown()
            .contains("does not establish security assurance"),
        "no clean assurance claim"
    );
    let mut invalid = serde_json::to_value(&input)?;
    invalid["model_completed"] = true.into();
    assert!(
        serde_json::from_value::<Manifest>(invalid).is_err(),
        "unknown manifest fields must fail"
    );
    input.schema_version = 2;
    assert!(
        controller.create(input.clone()).is_err(),
        "unknown versions must fail"
    );
    input.schema_version = 1;
    input.tasks[0].dependencies.push("cell-1".into());
    assert!(controller.create(input).is_err(), "cyclic graph must fail");
    Ok(())
}

#[test]
fn typed_zero_findings_unlocks_dependencies_but_prose_does_not_complete() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let mut input = manifest(2)?;
    input.tasks[1].dependencies.push("cell-0".into());
    let campaign = controller.create(input)?;
    let mut worker = Worker::default();
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let snapshot = controller.status(campaign.id)?;
    assert!(
        controller
            .dispatch_next(campaign.id, snapshot.revision, &mut worker)?
            .is_none(),
        "dependency is not satisfied by launch"
    );
    controller.submit(&assignment.lease, "complete", completed(&assignment.scope))?;
    let snapshot = controller.status(campaign.id)?;
    assert_eq!(snapshot.tasks[0].state, ExecutionState::Completed);
    assert_eq!(
        snapshot
            .accepted
            .iter()
            .filter(|a| matches!(a.payload, Payload::Candidate { .. }))
            .count(),
        0
    );
    let second = controller
        .dispatch_next(campaign.id, snapshot.revision, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("dependency not released"))?;
    worker.terminated.insert(second.lease.attempt_id, true);
    let reconciled = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(reconciled.tasks[1].state, ExecutionState::Failed);
    assert_eq!(
        reconciled.tasks[1].reason.as_deref(),
        Some("runtime exited without an accepted structured stage result")
    );
    assert_eq!(reconciled.state(), ExecutionState::Partial);
    Ok(())
}

#[test]
fn lease_expiry_retains_slot_and_retry_fences_preserve_candidates() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 1)?;
    let input = manifest(2)?;
    let submission = candidate(&input)?;
    let campaign = controller.create(input)?;
    let mut worker = Worker::default();
    let first = controller
        .dispatch_next(campaign.id, 0, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let accepted = controller.submit(&first.lease, "finding", submission.clone())?;
    let replay = controller.submit(&first.lease, "finding", submission.clone())?;
    assert_eq!(accepted.id, replay.id);
    let mut conflict = submission.clone();
    if let Payload::Candidate { candidate } = &mut conflict.payload {
        candidate.claim = "different".into();
    }
    assert!(
        controller
            .submit(&first.lease, "finding", conflict)
            .is_err(),
        "same-key conflict must fail"
    );
    clock.advance(100001);
    assert!(
        controller
            .submit(&first.lease, "late", submission.clone())
            .is_err(),
        "expired lease cannot submit"
    );
    let snapshot = controller.reconcile(campaign.id, &mut worker)?;
    assert_eq!(snapshot.tasks[0].state, ExecutionState::Blocked);
    assert!(
        snapshot.tasks[0].attempts[0].runtime_slot_held,
        "live slot must remain held"
    );
    assert_eq!(snapshot.tasks[0].attempts[0].usage.tokens, None);
    assert!(
        !snapshot.tasks[0].attempts[0].usage.complete,
        "interrupted usage stays uncertain"
    );
    assert!(
        controller
            .dispatch_next(campaign.id, snapshot.revision, &mut worker)
            .is_err(),
        "expired live worker still blocks host admission"
    );
    let snapshot = controller.status(campaign.id)?;
    assert!(
        controller
            .resume(campaign.id, snapshot.revision, first.lease.task_id, "retry")
            .is_err(),
        "live task cannot resume"
    );
    worker.terminated.insert(first.lease.attempt_id, true);
    let snapshot = controller.reconcile(campaign.id, &mut worker)?;
    let queued = controller.resume(
        campaign.id,
        snapshot.revision,
        first.lease.task_id,
        "retry after termination",
    )?;
    let retry = controller
        .dispatch_next(campaign.id, queued.revision, &mut worker)?
        .ok_or_else(|| anyhow::anyhow!("retry not admitted"))?;
    assert_eq!(retry.lease.generation, 2);
    assert_ne!(first.lease.attempt_id, retry.lease.attempt_id);
    assert_ne!(first.input_fingerprint, retry.input_fingerprint);
    assert!(
        controller
            .submit(&first.lease, "finding", submission.clone())
            .is_err(),
        "old generation cannot replay"
    );
    let retained = controller.submit(&retry.lease, "finding", submission)?;
    assert_eq!(retained.id, accepted.id);
    assert_eq!(controller.status(campaign.id)?.accepted.len(), 1);
    Ok(())
}

#[test]
fn partial_blocked_failed_and_cancelled_keep_independent_candidate_state() -> Result<()> {
    for (result, expected) in [
        (
            StageResult::Partial {
                reason: "remaining routes".into(),
            },
            ExecutionState::Partial,
        ),
        (
            StageResult::Blocked {
                reason: "database unavailable".into(),
            },
            ExecutionState::Blocked,
        ),
        (
            StageResult::Failed {
                reason: "provider failure returned as text".into(),
            },
            ExecutionState::Failed,
        ),
    ] {
        let directory = Directory::new()?;
        let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
        let input = manifest(1)?;
        let evidence = candidate(&input)?;
        let campaign = controller.create(input)?;
        let first = controller
            .dispatch_next(campaign.id, 0, &mut Worker::default())?
            .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
        controller.submit(&first.lease, "candidate", evidence)?;
        controller.submit(
            &first.lease,
            "result",
            Submission {
                schema_version: 1,
                payload: Payload::StageResult { result },
                evidence: vec![],
            },
        )?;
        let snapshot = controller.status(campaign.id)?;
        assert_eq!(snapshot.tasks[0].state, expected);
        assert_eq!(
            serde_json::to_value(snapshot.accepted[0].evidence_state)?,
            "candidate"
        );
        assert_eq!(
            serde_json::to_value(snapshot.accepted[0].remediation_state)?,
            "not_started"
        );
        let cancelled = controller.cancel(campaign.id, snapshot.revision)?;
        assert_eq!(cancelled.state(), ExecutionState::Cancelled);
        assert_eq!(cancelled.accepted.len(), 2);
        assert!(
            cancelled.tasks[0].attempts[0].runtime_slot_held,
            "cancellation is not proof of termination"
        );
        assert!(
            controller
                .submit(&first.lease, "after-cancel", completed(&first.scope))
                .is_err(),
            "cancelled worker cannot submit"
        );
    }
    Ok(())
}

#[test]
fn unsupported_and_uncertain_launch_never_report_clean_completion() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest(1)?)?;
    let mut worker = Worker {
        unsupported: true,
        ..Worker::default()
    };
    assert!(
        controller
            .dispatch_next(campaign.id, 0, &mut worker)
            .is_err(),
        "unsupported capabilities must refuse"
    );
    let blocked = controller.status(campaign.id)?;
    assert_eq!(blocked.state(), ExecutionState::Blocked);
    assert!(
        blocked.tasks[0].attempts.is_empty(),
        "no reservation for unsupported execution"
    );
    worker.unsupported = false;
    worker.launch_error = true;
    assert!(
        controller
            .dispatch_next(campaign.id, blocked.revision, &mut worker)
            .is_err(),
        "launch error must surface"
    );
    let failed = controller.status(campaign.id)?;
    assert_eq!(failed.tasks[0].state, ExecutionState::Failed);
    assert!(
        failed.tasks[0].attempts[0].runtime_slot_held,
        "uncertain launch may have started a process"
    );
    assert!(
        !failed.tasks[0].attempts[0].usage.complete,
        "unknown usage stays uncertain"
    );
    Ok(())
}
