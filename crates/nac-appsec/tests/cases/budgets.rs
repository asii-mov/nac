use crate::support::*;
use nac_appsec::*;
use std::sync::{Arc, Barrier};

#[test]
fn competing_campaigns_share_host_slots_and_revisions_are_checked() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let controller = open(&path, TestClock::new(), 1)?;
    let first = controller.create(manifest(1)?)?;
    let second = controller.create(manifest(1)?)?;
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [first.id, second.id]
        .into_iter()
        .map(|run| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            std::thread::spawn(move || -> Result<bool> {
                let controller = open(&path, TestClock::new(), 1)?;
                barrier.wait();
                Ok(controller
                    .dispatch_next(run, 0, &mut Worker::default())
                    .is_ok())
            })
        })
        .collect();
    let mut admitted = 0;
    for handle in handles {
        admitted += usize::from(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("admission thread panicked"))??,
        );
    }
    assert_eq!(admitted, 1);
    let records = [controller.status(first.id)?, controller.status(second.id)?];
    assert_eq!(
        records
            .iter()
            .flat_map(|r| &r.tasks)
            .flat_map(|t| &t.attempts)
            .filter(|a| a.runtime_slot_held)
            .count(),
        1
    );
    assert!(
        controller.cancel(first.id, 999).is_err(),
        "stale revision cannot cancel"
    );
    assert!(
        SqliteRepository::open(&path, 2).is_err(),
        "host capacity cannot be silently changed"
    );
    Ok(())
}

#[test]
fn competing_submissions_return_one_canonical_id() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let controller = open(&path, TestClock::new(), 1)?;
    let input = manifest(1)?;
    let submission = candidate(&input)?;
    let campaign = controller.create(input)?;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut Worker::default())?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let lease = assignment.lease.clone();
            let submission = submission.clone();
            std::thread::spawn(move || -> Result<Id> {
                let controller = open(&path, TestClock::new(), 1)?;
                barrier.wait();
                Ok(controller.submit(&lease, "same", submission)?.id)
            })
        })
        .collect();
    let ids = handles
        .into_iter()
        .map(|h| {
            h.join()
                .map_err(|_| anyhow::anyhow!("submission thread panicked"))?
        })
        .collect::<Result<Vec<_>>>()?;
    assert!(
        ids.iter().all(|id| *id == ids[0]),
        "all concurrent calls return the original ID"
    );
    assert_eq!(controller.status(campaign.id)?.accepted.len(), 1);
    Ok(())
}

#[test]
fn cancellation_races_completion_without_losing_an_accepted_result() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let controller = open(&path, TestClock::new(), 1)?;
    let campaign = controller.create(manifest(1)?)?;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut Worker::default())?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let revision = controller.status(campaign.id)?.revision;
    let barrier = Arc::new(Barrier::new(2));
    let cancel_path = path.clone();
    let cancel_barrier = Arc::clone(&barrier);
    let cancellation = std::thread::spawn(move || -> Result<bool> {
        let controller = open(&cancel_path, TestClock::new(), 1)?;
        cancel_barrier.wait();
        Ok(controller.cancel(campaign.id, revision).is_ok())
    });
    barrier.wait();
    let submitted = controller.submit(
        &assignment.lease,
        "completion",
        completed(&assignment.scope),
    );
    let cancelled = cancellation
        .join()
        .map_err(|_| anyhow::anyhow!("cancellation thread panicked"))??;
    let result = controller.status(campaign.id)?;
    if let Ok(accepted) = submitted {
        assert_eq!(result.accepted.len(), 1);
        assert_eq!(result.accepted[0].id, accepted.id);
        assert_eq!(result.tasks[0].state, ExecutionState::Completed);
        assert!(
            !cancelled,
            "stale cancellation cannot overwrite completed acceptance"
        );
    } else {
        assert!(
            cancelled,
            "only cancellation can reject this valid concurrent completion"
        );
        assert_eq!(result.tasks[0].state, ExecutionState::Cancelled);
        assert!(
            result.accepted.is_empty(),
            "cancelled submission has no accepted result"
        );
    }
    assert!(
        result.tasks[0].attempts[0].runtime_slot_held,
        "neither database operation proves runtime termination"
    );
    Ok(())
}
