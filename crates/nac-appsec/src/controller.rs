use crate::{repository::slots, source::validate_manifest, *};
use anyhow::ensure;

pub struct Controller<R, C = SystemClock> {
    pub(crate) repository: R,
    pub(crate) artifacts: ArtifactStore,
    pub(crate) clock: C,
}

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn new(repository: R, artifacts: ArtifactStore, clock: C) -> Self {
        Self {
            repository,
            artifacts,
            clock,
        }
    }

    pub fn create(&self, manifest: Manifest) -> Result<Campaign> {
        validate_manifest(&manifest)?;
        let now = self.clock.now_ms()?;
        let mut campaign = Campaign {
            schema_version: 1,
            id: Id::new(),
            revision: 0,
            created_ms: now,
            updated_ms: now,
            configuration_hash: hash(&serde_json::to_vec(&manifest)?),
            tasks: manifest
                .tasks
                .iter()
                .map(|plan| Task {
                    id: Id::new(),
                    plan: plan.clone(),
                    state: ExecutionState::Queued,
                    reason: None,
                    handoff: None,
                    attempts: vec![],
                    failed_recoveries: 0,
                    progress_fingerprints: vec![],
                })
                .collect(),
            manifest,
            cancelled: false,
            dispatch_blocker: None,
            accepted: vec![],
            pending_submissions: vec![],
            experiments: vec![],
            workflow: None,
        };
        campaign.workflow = Workflow::initialize(&campaign)?;
        self.repository.insert(&campaign)?;
        Ok(campaign)
    }

    pub fn status(&self, run: Id) -> Result<Campaign> {
        let campaign = self.repository.read(run)?;
        for accepted in &campaign.accepted {
            for reference in &accepted.evidence {
                self.artifacts.verify(reference)?;
            }
        }
        for attempt in campaign.tasks.iter().flat_map(|task| &task.attempts) {
            if let Some(artifact) = &attempt.diagnostic_evidence {
                self.artifacts.verify(artifact)?;
            }
        }
        Ok(campaign)
    }

    pub fn dispatch_next(
        &self,
        run: Id,
        revision: u64,
        runtime: &mut impl Runtime,
    ) -> Result<Option<Assignment>> {
        if let Err(error) = runtime.check_capabilities() {
            let reason = format!("unsupported runtime capability: {error}");
            self.repository
                .update(run, Some(revision), &mut |campaign, _| {
                    campaign.dispatch_blocker = Some(reason.clone());
                    campaign.updated_ms = self.clock.now_ms()?;
                    Ok(())
                })?;
            anyhow::bail!(reason);
        }
        let mut assignment = None;
        let mut input_error = None;
        self.repository
            .update(run, Some(revision), &mut |campaign, host_available| {
                let now = self.clock.now_ms()?;
                ensure!(!campaign.cancelled, "campaign is cancelled");
                let active = slots(campaign);
                ensure!(
                    active < host_available && active < campaign.manifest.max_concurrency,
                    "concurrency reservation exhausted"
                );
                let Some(index) = campaign
                    .tasks
                    .iter()
                    .enumerate()
                    .filter(|(_, task)| {
                        task.state == ExecutionState::Queued
                            && campaign
                                .workflow
                                .as_ref()
                                .is_none_or(|workflow| workflow.ready(campaign, task))
                            && task.plan.dependencies.iter().all(|key| {
                                campaign.tasks.iter().any(|dependency| {
                                    dependency.plan.key == *key
                                        && dependency.state == ExecutionState::Completed
                                })
                            })
                    })
                    .min_by_key(|(index, task)| {
                        (
                            campaign
                                .workflow
                                .as_ref()
                                .map(|w| w.priority(campaign, task))
                                .unwrap_or_default(),
                            *index,
                        )
                    })
                    .map(|(index, _)| index)
                else {
                    return Ok(());
                };
                let prepared = if let Some(workflow) = &campaign.workflow {
                    workflow
                        .prepare(campaign, campaign.tasks[index].id)
                        .map(Some)
                } else {
                    campaign
                        .manifest
                        .research
                        .as_ref()
                        .map(|research| research.prepare(&campaign.tasks[index].plan.key))
                        .transpose()
                };
                let mut prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let reason = format!("frozen research input unavailable: {error}");
                        campaign.dispatch_blocker = Some(reason.clone());
                        campaign.updated_ms = now;
                        input_error = Some(reason);
                        return Ok(());
                    }
                };
                let experiment_role = campaign
                    .workflow
                    .as_ref()
                    .and_then(|workflow| workflow.jobs.get(&campaign.tasks[index].id))
                    .map(|job| job.role)
                    .or_else(|| {
                        let research = campaign.manifest.research.as_ref()?;
                        match research
                            .stages
                            .get(&campaign.tasks[index].plan.key)?
                            .as_str()
                        {
                            "discovery" => Some(ResearchRole::Discovery),
                            "validation" => Some(ResearchRole::Validation),
                            _ => None,
                        }
                    });
                if matches!(
                    experiment_role,
                    Some(ResearchRole::Discovery | ResearchRole::Validation)
                ) {
                    if let (Some(prepared), Some(profile)) =
                        (&mut prepared, &campaign.manifest.experiments)
                    {
                        prepared.add_experiments(profile)?;
                    }
                }
                let task = &mut campaign.tasks[index];
                ensure!(
                    task.failed_recoveries < campaign.manifest.watchdog.max_failed_recoveries,
                    "consecutive failed recovery limit reached"
                );
                let generation: u32 = task
                    .attempts
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("generation overflow"))?
                    .try_into()?;
                let lease = Lease {
                    run_id: run,
                    task_id: task.id,
                    attempt_id: Id::new(),
                    generation,
                    token: Id::new(),
                };
                let deadline_ms = now
                    .checked_add(campaign.manifest.watchdog.lease_ms)
                    .ok_or_else(|| anyhow::anyhow!("lease deadline overflow"))?;
                let input_fingerprint = hash(&serde_json::to_vec(&(
                    &campaign.configuration_hash,
                    &task.plan,
                    &task.handoff,
                    generation,
                    &prepared,
                ))?);
                task.attempts.push(Attempt {
                    lease: lease.clone(),
                    started_ms: now,
                    deadline_ms,
                    terminated_ms: None,
                    revoked: false,
                    runtime_slot_held: true,
                    usage: Usage::default(),
                    reserved_submission_bytes: 0,
                    input_fingerprint: input_fingerprint.clone(),
                    last_liveness_ms: now,
                    last_progress_ms: now,
                    watchdog_state: WatchdogState::Healthy,
                    diagnostic_ms: None,
                    diagnostic_evidence: None,
                    last_operation: None,
                    made_meaningful_progress: false,
                    stop_intent: None,
                    runtime_exit: None,
                });
                task.state = ExecutionState::Running;
                task.reason = None;
                campaign.dispatch_blocker = None;
                campaign.updated_ms = now;
                assignment = Some(Assignment {
                    lease,
                    scope: task.plan.scope.clone(),
                    repositories: campaign.manifest.repositories.clone(),
                    input_fingerprint,
                    handoff: task.handoff.clone(),
                    limits: task.plan.operation_limits,
                    deadline_ms,
                    research: prepared,
                    experiment_tools: campaign.manifest.experiments.is_some()
                        && matches!(
                            experiment_role,
                            Some(ResearchRole::Discovery | ResearchRole::Validation)
                        ),
                });
                Ok(())
            })?;
        if let Some(error) = input_error {
            anyhow::bail!(error);
        }
        if let Some(assignment) = &assignment {
            if runtime.start(assignment).is_err() {
                self.repository.update(run, None, &mut |campaign, _| {
                    let (task, index) = locate(campaign, &assignment.lease)?;
                    task.attempts[index].revoked = true;
                    task.attempts[index].stop_intent = Some(StopIntent::LaunchFailure);
                    task.state = ExecutionState::Failed;
                    task.reason = Some("runtime launch failed; termination and usage remain uncertain until reconciliation".into());
                    campaign.updated_ms = self.clock.now_ms()?;
                    Ok(())
                })?;
                anyhow::bail!("runtime launch failed; slot retained");
            }
        }
        Ok(assignment)
    }

    pub fn cancel(&self, run: Id, revision: u64) -> Result<Campaign> {
        self.repository
            .update(run, Some(revision), &mut |campaign, _| {
                campaign.cancelled = true;
                campaign.updated_ms = self.clock.now_ms()?;
                for task in &mut campaign.tasks {
                    if task.state != ExecutionState::Completed {
                        task.state = ExecutionState::Cancelled;
                        task.reason = Some(
                            "cancellation requested; held slots require runtime reconciliation"
                                .into(),
                        );
                    }
                    for attempt in &mut task.attempts {
                        attempt.revoked = true;
                        if attempt.runtime_slot_held {
                            attempt.stop_intent = Some(StopIntent::OperatorCancellation);
                        }
                    }
                }
                Ok(())
            })
    }

    pub fn resume(&self, run: Id, revision: u64, task_id: Id, handoff: &str) -> Result<Campaign> {
        ensure!(
            !handoff.trim().is_empty() && handoff.len() <= 4096,
            "resume requires a nonempty handoff of at most 4096 bytes"
        );
        self.repository
            .update(run, Some(revision), &mut |campaign, _| {
                let unresolved_validation = campaign
                    .workflow
                    .as_ref()
                    .and_then(|workflow| workflow.latest_validation(campaign, task_id))
                    .is_some_and(|v| !v.is_resolved());
                ensure!(
                    campaign
                        .tasks
                        .iter()
                        .find(|task| task.id == task_id)
                        .is_some_and(|task| !task
                            .attempts
                            .iter()
                            .any(|attempt| campaign.attempt_occupied(attempt))),
                    "termination must be reconciled before resume"
                );
                let task = campaign
                    .tasks
                    .iter_mut()
                    .find(|t| t.id == task_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown task"))?;
                ensure!(
                    (unresolved_validation && task.state == ExecutionState::Completed)
                        || !matches!(
                            task.state,
                            ExecutionState::Queued
                                | ExecutionState::Running
                                | ExecutionState::Completed
                        ),
                    "task is not resumable"
                );
                ensure!(
                    !task.attempts.iter().any(|a| a.runtime_slot_held),
                    "termination must be reconciled before resume"
                );
                ensure!(
                    task.failed_recoveries < campaign.manifest.watchdog.max_failed_recoveries,
                    "consecutive failed recovery limit reached"
                );
                task.state = ExecutionState::Queued;
                task.reason = None;
                task.handoff = Some(handoff.to_string());
                campaign.cancelled = false;
                campaign.dispatch_blocker = None;
                campaign.updated_ms = self.clock.now_ms()?;
                Ok(())
            })
    }

    pub fn recover(
        &self,
        run: Id,
        revision: u64,
        task_id: Id,
        runtime: &mut impl Runtime,
    ) -> Result<Campaign> {
        self.repository
            .update(run, Some(revision), &mut |campaign, _| {
                let task = campaign
                    .tasks
                    .iter_mut()
                    .find(|t| t.id == task_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown task"))?;
                let attempt = task
                    .attempts
                    .last_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing attempt"))?;
                ensure!(
                    attempt.watchdog_state == WatchdogState::SuspectedStall
                        && attempt.diagnostic_ms.is_some(),
                    "recovery requires a diagnosed suspected stall"
                );
                ensure!(
                    task.failed_recoveries < campaign.manifest.watchdog.max_failed_recoveries,
                    "consecutive failed recovery limit reached"
                );
                attempt.revoked = true;
                attempt.stop_intent = Some(StopIntent::WatchdogRecovery);
                task.state = ExecutionState::Blocked;
                task.reason =
                    Some("watchdog recovery requested; termination must be reconciled".into());
                campaign.updated_ms = self.clock.now_ms()?;
                Ok(())
            })?;
        self.reconcile(run, runtime)
    }

    pub fn reconcile(&self, run: Id, runtime: &mut impl Runtime) -> Result<Campaign> {
        let snapshot = self.repository.read(run)?;
        for task in &snapshot.tasks {
            for attempt in task.attempts.iter().filter(|a| a.runtime_slot_held) {
                let cancellation_sent = attempt.stop_intent.is_some() || attempt.revoked;
                if cancellation_sent {
                    runtime.cancel(attempt.lease.attempt_id)?;
                }
                let observation = match runtime.observe(attempt.lease.attempt_id) {
                    Ok(observation) => observation,
                    Err(_) => {
                        let mut expired = false;
                        self.repository.update(run, None, &mut |campaign, _| {
                            let now = self.clock.now_ms()?;
                            let (task, index) = locate(campaign, &attempt.lease)?;
                            expired = task.attempts[index].stop_intent.is_none() && now >= task.attempts[index].deadline_ms;
                            if expired {
                                task.attempts[index].revoked = true;
                                task.attempts[index].stop_intent = Some(StopIntent::LeaseExpired);
                                if task.state == ExecutionState::Running { task.state = ExecutionState::Blocked; }
                            }
                            task.reason = Some("runtime observation unavailable; liveness, usage and termination remain uncertain".into());
                            Ok(())
                        })?;
                        if expired && !cancellation_sent {
                            runtime.cancel(attempt.lease.attempt_id)?;
                        }
                        anyhow::bail!("runtime observation unavailable; slot retained");
                    }
                };
                let progress = match &observation {
                    RuntimeObservation::Live { progress, .. }
                    | RuntimeObservation::Terminated { progress, .. } => progress,
                };
                if let Some(artifact) = progress {
                    ensure!(
                        artifact.bytes <= task.plan.operation_limits.output_bytes,
                        "progress receipt exceeds individual output limit"
                    );
                    self.artifacts.verify(artifact)?;
                }
                let mut must_cancel = false;
                let mut must_diagnose = false;
                self.repository.update(run, None, &mut |campaign, _| {
                    let now = self.clock.now_ms()?;
                    campaign.updated_ms = now;
                    let policy = campaign.manifest.watchdog;
                    let (task, index) = locate(campaign, &attempt.lease)?;
                    let current = &mut task.attempts[index];
                    if !current.runtime_slot_held {
                        return Ok(());
                    }
                    let (usage, exit) = match &observation {
                        RuntimeObservation::Live { usage, .. } => (usage, None),
                        RuntimeObservation::Terminated { usage, exit, .. } => (usage, Some(exit)),
                    };
                    current.usage.tokens = max_known(current.usage.tokens, usage.tokens);
                    current.usage.output_bytes =
                        max_known(current.usage.output_bytes, usage.output_bytes);
                    current.usage.complete = exit.is_some()
                        && usage.complete
                        && usage.tokens.is_some()
                        && usage.output_bytes.is_some();
                    if let RuntimeObservation::Live {
                        oldest_active_operation,
                        ..
                    } = &observation
                    {
                        current.last_liveness_ms = now;
                        if current.stop_intent.is_none() && now >= current.deadline_ms {
                            current.revoked = true;
                            current.stop_intent = Some(StopIntent::LeaseExpired);
                        }
                        if !current.revoked {
                            current.deadline_ms = now
                                .checked_add(policy.lease_ms)
                                .ok_or_else(|| anyhow::anyhow!("lease deadline overflow"))?;
                        }
                        if let Some(operation) = oldest_active_operation {
                            ensure!(!operation.id.trim().is_empty() && operation.id.len() <= 128 && operation.started_ms >= current.started_ms && operation.started_ms <= now, "invalid trusted operation identity or start time");
                            if let Some(previous) = &current.last_operation {
                                ensure!(operation.started_ms >= previous.started_ms && (operation.id != previous.id || operation.started_ms == previous.started_ms), "operation timing changed for the same identity or moved backwards");
                            }
                            current.last_operation = Some(operation.clone());
                            if matches!(current.stop_intent, None | Some(StopIntent::AcceptedResultCleanup)) && now.saturating_sub(operation.started_ms) >= task.plan.operation_limits.wall_ms {
                                current.revoked = true;
                                current.stop_intent = Some(StopIntent::OperationTimeout);
                                task.reason = Some("individual operation time limit exceeded; termination requested".into());
                            }
                        }
                        let quiet = now.saturating_sub(current.last_progress_ms);
                        if quiet >= policy.warn_after_ms {
                            current.watchdog_state = if quiet >= policy.stall_after_ms
                                && current.diagnostic_ms.is_some_and(|at| {
                                    now.saturating_sub(at) >= policy.diagnostic_grace_ms
                                }) {
                                WatchdogState::SuspectedStall
                            } else {
                                WatchdogState::Warning
                            };
                            must_diagnose = current.diagnostic_ms.is_none();
                        }
                    }
                    if let Some(artifact) = progress {
                        if !current.revoked && !task.progress_fingerprints.contains(&artifact.sha256) {
                            task.progress_fingerprints.push(artifact.sha256.clone());
                            current.last_progress_ms = now;
                            current.made_meaningful_progress = true;
                            current.watchdog_state = WatchdogState::Healthy;
                            current.diagnostic_ms = None;
                            current.diagnostic_evidence = None;
                            task.failed_recoveries = 0;
                            must_diagnose = false;
                        }
                    }
                    if let Some(exit) = exit {
                        current.runtime_slot_held = false;
                        current.revoked = true;
                        current.terminated_ms = Some(now);
                        current.runtime_exit = Some(*exit);
                        match (task.state, current.stop_intent, exit) {
                            (ExecutionState::Completed | ExecutionState::Cancelled, _, _) => {},
                            (ExecutionState::Partial, Some(StopIntent::AcceptedResultCleanup), RuntimeExit::Success | RuntimeExit::Cancelled) if current.made_meaningful_progress => {
                                task.failed_recoveries = 0;
                            }
                            _ => task.failed_recoveries = task.failed_recoveries.saturating_add(1),
                        }
                        if task.state == ExecutionState::Running {
                            task.state = match exit {
                                RuntimeExit::EnvironmentBlocked => ExecutionState::Blocked,
                                RuntimeExit::Cancelled => ExecutionState::Cancelled,
                                RuntimeExit::ProviderFailure | RuntimeExit::Success => {
                                    ExecutionState::Failed
                                }
                            };
                            task.reason = Some(
                                match exit {
                                    RuntimeExit::Success => {
                                        "runtime exited without an accepted structured stage result"
                                    }
                                    RuntimeExit::ProviderFailure => "provider failure",
                                    RuntimeExit::EnvironmentBlocked => "environment unavailable",
                                    RuntimeExit::Cancelled => "runtime cancelled",
                                }
                                .into(),
                            );
                        }
                    } else {
                        must_cancel = current.stop_intent.is_some() || current.revoked;
                        if current.revoked && task.state == ExecutionState::Running {
                            task.state = ExecutionState::Blocked;
                            task.reason.get_or_insert_with(|| {
                                "lease expired or operation interrupted; termination pending".into()
                            });
                        }
                    }
                    Ok(())
                })?;
                if must_diagnose && !must_cancel {
                    let diagnosis = runtime.diagnose(attempt.lease.attempt_id)?;
                    ensure!(
                        diagnosis.bytes <= task.plan.operation_limits.output_bytes,
                        "diagnostic exceeds individual output limit"
                    );
                    self.artifacts.verify(&diagnosis)?;
                    self.repository.update(run, None, &mut |campaign, _| {
                        let (task, index) = locate(campaign, &attempt.lease)?;
                        if task.attempts[index].watchdog_state != WatchdogState::Healthy {
                            task.attempts[index].diagnostic_ms = Some(self.clock.now_ms()?);
                            task.attempts[index].diagnostic_evidence = Some(diagnosis.clone());
                        }
                        Ok(())
                    })?;
                }
                if must_cancel && !cancellation_sent {
                    runtime.cancel(attempt.lease.attempt_id)?;
                }
            }
        }
        self.status(run)
    }
}

fn max_known(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

pub(crate) fn locate<'a>(
    campaign: &'a mut Campaign,
    lease: &Lease,
) -> Result<(&'a mut Task, usize)> {
    ensure!(campaign.id == lease.run_id, "wrong campaign lease");
    let task = campaign
        .tasks
        .iter_mut()
        .find(|t| t.id == lease.task_id)
        .ok_or_else(|| anyhow::anyhow!("unknown task"))?;
    let index = task
        .attempts
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("missing attempt"))?;
    let current = &task.attempts[index];
    ensure!(
        current.lease.attempt_id == lease.attempt_id
            && current.lease.generation == lease.generation
            && current.lease.token == lease.token,
        "stale fencing token"
    );
    Ok((task, index))
}

pub(crate) fn validate_lease(campaign: &mut Campaign, lease: &Lease, now: u64) -> Result<()> {
    ensure!(!campaign.cancelled, "campaign cancelled");
    let (task, index) = locate(campaign, lease)?;
    let attempt = &task.attempts[index];
    ensure!(
        !attempt.revoked && now < attempt.deadline_ms,
        "lease expired or revoked"
    );
    Ok(())
}
