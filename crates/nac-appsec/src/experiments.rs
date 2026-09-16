use crate::{controller::validate_lease, source::validate_source, *};
use anyhow::{ensure, Context};

impl ExperimentProfile {
    pub fn verify(&self, repositories: &[RepositoryInput]) -> Result<()> {
        require_version(self.schema_version)?;
        self.package.verify(repositories)?;
        let mut dependencies = std::collections::BTreeSet::new();
        let mut dependency_packages = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            dependency.verify_provenance()?;
            ensure!(
                dependency_packages.insert(&dependency.package),
                "duplicate prefetched dependency package identity"
            );
            ensure!(
                dependencies.insert((
                    &dependency.package,
                    &dependency.version,
                    &dependency.archive_sha256
                )),
                "duplicate dependency provenance"
            );
        }
        ensure!(
            !self.recipes.is_empty() && self.recipes.len() <= 32,
            "invalid recipe registry"
        );
        let mut ids = std::collections::BTreeSet::new();
        for recipe in &self.recipes {
            ensure!(
                !recipe.id.is_empty() && recipe.id.len() <= 128 && ids.insert(&recipe.id),
                "invalid recipe identity"
            );
            ensure!(
                crate::artifacts::valid_hash(&recipe.recipe_sha256),
                "invalid recipe digest"
            );
            ensure!(
                recipe.recipe_sha256 == recipe.canonical_sha256()?,
                "recipe policy digest drift"
            );
            recipe.production.verify(repositories)?;
            ensure!(
                recipe
                    .production
                    .files
                    .iter()
                    .all(|file| self.package.contains(&file.repository, &file.path)),
                "recipe production export exceeds the public package"
            );
            ensure!(
                recipe.target.source_sha256 == recipe.production.manifest_sha256
                    || matches!(recipe.scope, TargetScope::ReducedDemo { .. }),
                "original target must be derived from the declared production export"
            );
            if let TargetScope::ReducedDemo {
                original, tested, ..
            } = &recipe.scope
            {
                ensure!(
                    original.source_sha256 == recipe.production.manifest_sha256,
                    "reduced target must retain declared original production provenance"
                );
                tested.verify(repositories)?;
                ensure!(
                    recipe.target.source_sha256 == tested.manifest_sha256,
                    "reduced target source must match its declared tested package"
                );
            }
            for digest in [
                &recipe.target.source_sha256,
                &recipe.target.build_sha256,
                &recipe.target.image_sha256,
                &recipe.target.environment_sha256,
            ] {
                ensure!(
                    crate::artifacts::valid_hash(digest),
                    "invalid target digest"
                );
            }
            if let TargetScope::ReducedDemo {
                declared_changes, ..
            } = &recipe.scope
            {
                ensure!(
                    !declared_changes.is_empty()
                        && declared_changes.len() <= 32
                        && declared_changes
                            .iter()
                            .all(|change| !change.is_empty() && change.len() <= 1024),
                    "reduced target requires declared changes"
                );
            }
            ensure!(
                (1..=8).contains(&recipe.repetitions)
                    && (1..=300_000).contains(&recipe.operation_ms)
                    && (1..=16_777_216).contains(&recipe.capture_bytes),
                "invalid individual experiment bound"
            );
            ensure!(
                (1..=16).contains(&recipe.interface.max_requests)
                    && !recipe.interface.routes.is_empty()
                    && recipe.interface.routes.len() <= 16,
                "invalid bounded HTTP interface"
            );
            for route in &recipe.interface.routes {
                ensure!(
                    route.actor == "attacker" && route.path_prefix != "/",
                    "public experiment interface may expose attacker routes only"
                );
                valid_request(&HttpRequest {
                    actor: route.actor.clone(),
                    method: route.method,
                    path: route.path_prefix.clone(),
                    body: String::new(),
                })?;
                ensure!(
                    route.max_body_bytes <= 8192 && !route.path_prefix.ends_with('/')
                        || route.path_prefix == "/",
                    "invalid bounded HTTP interface route"
                );
            }
        }
        Ok(())
    }
}

impl Campaign {
    pub fn attempt_occupied(&self, attempt: &Attempt) -> bool {
        attempt.runtime_slot_held
            || self.experiments.iter().any(|experiment| {
                experiment.attempt_id == attempt.lease.attempt_id
                    && experiment.trials.iter().any(ExperimentTrial::holds_target)
            })
    }

    pub fn occupied_attempts(&self) -> usize {
        self.tasks
            .iter()
            .flat_map(|task| &task.attempts)
            .filter(|attempt| self.attempt_occupied(attempt))
            .count()
    }

    pub fn occupied_targets(&self) -> usize {
        self.experiments
            .iter()
            .flat_map(|experiment| &experiment.trials)
            .filter(|trial| trial.holds_target())
            .count()
    }

    pub(crate) fn fence_experiments(&mut self, now: u64) {
        for experiment in &mut self.experiments {
            let authorized = !self.cancelled
                && self
                    .tasks
                    .iter()
                    .find(|task| task.id == experiment.task_id)
                    .and_then(|task| task.attempts.last())
                    .is_some_and(|attempt| {
                        attempt.lease.attempt_id == experiment.attempt_id
                            && !attempt.revoked
                            && attempt.runtime_slot_held
                            && attempt.stop_intent.is_none()
                            && now < attempt.deadline_ms
                    });
            if !authorized {
                for trial in &mut experiment.trials {
                    stop(trial, now);
                }
            }
        }
    }
}

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn run_experiment(&self, lease: &Lease, plan: ExperimentPlan) -> Result<Experiment> {
        require_version(plan.schema_version)?;
        ensure!(
            !plan.key.is_empty()
                && plan.key.len() <= 128
                && !plan.hypothesis.is_empty()
                && plan.hypothesis.len() <= 4096,
            "invalid experiment plan"
        );
        ensure!(
            !plan.sources.is_empty()
                && plan.sources.len() <= 16
                && !plan.requests.is_empty()
                && plan.requests.len() <= 16,
            "invalid experiment plan bounds"
        );
        let digest = hash(&serde_json::to_vec(&plan)?);
        let mut result = None;
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                authorize(campaign, lease, now)?;
                if let Some(existing) = campaign.experiments.iter().find(|experiment| {
                    experiment.task_id == lease.task_id && experiment.plan.key == plan.key
                }) {
                    ensure!(
                        existing.plan_sha256 == digest,
                        "experiment idempotency conflict"
                    );
                    result = Some(existing.clone());
                    return Ok(());
                }
                for source in &plan.sources {
                    validate_source(&campaign.manifest, source)?;
                }
                let recipe = campaign
                    .manifest
                    .experiments
                    .as_ref()
                    .context("experiments not enabled")?
                    .recipes
                    .iter()
                    .find(|recipe| recipe.id == plan.recipe_id)
                    .context("unknown registered recipe")?;
                authorize_requests(recipe, &plan.requests)?;
                let experiment = Experiment {
                    schema_version: 1,
                    id: Id::new(),
                    task_id: lease.task_id,
                    attempt_id: lease.attempt_id,
                    plan: plan.clone(),
                    plan_sha256: digest.clone(),
                    recipe: recipe.clone(),
                    trials: (0..recipe.repetitions)
                        .map(|repetition| new_trial(0, repetition, now))
                        .collect(),
                };
                result = Some(experiment.clone());
                campaign.experiments.push(experiment);
                campaign.updated_ms = now;
                Ok(())
            })?;
        result.context("experiment reservation missing")
    }

    pub fn read_experiment(&self, lease: &Lease, id: Id) -> Result<Experiment> {
        let mut campaign = self.repository.read(lease.run_id)?;
        authorize(&mut campaign, lease, self.clock.now_ms()?)?;
        campaign
            .experiments
            .into_iter()
            .find(|experiment| experiment.id == id && experiment.task_id == lease.task_id)
            .context("experiment unavailable")
    }

    pub fn cancel_experiment(&self, lease: &Lease, id: Id) -> Result<Experiment> {
        let mut result = None;
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                authorize(campaign, lease, now)?;
                ensure!(
                    !campaign
                        .accepted
                        .iter()
                        .any(|accepted| match &accepted.payload {
                            Payload::Candidate { candidate } => candidate.experiments.contains(&id),
                            Payload::Workflow {
                                action: WorkflowAction::Validate { validation },
                                ..
                            } => validation.experiments.contains(&id),
                            _ => false,
                        }),
                    "accepted evidence makes the linked experiment immutable"
                );
                let experiment = campaign
                    .experiments
                    .iter_mut()
                    .find(|experiment| experiment.id == id && experiment.task_id == lease.task_id)
                    .context("experiment unavailable")?;
                for trial in &mut experiment.trials {
                    stop(trial, now);
                }
                campaign.updated_ms = now;
                result = Some(experiment.clone());
                Ok(())
            })?;
        result.context("experiment unavailable")
    }

    pub fn reset_experiment(&self, lease: &Lease, id: Id) -> Result<Experiment> {
        let mut result = None;
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                authorize(campaign, lease, now)?;
                ensure!(
                    !campaign
                        .accepted
                        .iter()
                        .any(|accepted| match &accepted.payload {
                            Payload::Candidate { candidate } => candidate.experiments.contains(&id),
                            Payload::Workflow {
                                action: WorkflowAction::Validate { validation },
                                ..
                            } => validation.experiments.contains(&id),
                            _ => false,
                        }),
                    "accepted evidence makes the linked experiment immutable"
                );
                let experiment = campaign
                    .experiments
                    .iter_mut()
                    .find(|experiment| experiment.id == id && experiment.task_id == lease.task_id)
                    .context("experiment unavailable")?;
                ensure!(
                    experiment.trials.iter().all(|trial| !trial.holds_target()),
                    "old target cleanup must be proved before reset"
                );
                let epoch = experiment
                    .trials
                    .last()
                    .context("missing trial")?
                    .epoch
                    .checked_add(1)
                    .context("epoch overflow")?;
                experiment.attempt_id = lease.attempt_id;
                experiment.trials.extend(
                    (0..experiment.recipe.repetitions)
                        .map(|repetition| new_trial(epoch, repetition, now)),
                );
                campaign.updated_ms = now;
                result = Some(experiment.clone());
                Ok(())
            })?;
        result.context("experiment unavailable")
    }

    pub fn reconcile_experiments(
        &self,
        run: Id,
        runner: &mut impl ExperimentRunner,
    ) -> Result<Campaign> {
        let snapshot = self.repository.update(run, None, &mut |campaign, _| {
            let now = self.clock.now_ms()?;
            campaign.fence_experiments(now);
            campaign.updated_ms = now;
            Ok(())
        })?;
        for experiment in snapshot.experiments {
            for trial in experiment.trials.iter().filter(|trial| {
                trial.holds_target() && (!trial.operator_recovery_required || trial.stop_requested)
            }) {
                let mut desired = None;
                self.repository.update(run, None, &mut |campaign, _| {
                    let now = self.clock.now_ms()?;
                    campaign.fence_experiments(now);
                    campaign.updated_ms = now;
                    let current = find_trial(campaign, experiment.id, trial.run_key)?;
                    if !current.holds_target() {
                        return Ok(());
                    }
                    if current.phase == ExperimentPhase::Reserved {
                        event(
                            current,
                            ExperimentPhase::PendingCreate,
                            ExperimentCode::Pending,
                            now,
                        );
                    }
                    desired = Some(ExperimentDesired {
                        experiment_id: experiment.id,
                        run_key: current.run_key,
                        stop: current.stop_requested,
                        phase: current.phase,
                        recipe: experiment.recipe.clone(),
                        plan_sha256: experiment.plan_sha256.clone(),
                        requests: experiment.plan.requests.clone(),
                    });
                    Ok(())
                })?;
                let Some(desired) = desired else {
                    continue;
                };
                let observation = runner.reconcile(&desired);
                self.repository.update(run, None, &mut |campaign, _| {
                    let now = self.clock.now_ms()?;
                    campaign.fence_experiments(now);
                    campaign.updated_ms = now;
                    let current = find_trial(campaign, experiment.id, trial.run_key)?;
                    if !current.holds_target() {
                        return Ok(());
                    }
                    let observed = match &observation {
                        Ok(observed) => observed,
                        Err(code) => {
                            recoverable_error(current, *code, now);
                            return Ok(());
                        }
                    };
                    ensure!(
                        observed.run_key == current.run_key,
                        "stale experiment callback"
                    );
                    if current.stop_requested && !desired.stop {
                        return Ok(());
                    }
                    ensure!(
                        transition(current.phase, observed.phase, current.stop_requested),
                        "invalid experiment transition"
                    );
                    if let Some(identity) = &observed.effective_target {
                        ensure!(
                            identity == &experiment.recipe.target,
                            "effective target identity mismatch"
                        );
                        current.effective_target = Some(identity.clone());
                    }
                    if let Some(receipt) = &observed.execution_receipt {
                        verify_receipt(receipt, &experiment, current)?;
                        current.execution_receipt = Some(receipt.clone());
                    }
                    if let Some(EvaluatorVerdict(verdict)) = &observed.evaluation {
                        ensure!(
                            !current.stop_requested
                                && current.verdict.is_none()
                                && observed.phase == ExperimentPhase::Assessed
                                && current.effective_target.is_some(),
                            "experiment evaluation is not authorized"
                        );
                        ensure!(
                            verdict.controls.len() <= 8
                                && verdict.diagnostics.len() <= 16
                                && verdict.diagnostics.iter().all(|diagnostic| diagnostic
                                    .byte_offset
                                    .is_none_or(|offset| offset <= 16_777_216)),
                            "invalid evaluator projection"
                        );
                        if matches!(
                            verdict.assessment,
                            Assessment::Confirmed | Assessment::NotObserved
                        ) {
                            let required = experiment.recipe.oracle_class.required_controls();
                            ensure!(
                                verdict.controls.len() == required.len()
                                    && required.iter().all(|kind| {
                                        verdict
                                            .controls
                                            .iter()
                                            .filter(|control| {
                                                control.control == *kind && control.passed
                                            })
                                            .count()
                                            == 1
                                    }),
                                "required controls did not pass"
                            );
                        }
                        current.verdict = Some(verdict.clone());
                    }
                    if observed.phase != current.phase || observed.code != ExperimentCode::Pending {
                        current.consecutive_recovery_attempts = 0;
                    }
                    event(current, observed.phase, observed.code, now);
                    Ok(())
                })?;
            }
        }
        self.status(run)
    }

    pub fn recover_experiment(&self, lease: &Lease, id: Id) -> Result<Experiment> {
        let mut result = None;
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                authorize(campaign, lease, now)?;
                let experiment = campaign
                    .experiments
                    .iter_mut()
                    .find(|experiment| experiment.id == id && experiment.task_id == lease.task_id)
                    .context("experiment unavailable")?;
                for trial in experiment
                    .trials
                    .iter_mut()
                    .filter(|trial| trial.operator_recovery_required)
                {
                    trial.operator_recovery_required = false;
                    trial.consecutive_recovery_attempts = 0;
                    trial.phase = trial
                        .recovery_phase
                        .take()
                        .unwrap_or(ExperimentPhase::Reserved);
                    event(trial, trial.phase, ExperimentCode::Pending, now);
                }
                campaign.updated_ms = now;
                result = Some(experiment.clone());
                Ok(())
            })?;
        result.context("experiment unavailable")
    }
}

pub(crate) fn validate_linked_experiments(
    campaign: &Campaign,
    task_id: Id,
    experiment_ids: &[Id],
    claim: &str,
    source: &SourceRef,
) -> Result<EvidenceState> {
    ensure!(
        !experiment_ids.is_empty() && experiment_ids.len() <= 8,
        "linked evidence requires one to eight experiments"
    );
    let mut assessment = None;
    let mut original = true;
    for id in experiment_ids {
        let experiment = campaign
            .experiments
            .iter()
            .find(|experiment| experiment.id == *id)
            .context("linked experiment unavailable")?;
        ensure!(
            experiment.task_id == task_id,
            "linked experiment belongs to another task"
        );
        ensure!(
            experiment.plan.hypothesis == claim
                && experiment.plan.sources.iter().any(|item| item == source),
            "linked experiment does not support this exact claim and source"
        );
        ensure!(
            experiment.trials.iter().all(|trial| {
                trial.phase == ExperimentPhase::Cleaned
                    && trial.verdict.is_some()
                    && trial.execution_receipt.is_some()
                    && trial.effective_target.is_some()
            }),
            "linked experiment is not settled with trusted execution provenance"
        );
        for trial in &experiment.trials {
            let Some(verdict) = trial.verdict.as_ref() else {
                anyhow::bail!("linked experiment verdict disappeared")
            };
            if let Some(previous) = assessment {
                ensure!(
                    previous == verdict.assessment,
                    "linked experiment repetitions have inconsistent outcomes"
                );
            } else {
                assessment = Some(verdict.assessment);
            }
            original &= matches!(experiment.recipe.scope, TargetScope::OriginalTarget);
        }
    }
    Ok(match (assessment, original) {
        (Some(Assessment::Confirmed), true) => EvidenceState::Reproduced,
        (Some(Assessment::NotObserved), true) => EvidenceState::Disproved,
        _ => EvidenceState::Inconclusive,
    })
}

fn authorize(campaign: &mut Campaign, lease: &Lease, now: u64) -> Result<()> {
    validate_lease(campaign, lease, now)?;
    let role = campaign
        .workflow
        .as_ref()
        .and_then(|workflow| workflow.jobs.get(&lease.task_id))
        .map(|job| job.role)
        .or_else(|| {
            let key = &campaign
                .tasks
                .iter()
                .find(|task| task.id == lease.task_id)?
                .plan
                .key;
            match campaign
                .manifest
                .research
                .as_ref()?
                .stages
                .get(key)?
                .as_str()
            {
                "discovery" => Some(ResearchRole::Discovery),
                "validation" => Some(ResearchRole::Validation),
                _ => None,
            }
        });
    ensure!(
        matches!(
            role,
            Some(ResearchRole::Discovery | ResearchRole::Validation)
        ),
        "role cannot run experiments"
    );
    ensure!(
        campaign.manifest.experiments.is_some(),
        "experiments not enabled"
    );
    Ok(())
}

fn new_trial(epoch: u32, repetition: u32, now: u64) -> ExperimentTrial {
    ExperimentTrial {
        run_key: Id::new(),
        epoch,
        repetition,
        phase: ExperimentPhase::Reserved,
        stop_requested: false,
        consecutive_recovery_attempts: 0,
        operator_recovery_required: false,
        recovery_phase: None,
        effective_target: None,
        execution_receipt: None,
        verdict: None,
        events: vec![ExperimentEvent {
            at_ms: now,
            phase: ExperimentPhase::Reserved,
            code: ExperimentCode::Pending,
        }],
    }
}

fn valid_request(request: &HttpRequest) -> Result<()> {
    ensure!(
        matches!(request.actor.as_str(), "owner" | "attacker" | "anonymous")
            && request.body.len() <= 8192,
        "invalid bounded HTTP request"
    );
    ensure!(
        request.path.starts_with('/')
            && !request.path.starts_with("//")
            && request.path.len() <= 1024
            && !request.path.contains(['\r', '\n', '\0', '#', '\\']),
        "invalid bounded HTTP request path"
    );
    Ok(())
}

fn authorize_requests(recipe: &RecipeBinding, requests: &[HttpRequest]) -> Result<()> {
    ensure!(
        !requests.is_empty() && requests.len() <= recipe.interface.max_requests as usize,
        "experiment exceeds the declared request interface"
    );
    for request in requests {
        valid_request(request)?;
        ensure!(
            recipe.interface.routes.iter().any(|route| {
                route.actor == request.actor
                    && route.method == request.method
                    && (route.path_prefix == "/"
                        || request.path == route.path_prefix
                        || request.path.starts_with(&format!("{}/", route.path_prefix)))
                    && request.body.len() as u64 <= route.max_body_bytes
            }),
            "request lies outside the declared experiment interface"
        );
    }
    Ok(())
}

fn verify_receipt(
    receipt: &ExecutionReceipt,
    experiment: &Experiment,
    trial: &ExperimentTrial,
) -> Result<()> {
    ensure!(
        receipt.adapter_version == "nac-appsec-target-v2"
            && receipt.source_manifest_sha256 == experiment.recipe.target.source_sha256
            && receipt.build_sha256 == experiment.recipe.target.build_sha256
            && receipt.image_sha256 == experiment.recipe.target.image_sha256
            && receipt.environment_sha256 == experiment.recipe.target.environment_sha256
            && receipt.request_plan_sha256 == experiment.plan_sha256,
        "adapter execution provenance drift"
    );
    for value in [
        &receipt.broker_sha256,
        &receipt.evaluator_sha256,
        &receipt.launch_sha256,
        &receipt.mount_sha256,
        &receipt.network_sha256,
        &receipt.log_sha256,
        &receipt.resource_sha256,
    ] {
        ensure!(
            crate::artifacts::valid_hash(value),
            "invalid execution receipt digest"
        );
    }
    ensure!(
        trial.effective_target.is_some()
            || receipt.image_sha256 == experiment.recipe.target.image_sha256,
        "execution receipt precedes target identity"
    );
    Ok(())
}

fn find_trial(campaign: &mut Campaign, experiment: Id, key: Id) -> Result<&mut ExperimentTrial> {
    campaign
        .experiments
        .iter_mut()
        .find(|item| item.id == experiment)
        .and_then(|item| item.trials.iter_mut().find(|trial| trial.run_key == key))
        .context("experiment trial unavailable")
}

fn stop(trial: &mut ExperimentTrial, now: u64) {
    if trial.holds_target() && !trial.stop_requested {
        trial.stop_requested = true;
        event(
            trial,
            ExperimentPhase::CleanupPending,
            ExperimentCode::Cancelled,
            now,
        );
    }
}

fn event(trial: &mut ExperimentTrial, phase: ExperimentPhase, code: ExperimentCode, now: u64) {
    trial.phase = phase;
    if trial
        .events
        .last()
        .is_none_or(|last| last.phase != phase || last.code != code)
    {
        if trial.events.len() < 128 {
            trial.events.push(ExperimentEvent {
                at_ms: now,
                phase,
                code,
            });
        } else {
            trial.stop_requested = true;
            trial.phase = ExperimentPhase::CleanupPending;
        }
    }
}

fn recoverable_error(trial: &mut ExperimentTrial, code: ExperimentCode, now: u64) {
    const MAX_AUTOMATIC_RECOVERY_ATTEMPTS: u32 = 3;
    trial.consecutive_recovery_attempts = trial.consecutive_recovery_attempts.saturating_add(1);
    trial.recovery_phase = Some(trial.phase);
    event(trial, trial.phase, code, now);
    if trial.consecutive_recovery_attempts >= MAX_AUTOMATIC_RECOVERY_ATTEMPTS {
        trial.operator_recovery_required = true;
        event(
            trial,
            ExperimentPhase::CleanupPending,
            ExperimentCode::RecoveryExhausted,
            now,
        );
    }
}

fn transition(from: ExperimentPhase, to: ExperimentPhase, stopped: bool) -> bool {
    use ExperimentPhase::*;
    from == to
        || (stopped && matches!(to, CleanupPending | Cleaned))
        || matches!(
            (from, to),
            (PendingCreate, PendingStart)
                | (PendingStart, Ready)
                | (Ready, PendingRequest)
                | (PendingRequest, Captured | CleanupPending)
                | (Captured, Assessed)
                | (Assessed, CleanupPending)
                | (CleanupPending, Cleaned)
        )
}
