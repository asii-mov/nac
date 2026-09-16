use crate::{source::validate_source, *};
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn authorize(campaign: &Campaign, task: Id, payload: &Payload) -> Result<()> {
    let Some(workflow) = &campaign.workflow else {
        ensure!(
            !matches!(payload, Payload::Workflow { .. }),
            "workflow is not enabled"
        );
        return Ok(());
    };
    let role = workflow
        .jobs
        .get(&task)
        .context("missing workflow role")?
        .role;
    let permitted = match payload {
        Payload::Candidate { .. }
        | Payload::StageResult {
            result: StageResult::Completed { .. },
        } => role == ResearchRole::Discovery,
        Payload::StageResult { .. } => true,
        Payload::Workflow { action, .. } => match action {
            WorkflowAction::AskSource { .. } | WorkflowAction::ResolveSource { .. } => matches!(
                role,
                ResearchRole::Recon | ResearchRole::Discovery | ResearchRole::Synthesis
            ),
            WorkflowAction::Map { .. } => role == ResearchRole::Recon,
            WorkflowAction::Approach { .. } | WorkflowAction::Followup { .. } => {
                matches!(role, ResearchRole::Discovery | ResearchRole::Synthesis)
            }
            WorkflowAction::Validate { .. } => role == ResearchRole::Validation,
            WorkflowAction::Synthesize { .. } => role == ResearchRole::Synthesis,
        },
    };
    ensure!(
        permitted,
        "controller-bound role is not authorized for this mutation"
    );
    Ok(())
}

pub(crate) enum NewJob {
    Discovery(String),
    Validation(Id),
    Synthesis,
}

pub(crate) fn add_job(
    campaign: &mut Campaign,
    workflow: &mut Workflow,
    parent: Id,
    round: u32,
    kind: NewJob,
    input: serde_json::Value,
) -> Result<Id> {
    let (role, cell, candidate) = match kind {
        NewJob::Discovery(cell) => (ResearchRole::Discovery, Some(cell), None),
        NewJob::Validation(candidate) => (ResearchRole::Validation, None, Some(candidate)),
        NewJob::Synthesis => (ResearchRole::Synthesis, None, None),
    };
    let root = campaign
        .tasks
        .iter()
        .find(|t| t.id == workflow.root)
        .context("missing root")?;
    let id = Id::new();
    let purpose = format!(
        "{} round {round} {}",
        role.stage(),
        cell.as_deref().unwrap_or("campaign evidence")
    );
    campaign.tasks.push(Task {
        id,
        plan: TaskPlan {
            key: format!("{}-{id}", role.stage()),
            scope: purpose.clone(),
            dependencies: vec![],
            operation_limits: root.plan.operation_limits,
        },
        state: ExecutionState::Queued,
        reason: None,
        handoff: None,
        attempts: vec![],
        failed_recoveries: 0,
        progress_fingerprints: vec![],
    });
    workflow.jobs.insert(
        id,
        ResearchJob {
            role,
            parent: Some(parent),
            purpose,
            round,
            cell,
            candidate,
            input_sha256: hash(&serde_json::to_vec(&input)?),
            input,
            effective_inputs: BTreeMap::new(),
        },
    );
    Ok(id)
}

pub(crate) fn apply(campaign: &mut Campaign, lease: &Lease, record: &Accepted) -> Result<()> {
    let Some(mut workflow) = campaign.workflow.take() else {
        ensure!(
            !matches!(record.payload, Payload::Workflow { .. }),
            "workflow is not enabled"
        );
        return Ok(());
    };
    let job = workflow
        .jobs
        .get(&lease.task_id)
        .context("missing workflow role")?
        .clone();
    match &record.payload {
        Payload::Candidate { candidate } => {
            crate::workflow::candidate_job(campaign, &mut workflow, record, candidate)?;
        }
        Payload::StageResult {
            result: StageResult::Completed { .. },
        } => {
            ensure!(
                job.role == ResearchRole::Discovery,
                "role requires its typed workflow result, not generic completion"
            );
            ensure!(
                workflow.assigned_class_work_supported(lease.task_id),
                "discovery requires source-grounded work bound to its assigned attack class before completion"
            );
        }
        Payload::StageResult { .. } => {}
        Payload::Workflow { action, .. } => {
            match action {
                WorkflowAction::AskSource { .. } | WorkflowAction::ResolveSource { .. } => {
                    ensure!(
                        matches!(
                            job.role,
                            ResearchRole::Recon | ResearchRole::Discovery | ResearchRole::Synthesis
                        ),
                        "validators cannot resolve campaign source questions or fixed inputs"
                    );
                    crate::workflow_questions::admit(campaign, action)?;
                }
                WorkflowAction::Map { areas, unknowns } => {
                    ensure!(
                        job.role == ResearchRole::Recon && workflow.areas.is_empty(),
                        "only the initial recon root can freeze the map"
                    );
                    ensure!(
                        campaign
                            .manifest
                            .repositories
                            .iter()
                            .all(|repo| workflow.inventory.get(&repo.identity).is_some_and(InventoryReceipt::complete)),
                        "recon requires complete contiguous inventory from the beginning for every pinned repository"
                    );
                    ensure!(
                        !areas.is_empty() && areas.len() <= 64,
                        "map requires 1-64 cited areas"
                    );
                    let mut keys = BTreeSet::new();
                    for area in areas {
                        bounded(&area.key)?;
                        bounded(&area.description)?;
                        ensure!(keys.insert(&area.key), "duplicate area");
                        sources(campaign, &area.sources, true)?;
                        for proposal in &area.applicability {
                            ensure!(
                                BASELINE_CLASSES.contains(&proposal.attack_class.as_str()),
                                "unknown attack class"
                            );
                            bounded(&proposal.reason)?;
                            sources(campaign, &proposal.sources, false)?;
                        }
                    }
                    workflow.areas = areas.clone();
                    workflow.unknowns = unknowns.clone();
                    for inventory in workflow.inventory.values_mut() {
                        inventory.freeze();
                    }
                    for area in areas {
                        for class in BASELINE_CLASSES {
                            let id = hash(&serde_json::to_vec(&(
                                &area.key,
                                class,
                                &workflow.scenario_sha256,
                            ))?);
                            let input = serde_json::json!({"role":"discovery", "area":area,"attack_class":class,"scenario_sha256":workflow.scenario_sha256,"applicability":"All proposals remain unverified; none removes baseline work"});
                            let task = add_job(
                                campaign,
                                &mut workflow,
                                lease.task_id,
                                1,
                                NewJob::Discovery(id.clone()),
                                input,
                            )?;
                            workflow.cells.push(Cell {
                                id,
                                area: area.key.clone(),
                                attack_class: class.into(),
                                scenario_sha256: workflow.scenario_sha256.clone(),
                                baseline: true,
                                family: None,
                                task,
                                round: 1,
                            });
                        }
                    }
                    synthesis_job(campaign, &mut workflow, 1)?;
                    complete(campaign, lease.task_id)?;
                }
                WorkflowAction::Approach { approach } => {
                    ensure!(
                        matches!(job.role, ResearchRole::Discovery | ResearchRole::Synthesis),
                        "role cannot register approach families"
                    );
                    register(campaign, &mut workflow, lease.task_id, approach)?;
                }
                WorkflowAction::Followup { request } => {
                    ensure!(
                        matches!(job.role, ResearchRole::Discovery | ResearchRole::Synthesis),
                        "role cannot request followups"
                    );
                    followup(campaign, &mut workflow, lease.task_id, job.round, request)?;
                }
                WorkflowAction::Validate { validation } => {
                    ensure!(
                        job.role == ResearchRole::Validation,
                        "only the assigned independent validator can submit a verdict"
                    );
                    bounded(&validation.prerequisites)?;
                    bounded(&validation.reachability)?;
                    bounded(&validation.security_violation)?;
                    sources(campaign, &validation.sources, true)?;
                    sources(campaign, &validation.counterevidence, false)?;
                    ensure!(
                        validation.outcome == ValidationOutcome::Inconclusive
                            || validation.is_resolved(),
                        "terminal validation cannot retain material unknowns; submit inconclusive"
                    );
                    if validation.outcome == ValidationOutcome::Inconclusive {
                        ensure!(
                            !validation.unknowns.is_empty() && !validation.next_actions.is_empty(),
                            "inconclusive validation needs unknowns and next actions"
                        );
                    }
                    if validation.outcome == ValidationOutcome::Disproved {
                        ensure!(
                            !validation.counterevidence.is_empty(),
                            "disproof requires source counterevidence, not missing configuration"
                        );
                    }
                    ensure!(
                        !campaign
                            .accepted
                            .iter()
                            .any(|a| a.attempt_id == lease.attempt_id
                                && matches!(
                                    a.payload,
                                    Payload::Workflow {
                                        action: WorkflowAction::Validate { .. },
                                        ..
                                    }
                                )),
                        "validator already returned a verdict in this attempt"
                    );
                    complete(campaign, lease.task_id)?;
                }
                WorkflowAction::Synthesize { synthesis } => {
                    ensure!(
                        job.role == ResearchRole::Synthesis,
                        "only root synthesis can redirect rounds"
                    );
                    ensure!(
                        workflow.ready(
                            campaign,
                            campaign
                                .tasks
                                .iter()
                                .find(|task| task.id == lease.task_id)
                                .context("missing synthesis task")?
                        ),
                        "synthesis waits for settled same-round work"
                    );
                    ensure!(
                        !synthesis.assumptions.is_empty(),
                        "synthesis must challenge assumptions explicitly"
                    );
                    sources(campaign, &synthesis.counterevidence, false)?;
                    ensure!(
                        !(synthesis.finish && !synthesis.next.is_empty()),
                        "cannot finish and request another round"
                    );
                    if synthesis.finish {
                        ensure!(
                            !workflow.rounds.is_empty(),
                            "completion requires at least two synthesis rounds"
                        );
                        let minimum = campaign
                            .manifest
                            .research
                            .as_ref()
                            .and_then(|r| r.brief.minimum_active_research_ms)
                            .unwrap_or(0);
                        ensure!(workflow.effort.credited_ms() >= minimum, "active-research floor not met; unproven model intervals receive no credit");
                        ensure!(campaign.manifest.repositories.iter().all(|repo| workflow.inventory.get(&repo.identity).is_some_and(InventoryReceipt::mapped)), "baseline lacks complete inventory proof at map admission; start a new campaign");
                        ensure!(
                            synthesis.gaps.is_empty(),
                            "unresolved coverage cannot be clean completion"
                        );
                        ensure!(workflow.unknowns.is_empty() && workflow.areas.iter().all(|area| area.unknowns.is_empty()), "frozen map unknowns remain unresolved; changed input context requires a new campaign");
                        ensure!(
                            crate::workflow_questions::unresolved(campaign).is_empty(),
                            "source research questions remain unresolved"
                        );
                        ensure!(
                            workflow
                                .families
                                .values()
                                .all(|family| family.history.last().is_some_and(
                                    |approach| approach.status != FamilyStatus::Blocked
                                )),
                            "blocked approach families remain unresolved"
                        );
                        ensure!(
                            campaign.tasks.iter().all(|task| task.id == lease.task_id
                                || (task.state == ExecutionState::Completed
                                    && workflow.assigned_class_work_supported(task.id))),
                            "partial, blocked or failed scope remains incomplete"
                        );
                        ensure!(
                            workflow.candidate_validators.values().all(|task| workflow
                                .latest_validation(campaign, *task)
                                .is_some_and(Validation::is_resolved)),
                            "inconclusive candidates remain unresolved"
                        );
                        workflow.complete = true;
                    } else {
                        ensure!(!synthesis.next.is_empty() || !synthesis.gaps.is_empty(), "another round needs nonduplicate followups or explicit unresolved gaps");
                        for request in &synthesis.next {
                            followup(
                                campaign,
                                &mut workflow,
                                lease.task_id,
                                job.round + 1,
                                request,
                            )?;
                        }
                        if !synthesis.next.is_empty() {
                            synthesis_job(campaign, &mut workflow, job.round + 1)?;
                        }
                    }
                    workflow.rounds.push(synthesis.clone());
                    complete(campaign, lease.task_id)?;
                    if !synthesis.finish && synthesis.next.is_empty() {
                        let task = campaign
                            .tasks
                            .iter_mut()
                            .find(|t| t.id == lease.task_id)
                            .context("missing synthesis task")?;
                        task.state = ExecutionState::Blocked;
                        task.reason = Some(format!(
                            "synthesis retains unresolved gaps: {}",
                            synthesis.gaps.join("; ")
                        ));
                    }
                }
            }
        }
    }
    campaign.workflow = Some(workflow);
    Ok(())
}

fn complete(campaign: &mut Campaign, id: Id) -> Result<()> {
    let task = campaign
        .tasks
        .iter_mut()
        .find(|t| t.id == id)
        .context("missing stage task")?;
    task.state = ExecutionState::Completed;
    task.attempts
        .last_mut()
        .context("missing attempt")?
        .stop_intent = Some(StopIntent::AcceptedResultCleanup);
    Ok(())
}

fn synthesis_job(campaign: &mut Campaign, workflow: &mut Workflow, round: u32) -> Result<()> {
    let input = serde_json::json!({"role":"synthesis","round":round,"scenario_sha256":workflow.scenario_sha256,"instruction":"Query canonical work pages, challenge assumptions and request evidence-grounded underexplored families. Coverage is not security assurance."});
    add_job(
        campaign,
        workflow,
        workflow.root,
        round,
        NewJob::Synthesis,
        input,
    )?;
    Ok(())
}

fn register(
    campaign: &Campaign,
    workflow: &mut Workflow,
    task: Id,
    approach: &Approach,
) -> Result<()> {
    bounded(&approach.idea)?;
    bounded(&approach.rationale)?;
    ensure!(
        BASELINE_CLASSES.contains(&approach.attack_class.as_str()),
        "unknown attack class"
    );
    validate_source(&campaign.manifest, &approach.mechanism)?;
    sources(campaign, &approach.evidence, true)?;
    let id = hash(&serde_json::to_vec(&(
        &approach.mechanism.repository,
        &approach.mechanism.commit,
        &approach.mechanism.path,
        &approach.attack_class,
    ))?);
    if let Some(family) = workflow.families.get_mut(&id) {
        let last = family.history.last().context("missing family history")?;
        let new_evidence = has_new_evidence(&approach.evidence, &family.history);
        let status_transition = family.tasks.contains(&task)
            && last.status != approach.status
            && matches!(
                approach.status,
                FamilyStatus::Blocked | FamilyStatus::Exhausted
            );
        ensure!(
            (new_evidence || status_transition) && last.rationale != approach.rationale,
            "duplicate family or reopening without new source evidence and mechanism rationale"
        );
        family.history.push(approach.clone());
        if !family.tasks.contains(&task) {
            family.tasks.push(task);
        }
    } else {
        workflow.families.insert(
            id.clone(),
            Family {
                id,
                history: vec![approach.clone()],
                tasks: vec![task],
            },
        );
    }
    Ok(())
}

fn followup(
    campaign: &mut Campaign,
    workflow: &mut Workflow,
    parent: Id,
    round: u32,
    request: &Followup,
) -> Result<()> {
    bounded(&request.rationale)?;
    sources(campaign, &request.evidence, true)?;
    ensure!(
        workflow.areas.iter().any(|area| area.key == request.area)
            && BASELINE_CLASSES.contains(&request.attack_class.as_str()),
        "followup is outside the frozen area/class scope"
    );
    let family = workflow
        .families
        .get(&request.family)
        .context("register a source-grounded family before requesting work")?;
    let approach = family.history.last().context("missing family history")?;
    ensure!(
        approach.status == FamilyStatus::Exploring && approach.attack_class == request.attack_class,
        "family is blocked, exhausted or incompatible; reopen with new evidence first"
    );
    let exploration = family
        .history
        .iter()
        .enumerate()
        .rev()
        .find(|(index, approach)| has_new_evidence(&approach.evidence, &family.history[..*index]))
        .map(|(_, approach)| approach)
        .context("family lacks a source-grounded exploration")?;
    let exploration_bytes = serde_json::to_vec(exploration)?;
    let mut exploration_record = None;
    for (index, accepted) in campaign.accepted.iter().enumerate() {
        if let Payload::Workflow {
            action: WorkflowAction::Approach { approach },
            ..
        } = &accepted.payload
        {
            if serde_json::to_vec(approach)? == exploration_bytes {
                exploration_record = Some((index, accepted.id));
            }
        }
    }
    let (exploration_index, exploration_id) =
        exploration_record.context("family exploration lacks canonical acceptance")?;
    let id = hash(&serde_json::to_vec(&(
        &request.area,
        &request.attack_class,
        &request.family,
        &workflow.scenario_sha256,
        exploration_id,
    ))?);
    ensure!(
        !workflow.cells.iter().any(|cell| cell.id == id),
        "duplicate followup gap/family despite title or rationale changes"
    );
    let matching_cells: Vec<_> = workflow
        .cells
        .iter()
        .filter(|cell| {
            !cell.baseline
                && cell.area == request.area
                && cell.attack_class == request.attack_class
                && cell.family.as_ref() == Some(&request.family)
        })
        .collect();
    if !matching_cells.is_empty() {
        let same_gap = |prior: &Followup| {
            prior.area == request.area
                && prior.attack_class == request.attack_class
                && prior.family == request.family
        };
        let previous_index = campaign
            .accepted
            .iter()
            .rposition(|accepted| match &accepted.payload {
                Payload::Workflow {
                    action: WorkflowAction::Followup { request },
                    ..
                } => same_gap(request),
                Payload::Workflow {
                    action: WorkflowAction::Synthesize { synthesis },
                    ..
                } => synthesis.next.iter().any(&same_gap),
                _ => false,
            })
            .context("previous followup lacks canonical acceptance")?;
        ensure!(
            exploration_index > previous_index,
            "duplicate followup without newly accepted source evidence"
        );
        ensure!(
            matching_cells.iter().all(|cell| campaign
                .tasks
                .iter()
                .find(|task| task.id == cell.task)
                .is_some_and(|task| !matches!(
                    task.state,
                    ExecutionState::Queued | ExecutionState::Running
                ) && !task
                    .attempts
                    .iter()
                    .any(|attempt| attempt.runtime_slot_held))),
            "previous exploration must settle before admitting reopened work"
        );
    }
    let input = serde_json::json!({"role":"discovery","followup":request,"scenario_sha256":workflow.scenario_sha256,"exploration_id":exploration_id});
    let task = add_job(
        campaign,
        workflow,
        parent,
        round,
        NewJob::Discovery(id.clone()),
        input,
    )?;
    workflow
        .families
        .get_mut(&request.family)
        .context("missing family")?
        .tasks
        .push(task);
    workflow.cells.push(Cell {
        id,
        area: request.area.clone(),
        attack_class: request.attack_class.clone(),
        scenario_sha256: workflow.scenario_sha256.clone(),
        baseline: false,
        family: Some(request.family.clone()),
        task,
        round,
    });
    Ok(())
}

fn has_new_evidence(proposed: &[SourceRef], history: &[Approach]) -> bool {
    proposed.iter().any(|source| {
        let mut covered: Vec<_> = history
            .iter()
            .flat_map(|approach| &approach.evidence)
            .filter(|old| {
                old.repository == source.repository
                    && old.commit == source.commit
                    && old.path == source.path
                    && old.content_sha256 == source.content_sha256
            })
            .map(|old| (u64::from(old.start_line), u64::from(old.end_line)))
            .collect();
        covered.sort_unstable();
        let mut next = u64::from(source.start_line);
        for (start, end) in covered {
            if start > next {
                break;
            }
            next = next.max(end + 1);
            if next > u64::from(source.end_line) {
                return false;
            }
        }
        true
    })
}

fn sources(campaign: &Campaign, sources: &[SourceRef], required: bool) -> Result<()> {
    ensure!(!required || !sources.is_empty(), "source evidence required");
    ensure!(sources.len() <= 64, "source reference count exceeds bound");
    for source in sources {
        validate_source(&campaign.manifest, source)?;
    }
    Ok(())
}

fn bounded(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 4096,
        "workflow text must be nonempty and at most 4096 bytes"
    );
    Ok(())
}
