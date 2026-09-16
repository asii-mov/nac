#[allow(dead_code)]
mod support;
use nac_appsec::*;
use std::collections::BTreeMap;
use support::*;
#[path = "cases/workflow_admission_regressions.rs"]
mod admission_regressions;
#[path = "cases/workflow_boundaries.rs"]
mod boundaries;
#[path = "cases/workflow_crash.rs"]
mod crash;
#[path = "cases/workflow_policy.rs"]
mod policy;

fn workflow_manifest(minimum: Option<u64>) -> Result<Manifest> {
    let mut manifest = manifest(1)?;
    let brief = ResearchBrief {
        schema_version: 1,
        assurance: Assurance::OpenEnded,
        source_root: "declared pinned source".into(),
        attacker_model: "unauthenticated caller".into(),
        deployment_profile: "configuration unknown".into(),
        impact_goal: "unauthorized data access".into(),
        success_property: "protected data reaches attacker".into(),
        minimum_active_research_ms: minimum,
        max_investigative_agents: 4,
    };
    let mut research = FrozenResearch::resolve(
        &manifest.repositories[0].checkout.join("skills/appsec"),
        brief,
        BTreeMap::from([("cell-0".into(), "recon".into())]),
    )?;
    research.workflow = true;
    manifest.research = Some(research);
    Ok(manifest)
}

fn action(
    controller: &Controller<SqliteRepository, TestClock>,
    lease: &Lease,
    key: &str,
    action: WorkflowAction,
) -> Result<Accepted> {
    let revision = controller.status(lease.run_id)?.accepted.len() as u64;
    controller.submit(
        lease,
        key,
        Submission {
            schema_version: 1,
            payload: Payload::Workflow { revision, action },
            evidence: vec![],
        },
    )
}

fn source(
    controller: &Controller<SqliteRepository, TestClock>,
    lease: &Lease,
) -> Result<SourceRef> {
    Ok(controller
        .read_source(
            lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "Cargo.toml".into(),
                start_line: 1,
                end_line: 3,
            },
        )?
        .source)
}

fn map(controller: &Controller<SqliteRepository, TestClock>, lease: &Lease) -> Result<Accepted> {
    inventory(controller, lease)?;
    let source = source(controller, lease)?;
    action(
        controller,
        lease,
        "map",
        WorkflowAction::Map {
            areas: vec![Area {
                key: "boundary".into(),
                description: "pinned fixture boundary".into(),
                sources: vec![source],
                trust_boundaries: vec!["unauthenticated caller to protected data".into()],
                unknowns: vec!["deployment not provided".into()],
                applicability: vec![Applicability {
                    attack_class: "authorization".into(),
                    proposed_exclusion: true,
                    reason: "safe in middleware (unsupported mapper claim)".into(),
                    sources: vec![],
                }],
            }],
            unknowns: vec!["configuration absent".into()],
        },
    )
}

fn inventory(controller: &Controller<SqliteRepository, TestClock>, lease: &Lease) -> Result<()> {
    let mut after = None;
    loop {
        after = controller
            .list_source_files(
                lease,
                SourceInventory {
                    repository: "nac-test".into(),
                    after,
                    limit: 256,
                },
            )?
            .next_after;
        if after.is_none() {
            return Ok(());
        }
    }
}

fn dispatch(
    controller: &Controller<SqliteRepository, TestClock>,
    run: Id,
    runtime: &mut Worker,
) -> Result<Assignment> {
    let status = controller.status(run)?;
    controller
        .dispatch_next(run, status.revision, runtime)?
        .ok_or_else(|| anyhow::anyhow!("no ready task"))
}

fn settle(
    controller: &Controller<SqliteRepository, TestClock>,
    run: Id,
    runtime: &mut Worker,
) -> Result<()> {
    controller.reconcile(run, runtime)?;
    for attempt in &runtime.cancelled {
        runtime.terminated.insert(*attempt, true);
    }
    controller.reconcile(run, runtime)?;
    Ok(())
}

fn approach(source: &SourceRef, class: &str) -> Approach {
    Approach {
        mechanism: source.clone(),
        attack_class: class.into(),
        idea: "inspect caller-controlled boundary".into(),
        status: FamilyStatus::Exploring,
        rationale: "trace the pinned mechanism".into(),
        evidence: vec![source.clone()],
    }
}

#[test]
fn map_freezes_denominator_children_share_slots_and_original_templates() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let manifest = workflow_manifest(None)?;
    let campaign = controller.create(manifest.clone())?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    let record = map(&controller, &root.lease)?;
    let status = controller.status(campaign.id)?;
    assert_eq!(
        status.manifest.tasks.len(),
        1,
        "dynamic work never changes manifest"
    );
    let workflow = status.workflow.as_ref().unwrap();
    assert_eq!(
        workflow.cells.len(),
        6,
        "unsupported exclusion cannot shrink denominator"
    );
    assert!(workflow.areas[0].applicability[0].proposed_exclusion);
    assert_eq!(workflow.jobs.len(), 8);
    assert_eq!(workflow.inventory.len(), 1);
    let replay = controller.submit(
        &root.lease,
        "map",
        Submission {
            schema_version: 1,
            payload: record.payload.clone(),
            evidence: vec![],
        },
    )?;
    assert_eq!(replay.id, record.id);
    for _ in 0..3 {
        let child = dispatch(&controller, campaign.id, &mut runtime)?;
        assert!(child
            .research
            .unwrap()
            .prompt
            .contains("Source discovery 1.0.0"));
    }
    assert!(
        dispatch(&controller, campaign.id, &mut runtime).is_err(),
        "root cleanup consumes the fourth slot"
    );
    let cancelled = controller.cancel(campaign.id, controller.status(campaign.id)?.revision)?;
    assert_eq!(cancelled.state(), ExecutionState::Cancelled);
    assert_eq!(cancelled.workflow.unwrap().cells.len(), 6);
    Ok(())
}

#[test]
fn validator_is_unique_blind_role_bound_and_resumable_without_erasing_history() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 4)?;
    let campaign = controller.create(workflow_manifest(Some(21_600_000))?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    map(&controller, &root.lease)?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &discovery.lease)?;
    action(
        &controller,
        &discovery.lease,
        "approach",
        WorkflowAction::Approach {
            approach: approach(&source, "authentication"),
        },
    )?;
    let candidate = Candidate {
        claim: "unauthorized access hypothesis".into(),
        prerequisites: vec!["unauthenticated caller".into()],
        unresolved_assumptions: vec!["DISCOVERER-CONFIDENCE-SECRET".into()],
        source: source.clone(),
    };
    let submission = Submission {
        schema_version: 1,
        payload: Payload::Candidate { candidate },
        evidence: vec![EvidenceInput::Upload {
            bytes: b"DISCOVERER-NOTES-SECRET".to_vec(),
        }],
    };
    let accepted = controller.submit(&discovery.lease, "candidate", submission.clone())?;
    assert_eq!(
        controller
            .submit(&discovery.lease, "candidate", submission.clone())?
            .id,
        accepted.id
    );
    assert!(controller
        .submit(&discovery.lease, "renamed-candidate", submission)
        .is_err());
    let before = controller.status(campaign.id)?;
    let workflow = before.workflow.as_ref().unwrap();
    assert_eq!(workflow.candidate_validators.len(), 1);
    let validator_id = workflow.candidate_validators[&accepted.id];
    let job = &workflow.jobs[&validator_id];
    assert_ne!(
        job.input_sha256,
        workflow.jobs[&discovery.lease.task_id].input_sha256
    );
    assert!(!job.input.to_string().contains("SECRET"));
    assert!(job.input.to_string().contains("unauthenticated caller"));
    let verdict = Validation {
        outcome: ValidationOutcome::Inconclusive,
        prerequisites: "configuration absent".into(),
        reachability: "unknown".into(),
        security_violation: "not established".into(),
        sources: vec![source.clone()],
        counterevidence: vec![],
        unknowns: vec!["configuration".into()],
        next_actions: vec!["supply pinned configuration".into()],
    };
    assert!(action(
        &controller,
        &discovery.lease,
        "forged-verdict",
        WorkflowAction::Validate {
            validation: verdict.clone()
        }
    )
    .is_err());
    controller.submit(&discovery.lease, "done", completed(&discovery.scope))?;
    settle(&controller, campaign.id, &mut runtime)?;
    let validator = loop {
        let next = dispatch(&controller, campaign.id, &mut runtime)?;
        if next.lease.task_id == validator_id {
            break next;
        }
        controller.submit(
            &next.lease,
            "blocked",
            Submission {
                schema_version: 1,
                payload: Payload::StageResult {
                    result: StageResult::Blocked {
                        reason: "fixture only".into(),
                    },
                },
                evidence: vec![],
            },
        )?;
        settle(&controller, campaign.id, &mut runtime)?;
    };
    assert_ne!(validator.lease.attempt_id, discovery.lease.attempt_id);
    assert!(validator
        .research
        .as_ref()
        .unwrap()
        .prompt
        .contains("Adversarial source validation 1.0.0"));
    assert!(!validator
        .research
        .as_ref()
        .unwrap()
        .prompt
        .contains("DISCOVERER-"));
    let query = controller.query_work(&validator.lease, 0, 1)?;
    assert_eq!(query["records"], serde_json::json!([]));
    assert!(controller.query_work(&validator.lease, 0, 33).is_err());
    action(
        &controller,
        &validator.lease,
        "verdict",
        WorkflowAction::Validate {
            validation: verdict.clone(),
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let snapshot = controller.status(campaign.id)?;
    assert!(snapshot.markdown().contains("Unresolved candidates: 1"));
    let resumed = controller.resume(
        campaign.id,
        snapshot.revision,
        validator_id,
        "Recheck the pinned prerequisite, retaining unknown configuration",
    )?;
    assert_eq!(resumed.accepted.len(), snapshot.accepted.len());
    assert_eq!(resumed.workflow.unwrap().candidate_validators.len(), 1);
    assert!(controller
        .submit(&validator.lease, "late", completed(&validator.scope))
        .is_err());
    let fresh = dispatch(&controller, campaign.id, &mut runtime)?;
    assert_eq!(fresh.lease.task_id, validator_id);
    assert_ne!(fresh.lease.attempt_id, validator.lease.attempt_id);
    let mut revised = verdict;
    revised.outcome = ValidationOutcome::Supported;
    revised.unknowns.clear();
    revised.next_actions.clear();
    action(
        &controller,
        &fresh.lease,
        "revised-verdict",
        WorkflowAction::Validate {
            validation: revised,
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let revised = controller.status(campaign.id)?;
    assert_eq!(
        revised
            .accepted
            .iter()
            .filter(|record| record.task_id == validator_id)
            .count(),
        2
    );
    assert!(revised.markdown().contains("Unresolved candidates: 0"));
    assert!(revised
        .accepted
        .iter()
        .any(|record| record.id == accepted.id));
    assert_eq!(
        controller
            .status(campaign.id)?
            .workflow
            .unwrap()
            .effort
            .credited_ms(),
        0,
        "static clock and repeated source work earn no time"
    );
    Ok(())
}

#[test]
fn two_rounds_are_persisted_and_idle_six_hours_cannot_pass_clean_gate() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let controller = open(&directory.0.join("state"), clock.clone(), 4)?;
    let campaign = controller.create(workflow_manifest(Some(21_600_000))?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    map(&controller, &root.lease)?;
    settle(&controller, campaign.id, &mut runtime)?;
    for class in BASELINE_CLASSES {
        let child = dispatch(&controller, campaign.id, &mut runtime)?;
        let source = source(&controller, &child.lease)?;
        action(
            &controller,
            &child.lease,
            "approach",
            WorkflowAction::Approach {
                approach: approach(&source, class),
            },
        )?;
        controller.submit(&child.lease, "done", completed(&child.scope))?;
        settle(&controller, campaign.id, &mut runtime)?;
    }
    let synthesis = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &synthesis.lease)?;
    let status = controller.status(campaign.id)?;
    let family = status
        .workflow
        .as_ref()
        .unwrap()
        .families
        .values()
        .find(|f| f.history[0].attack_class == "authorization")
        .unwrap()
        .id
        .clone();
    let request = Followup {
        area: "boundary".into(),
        attack_class: "authorization".into(),
        family,
        rationale: "trace alternate caller".into(),
        evidence: vec![source.clone()],
    };
    let next = Synthesis {
        assumptions: vec!["middleware safety remains unverified".into()],
        counterevidence: vec![source.clone()],
        gaps: vec!["alternate caller".into()],
        next: vec![request.clone()],
        finish: false,
    };
    action(
        &controller,
        &synthesis.lease,
        "round-one",
        WorkflowAction::Synthesize { synthesis: next },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let followup = dispatch(&controller, campaign.id, &mut runtime)?;
    assert!(action(
        &controller,
        &followup.lease,
        "duplicate-gap",
        WorkflowAction::Followup { request }
    )
    .is_err());
    let mut duplicate = approach(&source, "authorization");
    duplicate.idea = "renamed family".into();
    assert!(action(
        &controller,
        &followup.lease,
        "duplicate-family",
        WorkflowAction::Approach {
            approach: duplicate
        }
    )
    .is_err());
    controller.submit(&followup.lease, "done", completed(&followup.scope))?;
    settle(&controller, campaign.id, &mut runtime)?;
    let second = dispatch(&controller, campaign.id, &mut runtime)?;
    let final_round = Synthesis {
        assumptions: vec!["checked alternate caller".into()],
        counterevidence: vec![source],
        gaps: vec![],
        next: vec![],
        finish: true,
    };
    let early = action(
        &controller,
        &second.lease,
        "early-clean",
        WorkflowAction::Synthesize {
            synthesis: final_round.clone(),
        },
    )
    .unwrap_err();
    assert!(early.to_string().contains("active-research floor"));
    clock.advance(21_600_000);
    assert_eq!(
        controller
            .status(campaign.id)?
            .workflow
            .unwrap()
            .effort
            .credited_ms(),
        0
    );
    assert!(action(
        &controller,
        &second.lease,
        "idle-clean",
        WorkflowAction::Synthesize {
            synthesis: final_round
        }
    )
    .is_err());
    let cancelled = controller.cancel(campaign.id, controller.status(campaign.id)?.revision)?;
    assert_eq!(cancelled.state(), ExecutionState::Cancelled);
    assert!(!cancelled.workflow.unwrap().complete);
    Ok(())
}
