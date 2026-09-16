use super::*;

#[test]
fn frozen_stage_drift_is_persisted_as_a_blocker_without_admission() -> Result<()> {
    let directory = Directory::new()?;
    let mut manifest = workflow_manifest(None)?;
    let research = manifest.research.as_mut().unwrap();
    let frozen_root = directory.0.join("skills");
    std::fs::create_dir(&frozen_root)?;
    for name in ["skills.md", "skills.lock.json"] {
        std::fs::copy(research.root.join(name), frozen_root.join(name))?;
    }
    for skill in research.templates.values().flatten() {
        for (path, body) in &skill.files {
            let path = frozen_root.join(path);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, body)?;
        }
    }
    research.root = frozen_root.clone();
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let path = frozen_root.join("skills/validation/SKILL.md");
    let original = std::fs::read(&path)?;
    std::fs::write(&path, b"unapproved active validator replacement")?;
    let mut runtime = Worker::default();
    assert!(dispatch(&controller, campaign.id, &mut runtime).is_err());
    let blocked = controller.status(campaign.id)?;
    assert_eq!(blocked.state(), ExecutionState::Blocked);
    assert!(blocked
        .dispatch_blocker
        .unwrap()
        .contains("skill resource drift"));
    assert!(blocked.tasks[0].attempts.is_empty());
    assert!(runtime.starts.is_empty());
    std::fs::write(&path, original)?;
    let assignment = dispatch(&controller, campaign.id, &mut runtime)?;
    assert!(assignment
        .research
        .unwrap()
        .prompt
        .contains("Source reconnaissance 1.0.0"));
    assert!(controller.status(campaign.id)?.dispatch_blocker.is_none());
    Ok(())
}

#[test]
fn complete_scope_needs_two_rounds_and_retains_its_frozen_denominator() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let mut manifest = workflow_manifest(None)?;
    manifest
        .declared_inputs
        .insert("irrelevant_environment_annotation".into(), None);
    let campaign = controller.create(manifest)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    inventory(&controller, &root.lease)?;
    let source = source(&controller, &root.lease)?;
    action(
        &controller,
        &root.lease,
        "source-question",
        WorkflowAction::AskSource {
            question: SourceQuestion {
                key: "boundary-check".into(),
                question: "What does the pinned boundary declaration establish?".into(),
                sources: vec![source.clone()],
            },
        },
    )?;
    action(
        &controller,
        &root.lease,
        "map",
        WorkflowAction::Map {
            areas: vec![Area {
                key: "entry".into(),
                description: "entry boundary".into(),
                sources: vec![source.clone()],
                trust_boundaries: vec!["caller to state".into()],
                unknowns: vec![],
                applicability: vec![],
            }],
            unknowns: vec![],
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    for class in BASELINE_CLASSES {
        let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
        action(
            &controller,
            &discovery.lease,
            "approach",
            WorkflowAction::Approach {
                approach: approach(&source, class),
            },
        )?;
        if class == "authentication" {
            let mut blocked = approach(&source, class);
            blocked.status = FamilyStatus::Blocked;
            blocked.rationale = "unresolved prerequisite remains visible".into();
            action(
                &controller,
                &discovery.lease,
                "blocked-family",
                WorkflowAction::Approach { approach: blocked },
            )?;
        }
        controller.submit(&discovery.lease, "done", completed(&discovery.scope))?;
        settle(&controller, campaign.id, &mut runtime)?;
    }
    let first = dispatch(&controller, campaign.id, &mut runtime)?;
    let final_round = Synthesis {
        assumptions: vec!["source-only hypotheses reviewed; not security assurance".into()],
        counterevidence: vec![source.clone()],
        gaps: vec![],
        next: vec![],
        finish: true,
    };
    assert!(action(
        &controller,
        &first.lease,
        "one-round-clean",
        WorkflowAction::Synthesize {
            synthesis: final_round.clone()
        }
    )
    .unwrap_err()
    .to_string()
    .contains("at least two"));
    let in_round_family = controller
        .status(campaign.id)?
        .workflow
        .unwrap()
        .families
        .values()
        .find(|f| f.history[0].attack_class == "injection")
        .unwrap()
        .id
        .clone();
    action(
        &controller,
        &first.lease,
        "in-round-child",
        WorkflowAction::Followup {
            request: Followup {
                area: "entry".into(),
                attack_class: "injection".into(),
                family: in_round_family,
                rationale: "check a gap before ending this round".into(),
                evidence: vec![source.clone()],
            },
        },
    )?;
    assert!(action(
        &controller,
        &first.lease,
        "premature-synthesis",
        WorkflowAction::Synthesize {
            synthesis: final_round.clone()
        }
    )
    .unwrap_err()
    .to_string()
    .contains("settled same-round work"));
    let in_round_child = dispatch(&controller, campaign.id, &mut runtime)?;
    assert_eq!(
        controller
            .status(campaign.id)?
            .tasks
            .iter()
            .find(|task| task.id == first.lease.task_id)
            .unwrap()
            .state,
        ExecutionState::Running,
        "the root waits without making its child depend on root completion"
    );
    controller.submit(
        &in_round_child.lease,
        "done",
        completed(&in_round_child.scope),
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let family = controller
        .status(campaign.id)?
        .workflow
        .unwrap()
        .families
        .values()
        .find(|f| f.history[0].attack_class == "authorization")
        .unwrap()
        .id
        .clone();
    action(
        &controller,
        &first.lease,
        "next-round",
        WorkflowAction::Synthesize {
            synthesis: Synthesis {
                assumptions: vec!["alternate caller remains".into()],
                counterevidence: vec![],
                gaps: vec!["alternate path".into()],
                next: vec![Followup {
                    area: "entry".into(),
                    attack_class: "authorization".into(),
                    family,
                    rationale: "inspect alternate caller".into(),
                    evidence: vec![source],
                }],
                finish: false,
            },
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let child = dispatch(&controller, campaign.id, &mut runtime)?;
    controller.submit(&child.lease, "done", completed(&child.scope))?;
    settle(&controller, campaign.id, &mut runtime)?;
    let second = dispatch(&controller, campaign.id, &mut runtime)?;
    assert!(action(
        &controller,
        &second.lease,
        "finish",
        WorkflowAction::Synthesize {
            synthesis: final_round.clone()
        }
    )
    .unwrap_err()
    .to_string()
    .contains("source research questions remain unresolved"));
    action(
        &controller,
        &second.lease,
        "resolve-source-question",
        WorkflowAction::ResolveSource {
            resolution: SourceResolution {
                key: "boundary-check".into(),
                answer: "The cited declaration establishes the source-only boundary under review"
                    .into(),
                sources: final_round.counterevidence.clone(),
            },
        },
    )?;
    assert!(action(
        &controller,
        &second.lease,
        "finish",
        WorkflowAction::Synthesize {
            synthesis: final_round.clone()
        }
    )
    .unwrap_err()
    .to_string()
    .contains("blocked approach families"));
    let evidence = controller
        .read_source(
            &second.lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "Cargo.toml".into(),
                start_line: 4,
                end_line: 5,
            },
        )?
        .source;
    let mut reopened = approach(&final_round.counterevidence[0], "authentication");
    reopened.evidence = vec![evidence];
    reopened.rationale = "new source evidence resolves the blocked prerequisite".into();
    action(
        &controller,
        &second.lease,
        "reopen-family",
        WorkflowAction::Approach { approach: reopened },
    )?;
    action(
        &controller,
        &second.lease,
        "finish",
        WorkflowAction::Synthesize {
            synthesis: final_round,
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let status = controller.status(campaign.id)?;
    assert_eq!(status.state(), ExecutionState::Completed);
    assert_eq!(
        status.manifest.declared_inputs["irrelevant_environment_annotation"],
        None
    );
    assert_eq!(status.manifest.tasks.len(), 1);
    assert_eq!(status.workflow.as_ref().unwrap().rounds.len(), 2);
    assert_eq!(
        status
            .workflow
            .as_ref()
            .unwrap()
            .cells
            .iter()
            .filter(|cell| cell.baseline)
            .count(),
        6
    );
    assert!(status
        .markdown()
        .contains("Baseline completed/planned: 6/6"));
    assert!(status
        .markdown()
        .contains("Additional proposed/completed: 2/2"));
    assert!(status.markdown().contains("not security assurance"));
    let mut wrong_class = status.clone();
    let workflow = wrong_class.workflow.as_mut().unwrap();
    let task = workflow
        .cells
        .iter()
        .find(|cell| cell.baseline && cell.attack_class == "authentication")
        .unwrap()
        .task;
    for family in workflow.families.values_mut() {
        family.tasks.retain(|id| *id != task);
    }
    workflow
        .families
        .values_mut()
        .find(|family| family.history[0].attack_class == "injection")
        .unwrap()
        .tasks
        .push(task);
    let connection = rusqlite::Connection::open(directory.0.join("state/control.sqlite"))?;
    connection.execute(
        "UPDATE campaigns SET record=?1 WHERE id=?2",
        rusqlite::params![
            serde_json::to_string(&wrong_class)?,
            campaign.id.to_string()
        ],
    )?;
    let loaded = controller.status(campaign.id)?;
    assert_eq!(loaded.state(), ExecutionState::Partial);
    assert!(!loaded.workflow.as_ref().unwrap().complete);
    assert!(loaded
        .markdown()
        .contains("Baseline completed/planned: 5/6"));
    assert!(loaded.markdown().contains("Completed scope: 10/11 tasks"));
    assert_eq!(loaded.revision, wrong_class.revision);
    assert_eq!(
        serde_json::to_value(&loaded.accepted)?,
        serde_json::to_value(&status.accepted)?
    );
    let mut legacy = status;
    let receipt = legacy
        .workflow
        .as_mut()
        .unwrap()
        .inventory
        .get_mut("nac-test")
        .unwrap();
    let InventoryReceipt::Enumeration(enumeration) = receipt else {
        panic!("expected a complete inventory proof");
    };
    *receipt = InventoryReceipt::LegacyHash(enumeration.listing_sha256.clone());
    let connection = rusqlite::Connection::open(directory.0.join("state/control.sqlite"))?;
    connection.execute(
        "UPDATE campaigns SET record=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&legacy)?, campaign.id.to_string()],
    )?;
    let loaded = controller.status(campaign.id)?;
    assert_eq!(loaded.state(), ExecutionState::Partial);
    assert!(!loaded.workflow.as_ref().unwrap().complete);
    assert_eq!(loaded.revision, legacy.revision);
    assert_eq!(
        serde_json::to_value(&loaded.accepted)?,
        serde_json::to_value(&legacy.accepted)?
    );
    Ok(())
}

#[test]
fn blocked_families_require_new_evidence_and_queries_cannot_unblind_validation() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(workflow_manifest(None)?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    map(&controller, &root.lease)?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &discovery.lease)?;
    let mut proposal = approach(&source, "authentication");
    action(
        &controller,
        &discovery.lease,
        "family",
        WorkflowAction::Approach {
            approach: proposal.clone(),
        },
    )?;
    proposal.status = FamilyStatus::Blocked;
    proposal.rationale = "missing prerequisite blocks this route".into();
    action(
        &controller,
        &discovery.lease,
        "blocked",
        WorkflowAction::Approach {
            approach: proposal.clone(),
        },
    )?;
    proposal.status = FamilyStatus::Exploring;
    proposal.idea = "new title is not a new mechanism".into();
    proposal.rationale = "try the same route again".into();
    assert!(action(
        &controller,
        &discovery.lease,
        "reopen-without-evidence",
        WorkflowAction::Approach {
            approach: proposal.clone()
        }
    )
    .is_err());
    let family = controller
        .status(campaign.id)?
        .workflow
        .unwrap()
        .families
        .keys()
        .next()
        .unwrap()
        .clone();
    let mut followup = Followup {
        area: "boundary".into(),
        attack_class: "authentication".into(),
        family,
        rationale: "inspect route".into(),
        evidence: vec![source.clone()],
    };
    assert!(action(
        &controller,
        &discovery.lease,
        "blocked-child",
        WorkflowAction::Followup {
            request: followup.clone()
        }
    )
    .is_err());
    let new_source = controller
        .read_source(
            &discovery.lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "Cargo.toml".into(),
                start_line: 4,
                end_line: 5,
            },
        )?
        .source;
    proposal.evidence = vec![new_source];
    action(
        &controller,
        &discovery.lease,
        "reopen",
        WorkflowAction::Approach { approach: proposal },
    )?;
    followup.area = "invented-out-of-scope-area".into();
    assert!(action(
        &controller,
        &discovery.lease,
        "out-of-scope",
        WorkflowAction::Followup { request: followup }
    )
    .is_err());
    let accepted = controller.submit(
        &discovery.lease,
        "candidate",
        candidate(&campaign.manifest)?,
    )?;
    let validator = dispatch(&controller, campaign.id, &mut runtime)?;
    assert!(controller
        .read_work_record(&validator.lease, accepted.id, 0, 128)
        .unwrap_err()
        .to_string()
        .contains("cannot read discoverer"));
    let canonical = controller.read_work_record(&discovery.lease, accepted.id, 0, 128)?;
    assert_eq!(canonical["bytes"].as_array().unwrap().len(), 128);
    assert!(canonical["next_offset"].is_number());
    assert!(controller
        .read_work_record(&discovery.lease, accepted.id, 0, 100000)
        .is_err());
    assert!(controller
        .resume(
            campaign.id,
            controller.status(campaign.id)?.revision,
            discovery.lease.task_id,
            &"x".repeat(4097)
        )
        .is_err());
    Ok(())
}
