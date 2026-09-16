use super::*;

fn pinned_fixture(files: usize) -> Result<(Directory, Manifest)> {
    let directory = Directory::new()?;
    let checkout = directory.0.join("source");
    std::fs::create_dir(&checkout)?;
    for index in 0..files {
        std::fs::write(
            checkout.join(format!("f{index:03}.txt")),
            "pinned source witness\n",
        )?;
    }
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec!["commit", "-qm", "bounded inventory fixture"],
    ] {
        anyhow::ensure!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&checkout)
                .args(args)
                .status()?
                .success(),
            "fixture git failed"
        );
    }
    let commit = std::process::Command::new("git")
        .arg("-C")
        .arg(&checkout)
        .args(["rev-parse", "HEAD"])
        .output()?;
    let mut manifest = workflow_manifest(None)?;
    manifest.repositories[0].checkout = checkout;
    manifest.repositories[0].commit = String::from_utf8(commit.stdout)?.trim().into();
    Ok((directory, manifest))
}

fn witness(
    controller: &Controller<SqliteRepository, TestClock>,
    lease: &Lease,
    index: usize,
) -> Result<SourceRef> {
    Ok(controller
        .read_source(
            lease,
            SourceRead {
                repository: "nac-test".into(),
                path: format!("f{index:03}.txt"),
                start_line: 1,
                end_line: 1,
            },
        )?
        .source)
}

fn map_action(source: &SourceRef) -> WorkflowAction {
    WorkflowAction::Map {
        areas: vec![Area {
            key: "entry".into(),
            description: "pinned sources".into(),
            sources: vec![source.clone()],
            trust_boundaries: vec!["caller to state".into()],
            unknowns: vec![],
            applicability: vec![],
        }],
        unknowns: vec![],
    }
}

#[test]
fn cell_completion_requires_assigned_class_work_but_allows_cross_area_proposals() -> Result<()> {
    let (directory, manifest) = pinned_fixture(2)?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    inventory(&controller, &root.lease)?;
    let first = witness(&controller, &root.lease, 0)?;
    let other = witness(&controller, &root.lease, 1)?;
    let WorkflowAction::Map {
        mut areas,
        unknowns,
    } = map_action(&first)
    else {
        unreachable!();
    };
    let mut other_area = areas[0].clone();
    other_area.key = "other".into();
    other_area.sources = vec![other];
    areas.push(other_area);
    action(
        &controller,
        &root.lease,
        "map",
        WorkflowAction::Map { areas, unknowns },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let query = controller.query_work(&discovery.lease, 0, 1)?;
    assert_eq!(query["input"]["attack_class"], "authentication");
    assert_eq!(query["input"]["area"]["key"], "entry");
    let foreign_source = witness(&controller, &discovery.lease, 1)?;
    action(
        &controller,
        &discovery.lease,
        "foreign-class",
        WorkflowAction::Approach {
            approach: approach(&foreign_source, "injection"),
        },
    )?;
    let before = controller.status(campaign.id)?;
    let cell = before
        .workflow
        .as_ref()
        .unwrap()
        .cells
        .iter()
        .find(|cell| cell.task == discovery.lease.task_id)
        .unwrap();
    assert_eq!(cell.attack_class, "authentication");
    assert_eq!(before.workflow.as_ref().unwrap().families.len(), 1);
    assert!(controller
        .submit(&discovery.lease, "done", completed(&discovery.scope))
        .unwrap_err()
        .to_string()
        .contains("assigned attack class"));
    let rejected = controller.status(campaign.id)?;
    assert_eq!(rejected.accepted.len(), before.accepted.len());
    assert!(rejected
        .markdown()
        .contains("Baseline completed/planned: 0/12"));
    assert_eq!(
        rejected
            .tasks
            .iter()
            .find(|task| task.id == discovery.lease.task_id)
            .unwrap()
            .state,
        ExecutionState::Running
    );
    action(
        &controller,
        &discovery.lease,
        "assigned-class-cross-area",
        WorkflowAction::Approach {
            approach: approach(&foreign_source, "authentication"),
        },
    )?;
    controller.submit(&discovery.lease, "done", completed(&discovery.scope))?;
    settle(&controller, campaign.id, &mut runtime)?;
    let completed = controller.status(campaign.id)?;
    assert!(completed
        .markdown()
        .contains("Baseline completed/planned: 1/12"));
    assert_eq!(completed.workflow.as_ref().unwrap().families.len(), 2);
    assert_eq!(
        serde_json::to_value(&completed.accepted[..before.accepted.len()])?,
        serde_json::to_value(&before.accepted)?
    );
    Ok(())
}

#[test]
fn inventory_requires_every_delivered_page_and_survives_restart_and_replay() -> Result<()> {
    let (directory, manifest) = pinned_fixture(301)?;
    let clock = TestClock::new();
    let state = directory.0.join("state");
    let controller = open(&state, clock.clone(), 4)?;
    let campaign = controller.create(manifest)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = witness(&controller, &root.lease, 0)?;
    for after in [Some("zzzz".into()), Some("f299.txt".into()), None] {
        controller.list_source_files(
            &root.lease,
            SourceInventory {
                repository: "nac-test".into(),
                after,
                limit: 1,
            },
        )?;
        assert!(action(&controller, &root.lease, "map", map_action(&source))
            .unwrap_err()
            .to_string()
            .contains("complete contiguous inventory"));
    }
    drop(controller);
    let controller = open(&state, clock, 4)?;
    for after in ["f199.txt", "f099.txt", "f099.txt"] {
        controller.list_source_files(
            &root.lease,
            SourceInventory {
                repository: "nac-test".into(),
                after: Some(after.into()),
                limit: 100,
            },
        )?;
        assert!(
            !controller.status(campaign.id)?.workflow.unwrap().inventory["nac-test"].complete()
        );
    }
    assert!(
        action(&controller, &root.lease, "map", map_action(&source)).is_err(),
        "the skipped range cannot disappear behind a terminal cursor"
    );
    let gap = controller.list_source_files(
        &root.lease,
        SourceInventory {
            repository: "nac-test".into(),
            after: Some("f000.txt".into()),
            limit: 99,
        },
    )?;
    assert_eq!(gap.files.len(), 99);
    let complete = controller.status(campaign.id)?;
    let receipt = &complete.workflow.as_ref().unwrap().inventory["nac-test"];
    assert!(receipt.complete());
    assert!(!receipt.mapped());
    let accepted = action(&controller, &root.lease, "map", map_action(&source))?;
    assert_eq!(
        action(&controller, &root.lease, "map", map_action(&source))?.id,
        accepted.id
    );
    let status = controller.status(campaign.id)?;
    let workflow = status.workflow.unwrap();
    assert_eq!(workflow.cells.len(), 6);
    assert!(workflow.inventory["nac-test"].mapped());
    match &workflow.inventory["nac-test"] {
        InventoryReceipt::Enumeration(receipt) => {
            assert_eq!(receipt.total_files, 301);
            assert_eq!(receipt.delivered, vec![(0, 301)]);
            assert_eq!(receipt.commit, status.manifest.repositories[0].commit);
        }
        InventoryReceipt::LegacyHash(_) => {
            panic!("hash-only inventory is not complete enumeration")
        }
    }
    Ok(())
}

#[test]
fn material_unknowns_cannot_be_terminal_verdicts_but_inconclusive_can_resume() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(workflow_manifest(None)?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    map(&controller, &root.lease)?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &discovery.lease)?;
    let finding = Candidate {
        claim: "configuration-dependent read".into(),
        prerequisites: vec!["REQUIRED deployment configuration".into()],
        unresolved_assumptions: vec!["required configuration absent".into()],
        source: source.clone(),
    };
    let accepted = controller.submit(
        &discovery.lease,
        "candidate",
        Submission {
            schema_version: 1,
            payload: Payload::Candidate { candidate: finding },
            evidence: vec![EvidenceInput::Upload {
                bytes: b"source-controlled candidate receipt".to_vec(),
            }],
        },
    )?;
    let validator = dispatch(&controller, campaign.id, &mut runtime)?;
    let mut verdict = Validation {
        outcome: ValidationOutcome::Supported,
        prerequisites: "required configuration was not supplied".into(),
        reachability: "cannot determine without required configuration".into(),
        security_violation: "not established".into(),
        sources: vec![source.clone()],
        counterevidence: vec![source],
        unknowns: vec!["REQUIRED deployment configuration remains absent".into()],
        next_actions: vec!["supply the pinned deployment configuration".into()],
    };
    for (key, outcome) in [
        ("supported", ValidationOutcome::Supported),
        ("disproved", ValidationOutcome::Disproved),
    ] {
        verdict.outcome = outcome;
        assert!(action(
            &controller,
            &validator.lease,
            key,
            WorkflowAction::Validate {
                validation: verdict.clone()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("terminal validation cannot retain material unknowns"));
        assert!(!verdict.is_resolved());
    }
    verdict.outcome = ValidationOutcome::Inconclusive;
    action(
        &controller,
        &validator.lease,
        "inconclusive",
        WorkflowAction::Validate {
            validation: verdict,
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let unresolved = controller.status(campaign.id)?;
    assert!(unresolved.markdown().contains("Unresolved candidates: 1"));
    assert!(!unresolved.workflow.as_ref().unwrap().complete);
    let resumed = controller.resume(
        campaign.id,
        unresolved.revision,
        validator.lease.task_id,
        "The required configuration is still absent; preserve the blocker",
    )?;
    assert_eq!(
        resumed.workflow.unwrap().candidate_validators[&accepted.id],
        validator.lease.task_id
    );
    assert_eq!(resumed.accepted.len(), unresolved.accepted.len());
    let validator = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = super::source(&controller, &validator.lease)?;
    action(
        &controller,
        &validator.lease,
        "source-disproof",
        WorkflowAction::Validate {
            validation: Validation {
                outcome: ValidationOutcome::Disproved,
                prerequisites:
                    "source guard disproves this path independently of deployment configuration"
                        .into(),
                reachability: "guard executes before the proposed sink".into(),
                security_violation: "the claimed source path is disproved, not system safety"
                    .into(),
                sources: vec![source.clone()],
                counterevidence: vec![source],
                unknowns: vec![],
                next_actions: vec![],
            },
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let resolved = controller.status(campaign.id)?;
    assert!(resolved.markdown().contains("Unresolved candidates: 0"));
    assert_eq!(resolved.accepted.len(), unresolved.accepted.len() + 1);
    assert_eq!(
        serde_json::to_value(&resolved.accepted[..unresolved.accepted.len()])?,
        serde_json::to_value(&unresolved.accepted)?
    );

    let mut legacy = resolved;
    legacy.workflow.as_mut().unwrap().complete = true;
    if let Payload::Workflow {
        action: WorkflowAction::Validate { validation },
        ..
    } = &mut legacy.accepted.last_mut().unwrap().payload
    {
        validation.unknowns = vec!["required deployment configuration remains absent".into()];
    } else {
        panic!("expected the latest accepted validation");
    }
    let connection = rusqlite::Connection::open(directory.0.join("state/control.sqlite"))?;
    connection.execute(
        "UPDATE campaigns SET record=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&legacy)?, campaign.id.to_string()],
    )?;
    let loaded = controller.status(campaign.id)?;
    assert!(!loaded.workflow.as_ref().unwrap().complete);
    assert!(loaded.markdown().contains("Unresolved candidates: 1"));
    assert_eq!(loaded.revision, legacy.revision);
    assert_eq!(
        serde_json::to_value(&loaded.accepted)?,
        serde_json::to_value(&legacy.accepted)?
    );
    Ok(())
}

#[test]
fn genuinely_new_work_can_exceed_baseline_count_without_exceeding_four_actors() -> Result<()> {
    let (directory, manifest) = pinned_fixture(8)?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    inventory(&controller, &root.lease)?;
    let source = witness(&controller, &root.lease, 0)?;
    action(&controller, &root.lease, "map", map_action(&source))?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    for index in 0..7 {
        let source = witness(&controller, &discovery.lease, index)?;
        action(
            &controller,
            &discovery.lease,
            &format!("family-{index}"),
            WorkflowAction::Approach {
                approach: approach(&source, "authentication"),
            },
        )?;
        let status = controller.status(campaign.id)?;
        let family = status
            .workflow
            .unwrap()
            .families
            .values()
            .find(|family| family.history[0].mechanism.path == source.path)
            .unwrap()
            .id
            .clone();
        action(
            &controller,
            &discovery.lease,
            &format!("followup-{index}"),
            WorkflowAction::Followup {
                request: Followup {
                    area: "entry".into(),
                    attack_class: "authentication".into(),
                    family,
                    rationale: "new source-grounded mechanism".into(),
                    evidence: vec![source],
                },
            },
        )?;
    }
    let workflow = controller.status(campaign.id)?.workflow.unwrap();
    assert_eq!(
        workflow.cells.iter().filter(|cell| cell.baseline).count(),
        6
    );
    assert_eq!(
        workflow.cells.iter().filter(|cell| !cell.baseline).count(),
        7
    );
    for _ in 0..3 {
        dispatch(&controller, campaign.id, &mut runtime)?;
    }
    assert!(dispatch(&controller, campaign.id, &mut runtime)
        .unwrap_err()
        .to_string()
        .contains("concurrency reservation exhausted"));
    Ok(())
}

#[test]
fn source_questions_resolve_with_evidence_without_clearing_fixed_input_unknowns() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(workflow_manifest(None)?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &root.lease)?;
    action(
        &controller,
        &root.lease,
        "question",
        WorkflowAction::AskSource {
            question: SourceQuestion {
                key: "source-boundary".into(),
                question: "Which pinned declaration defines the source boundary?".into(),
                sources: vec![source.clone()],
            },
        },
    )?;
    assert!(controller
        .status(campaign.id)?
        .markdown()
        .contains("Unresolved source questions: 1"));
    let resolution = SourceResolution {
        key: "source-boundary".into(),
        answer: "The cited pinned declaration establishes this boundary".into(),
        sources: vec![source],
    };
    let accepted = action(
        &controller,
        &root.lease,
        "resolve-question",
        WorkflowAction::ResolveSource {
            resolution: resolution.clone(),
        },
    )?;
    assert_eq!(
        action(
            &controller,
            &root.lease,
            "resolve-question",
            WorkflowAction::ResolveSource {
                resolution: resolution.clone()
            }
        )?
        .id,
        accepted.id
    );
    assert!(action(
        &controller,
        &root.lease,
        "duplicate-resolution",
        WorkflowAction::ResolveSource { resolution }
    )
    .is_err());
    map(&controller, &root.lease)?;
    let status = controller.status(campaign.id)?;
    assert!(status.markdown().contains("Unresolved source questions: 0"));
    assert_eq!(
        status.workflow.as_ref().unwrap().unknowns,
        vec!["configuration absent"]
    );
    assert!(!status.workflow.as_ref().unwrap().complete);
    Ok(())
}
