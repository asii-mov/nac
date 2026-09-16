use super::*;

#[test]
fn distinct_allegations_on_the_same_source_line_each_get_one_validator() -> Result<()> {
    let directory = Directory::new()?;
    let checkout = directory.0.join("source");
    std::fs::create_dir(&checkout)?;
    std::fs::write(
        checkout.join("dual.py"),
        "def handle(path, query, db): return open(path).read(), db.execute(query).fetchall()\n",
    )?;
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec!["commit", "-qm", "same-line independent allegations"],
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
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    controller.list_source_files(
        &root.lease,
        SourceInventory {
            repository: "nac-test".into(),
            after: None,
            limit: 1,
        },
    )?;
    let source = controller
        .read_source(
            &root.lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "dual.py".into(),
                start_line: 1,
                end_line: 1,
            },
        )?
        .source;
    action(
        &controller,
        &root.lease,
        "map",
        WorkflowAction::Map {
            areas: vec![Area {
                key: "handler".into(),
                description: "attacker-facing file and database handler".into(),
                sources: vec![source.clone()],
                trust_boundaries: vec!["request arguments to file and SQL operations".into()],
                unknowns: vec![],
                applicability: vec![],
            }],
            unknowns: vec![],
        },
    )?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let file_claim = Candidate {
        claim: "An attacker-controlled path permits reading arbitrary files".into(),
        prerequisites: vec!["attacker controls handler arguments".into()],
        unresolved_assumptions: vec!["caller argument validation is unknown".into()],
        source,
        experiments: vec![],
    };
    let submission = |candidate: Candidate| Submission {
        schema_version: 1,
        payload: Payload::Candidate { candidate },
        evidence: vec![EvidenceInput::Upload {
            bytes: b"pinned handler source receipt".to_vec(),
        }],
    };
    let file = controller.submit(
        &discovery.lease,
        "file-read",
        submission(file_claim.clone()),
    )?;
    assert_eq!(
        controller
            .submit(
                &discovery.lease,
                "file-read",
                submission(file_claim.clone())
            )?
            .id,
        file.id
    );
    assert!(controller
        .submit(
            &discovery.lease,
            "exact-repeat",
            submission(file_claim.clone())
        )
        .is_err());
    let mut sql_claim = file_claim;
    sql_claim.claim =
        "An attacker-controlled SQL query permits unauthorized database operations".into();
    let sql = controller.submit(
        &discovery.lease,
        "sql-injection",
        submission(sql_claim.clone()),
    )?;
    assert_ne!(sql.id, file.id);
    assert_eq!(
        controller
            .submit(
                &discovery.lease,
                "sql-injection",
                submission(sql_claim.clone())
            )?
            .id,
        sql.id
    );
    assert!(controller
        .submit(&discovery.lease, "sql-repeat", submission(sql_claim))
        .is_err());
    let workflow = controller.status(campaign.id)?.workflow.unwrap();
    assert_eq!(workflow.candidate_validators.len(), 2);
    let file_validator = workflow.candidate_validators[&file.id];
    let sql_validator = workflow.candidate_validators[&sql.id];
    assert_ne!(file_validator, sql_validator);
    assert_ne!(
        workflow.jobs[&file_validator].input_sha256,
        workflow.jobs[&sql_validator].input_sha256
    );
    Ok(())
}

#[test]
fn settled_followup_can_reopen_only_for_a_new_source_grounded_exploration() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(workflow_manifest(None)?)?;
    let mut runtime = Worker::default();
    let root = dispatch(&controller, campaign.id, &mut runtime)?;
    map(&controller, &root.lease)?;
    settle(&controller, campaign.id, &mut runtime)?;
    let discovery = dispatch(&controller, campaign.id, &mut runtime)?;
    let source = source(&controller, &discovery.lease)?;
    let mut approach = approach(&source, "authentication");
    action(
        &controller,
        &discovery.lease,
        "register",
        WorkflowAction::Approach {
            approach: approach.clone(),
        },
    )?;
    let family = controller
        .status(campaign.id)?
        .workflow
        .unwrap()
        .families
        .keys()
        .next()
        .unwrap()
        .clone();
    let mut request = Followup {
        area: "boundary".into(),
        attack_class: "authentication".into(),
        family,
        rationale: "trace the first source-backed route".into(),
        evidence: vec![source],
    };
    action(
        &controller,
        &discovery.lease,
        "first-followup",
        WorkflowAction::Followup {
            request: request.clone(),
        },
    )?;
    let first_id = controller
        .status(campaign.id)?
        .workflow
        .unwrap()
        .cells
        .iter()
        .find(|cell| !cell.baseline)
        .unwrap()
        .task;
    loop {
        let worker = dispatch(&controller, campaign.id, &mut runtime)?;
        controller.submit(
            &worker.lease,
            "blocked",
            Submission {
                schema_version: 1,
                payload: Payload::StageResult {
                    result: StageResult::Blocked {
                        reason: "route needs a new source witness".into(),
                    },
                },
                evidence: vec![],
            },
        )?;
        settle(&controller, campaign.id, &mut runtime)?;
        if worker.lease.task_id == first_id {
            break;
        }
    }
    approach.status = FamilyStatus::Blocked;
    approach.rationale = "first route settled without its prerequisite".into();
    action(
        &controller,
        &discovery.lease,
        "block-family",
        WorkflowAction::Approach {
            approach: approach.clone(),
        },
    )?;
    approach.status = FamilyStatus::Exploring;
    approach.idea = "a renamed version of the same route".into();
    approach.rationale = "different wording without new evidence".into();
    assert!(action(
        &controller,
        &discovery.lease,
        "cosmetic-reopen",
        WorkflowAction::Approach {
            approach: approach.clone()
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
    approach.evidence = vec![new_source.clone()];
    approach.rationale = "new cited lines establish a different mechanism route".into();
    let reopened = action(
        &controller,
        &discovery.lease,
        "novel-reopen",
        WorkflowAction::Approach {
            approach: approach.clone(),
        },
    )?;
    request.evidence = vec![new_source];
    request.rationale = "investigate the newly evidenced route".into();
    action(
        &controller,
        &discovery.lease,
        "second-followup",
        WorkflowAction::Followup {
            request: request.clone(),
        },
    )?;
    let status = controller.status(campaign.id)?;
    let workflow = status.workflow.as_ref().unwrap();
    let additional: Vec<_> = workflow
        .cells
        .iter()
        .filter(|cell| !cell.baseline)
        .collect();
    assert_eq!(additional.len(), 2);
    assert_ne!(additional[0].id, additional[1].id);
    assert_eq!(
        workflow.jobs[&additional[1].task].input["exploration_id"],
        serde_json::to_value(reopened.id)?
    );
    assert_eq!(
        status
            .tasks
            .iter()
            .find(|task| task.id == first_id)
            .unwrap()
            .state,
        ExecutionState::Blocked
    );
    request.rationale = "another title for the same approved exploration".into();
    assert!(action(
        &controller,
        &discovery.lease,
        "reworded-duplicate",
        WorkflowAction::Followup { request }
    )
    .is_err());
    let already_covered = controller
        .read_source(
            &discovery.lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "Cargo.toml".into(),
                start_line: 1,
                end_line: 5,
            },
        )?
        .source;
    approach.evidence = vec![already_covered];
    approach.rationale = "larger citation adds no previously uncovered lines".into();
    assert!(action(
        &controller,
        &discovery.lease,
        "no-novel-lines",
        WorkflowAction::Approach { approach }
    )
    .is_err());
    assert_eq!(
        controller
            .status(campaign.id)?
            .workflow
            .unwrap()
            .cells
            .iter()
            .filter(|cell| !cell.baseline)
            .count(),
        2
    );
    Ok(())
}
