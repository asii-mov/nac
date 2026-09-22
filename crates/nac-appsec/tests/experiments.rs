#[allow(
    dead_code,
    reason = "shared integration support exposes a broader fixture API"
)]
mod support;

use nac_appsec::*;
use std::{collections::BTreeMap, path::Path};
use support::*;

fn profile() -> Result<Manifest> {
    profile_for("discovery")
}

fn profile_for(stage: &str) -> Result<Manifest> {
    let mut input = manifest(1)?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/appsec")
        .canonicalize()?;
    input.research = Some(FrozenResearch::resolve(
        &root,
        ResearchBrief {
            schema_version: 1,
            assurance: Assurance::OpenEnded,
            source_root: "main/".into(),
            attacker_model: "locally authored pilot attacker".into(),
            deployment_profile: "deterministic test-only adapter".into(),
            impact_goal: "test-only unauthorized delivery".into(),
            success_property: "trusted evaluator observes forbidden delivery".into(),
            minimum_active_research_ms: None,
            max_investigative_agents: 4,
        },
        BTreeMap::from([("cell-0".into(), stage.into())]),
    )?);
    input
        .research
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("frozen research missing"))?
        .enable_controlled_experiments()?;
    let package = SourcePackage::freeze(
        &input.repositories,
        &[("nac-test".into(), "Cargo.toml".into())],
        &[],
    )?;
    let production = SourcePackage::freeze(
        &input.repositories,
        &[("nac-test".into(), "Cargo.toml".into())],
        &[],
    )?;
    let target = TargetIdentity {
        source_sha256: production.manifest_sha256.clone(),
        build_sha256: "c".repeat(64),
        image_sha256: "d".repeat(64),
        environment_sha256: "e".repeat(64),
    };
    let mut recipe = RecipeBinding {
        id: "local-test-only-authz".into(),
        recipe_sha256: String::new(),
        target,
        scope: TargetScope::OriginalTarget,
        oracle_class: OracleClass::Authorization,
        interface: HttpInterface {
            max_requests: 4,
            routes: vec![HttpRoute {
                actor: "attacker".into(),
                method: HttpMethod::Get,
                path_prefix: "/object".into(),
                max_body_bytes: 0,
            }],
        },
        production,
        repetitions: 1,
        operation_ms: 1000,
        capture_bytes: 4096,
    };
    recipe.recipe_sha256 = recipe.canonical_sha256()?;
    input.experiments = Some(ExperimentProfile {
        schema_version: 1,
        package,
        dependencies: vec![],
        recipes: vec![recipe],
    });
    Ok(input)
}

fn plan(input: &Manifest) -> Result<ExperimentPlan> {
    let Payload::Candidate { candidate } = candidate(input)?.payload else {
        unreachable!()
    };
    Ok(ExperimentPlan {
        schema_version: 1,
        key: "before-candidate".into(),
        recipe_id: "local-test-only-authz".into(),
        hypothesis: "locally authored lifecycle fixture, not external evaluation".into(),
        sources: vec![candidate.source],
        requests: vec![HttpRequest {
            actor: "attacker".into(),
            method: HttpMethod::Get,
            path: "/object/owner".into(),
            body: String::new(),
        }],
    })
}

fn configured(
    path: &Path,
    clock: TestClock,
    targets: u32,
) -> Result<Controller<SqliteRepository, TestClock>> {
    Ok(Controller::new(
        SqliteRepository::open_with_target_capacity(path, 1, targets)?,
        ArtifactStore::open(path)?,
        clock,
    ))
}

struct FixtureRunner {
    observations: Vec<ExperimentDesired>,
    uncertain: bool,
}

impl ExperimentRunner for FixtureRunner {
    fn reconcile(
        &mut self,
        desired: &ExperimentDesired,
    ) -> std::result::Result<RunnerObservation, ExperimentCode> {
        self.observations.push(desired.clone());
        if self.uncertain {
            return Err(ExperimentCode::DeliveryUncertain);
        }
        use ExperimentPhase::*;
        let next = if desired.stop {
            Cleaned
        } else {
            match desired.phase {
                Reserved => PendingCreate,
                PendingCreate => PendingStart,
                PendingStart => Ready,
                Ready => PendingRequest,
                PendingRequest => Captured,
                Captured => Assessed,
                Assessed => CleanupPending,
                CleanupPending | Cleaned => Cleaned,
            }
        };
        Ok(RunnerObservation {
            run_key: desired.run_key,
            phase: next,
            code: ExperimentCode::Pending,
            effective_target: Some(desired.recipe.target.clone()),
            execution_receipt: (next == Assessed).then(|| ExecutionReceipt {
                adapter_version: "nac-appsec-target-v2".into(),
                broker_sha256: "a".repeat(64),
                evaluator_sha256: "b".repeat(64),
                source_manifest_sha256: desired.recipe.target.source_sha256.clone(),
                build_sha256: desired.recipe.target.build_sha256.clone(),
                image_sha256: desired.recipe.target.image_sha256.clone(),
                environment_sha256: desired.recipe.target.environment_sha256.clone(),
                launch_sha256: "c".repeat(64),
                mount_sha256: "d".repeat(64),
                network_sha256: "e".repeat(64),
                log_sha256: "f".repeat(64),
                resource_sha256: "0".repeat(64),
                request_plan_sha256: desired.plan_sha256.clone(),
            }),
            evaluation: (next == Assessed).then(|| {
                EvaluatorVerdict(ExperimentVerdict {
                    assessment: Assessment::Confirmed,
                    controls: desired
                        .recipe
                        .oracle_class
                        .required_controls()
                        .iter()
                        .map(|control| ControlResult {
                            control: *control,
                            passed: true,
                        })
                        .collect(),
                    diagnostics: vec![],
                })
            }),
        })
    }
}

#[test]
fn discovery_before_candidate_uses_frozen_recipe_and_task_scoped_idempotency() -> Result<()> {
    let directory = Directory::new()?;
    let control = configured(&directory.0.join("state"), TestClock::new(), 1)?;
    let input = profile()?;
    let request = plan(&input)?;
    let run = control.create(input)?;
    let mut worker = Worker::default();
    let assignment = control.dispatch_next(run.id, 0, &mut worker)?.unwrap();
    let experiment = control.run_experiment(&assignment.lease, request.clone())?;
    assert!(control.status(run.id)?.accepted.is_empty());
    assert_eq!(
        control
            .run_experiment(&assignment.lease, request.clone())?
            .id,
        experiment.id
    );
    let mut changed = request;
    changed.hypothesis.push('x');
    assert!(control.run_experiment(&assignment.lease, changed).is_err());
    let mut runner = FixtureRunner {
        observations: vec![],
        uncertain: false,
    };
    for _ in 0..7 {
        control.reconcile_experiments(run.id, &mut runner)?;
    }
    let result = control.read_experiment(&assignment.lease, experiment.id)?;
    assert_eq!(result.trials[0].phase, ExperimentPhase::Cleaned);
    assert_eq!(
        result.trials[0].verdict.as_ref().unwrap().assessment,
        Assessment::Confirmed
    );
    let reset = control.reset_experiment(&assignment.lease, experiment.id)?;
    assert_ne!(reset.trials[0].run_key, reset.trials[1].run_key);
    assert_eq!(reset.trials[1].epoch, 1);
    Ok(())
}

#[test]
fn fresh_validation_task_uses_the_same_controller_operations_with_a_distinct_target() -> Result<()>
{
    let directory = Directory::new()?;
    let control = configured(&directory.0.join("state"), TestClock::new(), 2)?;
    let input = profile_for("validation")?;
    let request = plan(&input)?;
    let run = control.create(input)?;
    let assignment = control
        .dispatch_next(run.id, 0, &mut Worker::default())?
        .unwrap();
    assert!(assignment.experiment_tools);
    assert!(assignment.research.as_ref().is_some_and(|research| research
        .prompt
        .contains("Controlled HTTP experiments 1.0.0")
        && research
            .prompt
            .contains("frozen controlled-experiment profile")));
    let experiment = control.run_experiment(&assignment.lease, request)?;
    assert_eq!(experiment.task_id, assignment.lease.task_id);
    assert_eq!(experiment.attempt_id, assignment.lease.attempt_id);
    assert_ne!(experiment.trials[0].run_key, assignment.lease.attempt_id);
    assert!(control.status(run.id)?.accepted.is_empty());
    Ok(())
}

#[test]
fn uncertain_create_outlives_investigator_and_holds_both_capacity_reservations() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let clock = TestClock::new();
    let control = configured(&path, clock.clone(), 1)?;
    let input = profile()?;
    let request = plan(&input)?;
    let run = control.create(input.clone())?;
    let other = control.create(input)?;
    let mut worker = Worker::default();
    let assignment = control.dispatch_next(run.id, 0, &mut worker)?.unwrap();
    let experiment = control.run_experiment(&assignment.lease, request)?;
    let mut runner = FixtureRunner {
        observations: vec![],
        uncertain: true,
    };
    control.reconcile_experiments(run.id, &mut runner)?;
    worker.terminated.insert(assignment.lease.attempt_id, true);
    let state = control.reconcile(run.id, &mut worker)?;
    assert!(!state.tasks[0].attempts[0].runtime_slot_held);
    assert_eq!(state.occupied_attempts(), 1);
    assert_eq!(state.occupied_targets(), 1);
    assert_eq!(
        state.experiments[0].trials[0].phase,
        ExperimentPhase::CleanupPending
    );
    assert!(control.dispatch_next(other.id, 0, &mut worker).is_err());
    let reopened = configured(&path, clock, 1)?;
    let state = reopened.reconcile_experiments(run.id, &mut runner)?;
    assert_eq!(state.occupied_attempts(), 1);
    assert_eq!(state.occupied_targets(), 1);
    assert_eq!(state.experiments[0].id, experiment.id);
    runner.uncertain = false;
    let state = reopened.reconcile_experiments(run.id, &mut runner)?;
    assert_eq!(state.occupied_attempts(), 0);
    assert_eq!(state.occupied_targets(), 0);
    assert!(reopened.dispatch_next(other.id, 0, &mut worker)?.is_some());
    assert!(!path.join("control.sqlite-wal").exists());
    Ok(())
}

#[test]
fn persistent_adapter_failure_requires_explicit_recovery_and_retains_target() -> Result<()> {
    let directory = Directory::new()?;
    let clock = TestClock::new();
    let control = configured(&directory.0.join("state"), clock, 1)?;
    let input = profile()?;
    let request = plan(&input)?;
    let run = control.create(input)?;
    let assignment = control
        .dispatch_next(run.id, 0, &mut Worker::default())?
        .unwrap();
    let experiment = control.run_experiment(&assignment.lease, request)?;
    let mut runner = FixtureRunner {
        observations: vec![],
        uncertain: true,
    };
    for _ in 0..8 {
        control.reconcile_experiments(run.id, &mut runner)?;
    }
    let blocked = control.read_experiment(&assignment.lease, experiment.id)?;
    assert!(blocked.trials[0].operator_recovery_required);
    assert_eq!(blocked.trials[0].consecutive_recovery_attempts, 3);
    assert_eq!(control.status(run.id)?.occupied_targets(), 1);
    let reopened = configured(&directory.0.join("state"), TestClock::new(), 1)?;
    reopened.recover_experiment(&assignment.lease, experiment.id)?;
    let reset = reopened.read_experiment(&assignment.lease, experiment.id)?;
    assert!(!reset.trials[0].operator_recovery_required);
    runner.uncertain = false;
    for _ in 0..8 {
        reopened.reconcile_experiments(run.id, &mut runner)?;
    }
    assert_eq!(
        reopened
            .read_experiment(&assignment.lease, experiment.id)?
            .trials[0]
            .phase,
        ExperimentPhase::Cleaned
    );
    Ok(())
}

#[test]
fn recipe_digest_binds_public_interface_and_limits() -> Result<()> {
    let input = profile()?;
    let recipe = &input.experiments.as_ref().unwrap().recipes[0];
    let original = recipe.recipe_sha256.clone();
    let mut changed = recipe.clone();
    changed.interface.max_requests += 1;
    assert_ne!(changed.canonical_sha256()?, original);
    changed.recipe_sha256 = original;
    let mut invalid = input;
    invalid.experiments.as_mut().unwrap().recipes[0] = changed;
    let directory = Directory::new()?;
    assert!(Controller::new(
        SqliteRepository::open(&directory.0.join("state"), 1)?,
        ArtifactStore::open(&directory.0.join("artifacts"))?,
        TestClock::new()
    )
    .create(invalid)
    .is_err());
    Ok(())
}

#[test]
fn package_membership_filters_inventory_reads_and_candidate_validation() -> Result<()> {
    let directory = Directory::new()?;
    let control = configured(&directory.0.join("state"), TestClock::new(), 1)?;
    let input = profile()?;
    let run = control.create(input.clone())?;
    let assignment = control
        .dispatch_next(run.id, 0, &mut Worker::default())?
        .unwrap();
    let files = control.list_source_files(
        &assignment.lease,
        SourceInventory {
            repository: "nac-test".into(),
            after: None,
            limit: 256,
        },
    )?;
    assert_eq!(files.files, ["Cargo.toml"]);
    assert!(control
        .read_source(
            &assignment.lease,
            SourceRead {
                repository: "nac-test".into(),
                path: "AGENTS.md".into(),
                start_line: 1,
                end_line: 1
            }
        )
        .is_err());
    let mut forged = candidate(&input)?;
    if let Payload::Candidate { candidate } = &mut forged.payload {
        candidate.source.path = "AGENTS.md".into();
    }
    assert!(control
        .submit(&assignment.lease, "outside", forged)
        .is_err());
    let package = &input.experiments.as_ref().unwrap().package;
    let export = directory.0.join("export");
    package.export(&input.repositories, &export)?;
    assert!(export.join("main/nac-test/Cargo.toml").is_file());
    assert!(!export.join("main/nac-test/.git").exists());
    assert!(!export.join("main/nac-test/AGENTS.md").exists());
    assert!(package.export(&input.repositories, &export).is_err());
    assert!(SourcePackage::freeze(
        &input.repositories,
        &[("nac-test".into(), ".git/config".into())],
        &[]
    )
    .is_err());
    assert!(SourcePackage::freeze(
        &input.repositories,
        &[(
            "nac-test".into(),
            "crates/nac-appsec/tests/controller.rs".into()
        )],
        &[]
    )
    .is_ok());
    assert!(SourcePackage::freeze(
        &input.repositories,
        &[(
            "nac-test".into(),
            "crates/nac-appsec/tests/controller.rs".into()
        )],
        &[(
            "nac-test".into(),
            "crates/nac-appsec/tests/controller.rs".into()
        )]
    )
    .is_err());
    assert!(SourcePackage::freeze(
        &input.repositories,
        &[("nac-test".into(), "Cargo.toml".into())],
        &[("nac-test".into(), "Cargo.toml".into())]
    )
    .is_err());
    Ok(())
}

#[test]
fn model_plan_cannot_deserialize_runner_evaluator_or_backend_authority() -> Result<()> {
    let plan = plan(&profile()?)?;
    for field in [
        "lease",
        "role",
        "engine",
        "host",
        "oracle",
        "secret",
        "evaluation",
        "run_key",
    ] {
        let mut value = serde_json::to_value(&plan)?;
        value[field] = serde_json::json!("forged");
        assert!(
            serde_json::from_value::<ExperimentPlan>(value).is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn accepted_experiment_evidence_is_claim_bound_and_cannot_be_reset() -> Result<()> {
    let directory = Directory::new()?;
    let control = configured(&directory.0.join("state"), TestClock::new(), 1)?;
    let input = profile()?;
    let mut submission = candidate(&input)?;
    let Payload::Candidate { candidate } = &submission.payload else {
        unreachable!()
    };
    let mut request = plan(&input)?;
    request.hypothesis = candidate.claim.clone();
    let run = control.create(input)?;
    let assignment = control
        .dispatch_next(run.id, 0, &mut Worker::default())?
        .unwrap();
    let experiment = control.run_experiment(&assignment.lease, request)?;
    let mut runner = FixtureRunner {
        observations: vec![],
        uncertain: false,
    };
    for _ in 0..7 {
        control.reconcile_experiments(run.id, &mut runner)?;
    }
    if let Payload::Candidate { candidate } = &mut submission.payload {
        candidate.experiments = vec![experiment.id];
        candidate.claim = "unrelated changed claim".into();
    }
    assert!(control
        .submit(&assignment.lease, "mismatched-link", submission.clone())
        .is_err());
    if let Payload::Candidate { candidate } = &mut submission.payload {
        candidate.claim = experiment.plan.hypothesis.clone();
    }
    control.submit(&assignment.lease, "matched-link", submission)?;
    assert!(control
        .reset_experiment(&assignment.lease, experiment.id)
        .is_err());
    assert!(control
        .cancel_experiment(&assignment.lease, experiment.id)
        .is_err());
    Ok(())
}

#[test]
fn campaign_rejects_credential_bearing_dependency_provenance_before_prompting() -> Result<()> {
    let directory = Directory::new()?;
    let mut input = profile()?;
    input.experiments.as_mut().unwrap().dependencies = vec![PrefetchedDependency {
        schema_version: 1,
        package: "fixture".into(),
        version: "1.0.0".into(),
        source_url: "https://user:secret@example.invalid/source.tar".into(),
        source_ref: "fixture-v1".into(),
        archive_sha256: "a".repeat(64),
    }];
    let control = configured(&directory.0.join("state"), TestClock::new(), 1)?;
    assert!(control.create(input).is_err());
    Ok(())
}
