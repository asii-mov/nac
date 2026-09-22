use super::*;
use nac_appsec::{
    Accepted, AssertionReviewReason, Candidate, Clock, Controller, EffectiveInputs,
    EvaluatorAssertion, EvidenceState, FindingRevision, GoAuthorizationRemediationProfile,
    Manifest, MonetaryPolicy, OracleClass, Payload, RecordRemediationObservation, RemediationCase,
    RemediationPhase, RemediationState, RemediationWorkerIdentity, Repository, ResearchEffort,
    ResearchJob, ResearchRole, SourceRef, SqliteRepository, StartRemediation, TargetIdentity,
    TokenPolicy, Validation, ValidationOutcome, WatchdogPolicy, Workflow, WorkflowAction,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn git(arguments: &[&str]) -> Result<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    ensure!(output.status.success(), "fixture Git lookup failed");
    Ok(output.stdout)
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "nac-remediation-generator-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct TestClock(std::sync::Arc<AtomicU64>);

impl TestClock {
    fn new() -> Self {
        Self(std::sync::Arc::new(AtomicU64::new(1000)))
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct FakeBackend {
    backend_identity: Vec<u8>,
    mount_identity: Vec<u8>,
}

impl FakeBackend {
    fn new(backend_identity: &str, mount_identity: &str) -> Self {
        Self {
            backend_identity: backend_identity.as_bytes().to_vec(),
            mount_identity: mount_identity.as_bytes().to_vec(),
        }
    }
}

impl ConfinedCodingBackend for FakeBackend {
    fn backend_identity(&self) -> &[u8] {
        &self.backend_identity
    }
    fn mount_identity(&self) -> &[u8] {
        &self.mount_identity
    }
    fn command(
        &self,
        _workspace: &Path,
        _program: &str,
        _args: &[String],
        _environment: &BTreeMap<String, String>,
    ) -> Result<tokio::process::Command> {
        Ok(tokio::process::Command::new("true"))
    }
}

/// A driver whose entire tool call sequence is fixed ahead of time: exactly
/// what "a scripted model" means for these tests. It never sees anything
/// beyond the facade-backed `GeneratorTools` surface.
struct ScriptedDriver {
    calls: Vec<(&'static str, serde_json::Value)>,
}

impl PatchGeneratorDriver for ScriptedDriver {
    fn drive(&mut self, tools: GeneratorTools, _prompt: String, _action: String) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            for (name, arguments) in &self.calls {
                tools.call(name, arguments.clone()).await?;
            }
            Ok::<_, anyhow::Error>(())
        })
    }
}

const PILOT_PATH: &str = "crates/nac-server/tests/fixtures/appsec-pilot/main.go";
const PILOT_ROOT: &str = "crates/nac-server/tests/fixtures/appsec-pilot";

fn manifest_fixture() -> Result<Manifest> {
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?
        .trim()
        .to_string();
    Ok(Manifest {
        schema_version: 1,
        remediation: None,
        experiments: None,
        research: None,
        repositories: vec![nac_appsec::RepositoryInput {
            identity: "nac-test".into(),
            checkout: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()?,
            commit,
        }],
        declared_inputs: BTreeMap::new(),
        monetary_policy: MonetaryPolicy::Uncapped,
        token_policy: TokenPolicy::ObserveOnly,
        watchdog: WatchdogPolicy {
            warn_after_ms: 10_000,
            stall_after_ms: 20_000,
            diagnostic_grace_ms: 5_000,
            lease_ms: 100_000,
            max_failed_recoveries: 3,
        },
        max_concurrency: 4,
        tasks: vec![],
    })
}

fn pilot_bytes(commit: &str) -> Result<Vec<u8>> {
    git(&["show", &format!("{commit}:{PILOT_PATH}")])
}

fn remediation_limits() -> RemediationLimits {
    RemediationLimits {
        operation_ms: 10_000,
        output_bytes: 1_000_000,
        max_files: 4,
        max_patch_bytes: 100_000,
    }
}

/// Computes the exact generator worker identity a real profile would need to
/// pin: it materializes a throwaway facade with the same policy, files, and
/// backend the adapter itself would use, then reads off its authority
/// receipt. This is the one place the test and the adapter share "the same
/// policy" the way a real deployment would.
fn generator_worker_identity(
    files: Vec<ControlledSourceFile>,
    editable_roots: &[String],
    required_production_path: &str,
    limits: &RemediationLimits,
    backend: &Arc<dyn ConfinedCodingBackend>,
) -> Result<RemediationWorkerIdentity> {
    let scratch = TestDirectory::new("identity-fixture")?;
    let policy = controlled_policy(editable_roots, required_production_path, limits);
    let facade =
        ControlledCodingFacade::materialize(&scratch.0, files, policy, Arc::clone(backend))?;
    let authority = facade.authority().clone();
    drop(facade);
    Ok(RemediationWorkerIdentity {
        model: "scripted-generator-model".into(),
        runtime: "controlled-coding-v1".into(),
        extractor: "go-remediation-v1".into(),
        prompt_sha256: "f".repeat(64),
        environment_sha256: authority.environment_sha256,
        tools_sha256: authority.tools_sha256,
        mounts_sha256: authority.mounts_sha256,
        backend_sha256: authority.backend_sha256,
        process_supervision_sha256: authority.process_supervision_sha256,
    })
}

fn seeded_campaign(
    seed: u128,
    backend: &Arc<dyn ConfinedCodingBackend>,
) -> Result<nac_appsec::Campaign> {
    let mut manifest = manifest_fixture()?;
    let commit = manifest.repositories[0].commit.clone();
    let package = SourcePackage::freeze(
        &manifest.repositories,
        &[("nac-test".into(), PILOT_PATH.into())],
        &[],
    )?;
    let original = pilot_bytes(&commit)?;
    let editable_roots = vec![PILOT_ROOT.to_string()];
    let limits = remediation_limits();
    let generator = generator_worker_identity(
        vec![ControlledSourceFile {
            path: PILOT_PATH.into(),
            bytes: original.clone(),
            mode: 0o644,
        }],
        &editable_roots,
        PILOT_PATH,
        &limits,
        backend,
    )?;
    let target = TargetIdentity {
        source_sha256: package.manifest_sha256.clone(),
        build_sha256: "5".repeat(64),
        image_sha256: "6".repeat(64),
        environment_sha256: "7".repeat(64),
    };
    let mut assertion = EvaluatorAssertion {
        version: "go-authz-v1".into(),
        assertion_sha256: String::new(),
        recipe_id: "go-authz".into(),
        recipe_sha256: "8".repeat(64),
        oracle_class: OracleClass::Authorization,
        oracle_sha256: "9".repeat(64),
        rubric_sha256: "a".repeat(64),
        fixture_sha256: "b".repeat(64),
        required_checks_sha256: "c".repeat(64),
        original_target: target,
    };
    assertion.assertion_sha256 = assertion.canonical_sha256()?;
    manifest.remediation = Some(GoAuthorizationRemediationProfile {
        schema_version: 1,
        repository: "nac-test".into(),
        base_commit: commit.clone(),
        source_package: package,
        dependencies: vec![],
        configuration_sha256: "d".repeat(64),
        skill_bundle_sha256: "e".repeat(64),
        editable_roots,
        generator,
        evaluator: RemediationWorkerIdentity {
            model: "evaluator-model".into(),
            runtime: "evaluator-runtime-v1".into(),
            extractor: "verdict-extractor-v1".into(),
            prompt_sha256: "1".repeat(64),
            environment_sha256: "2".repeat(64),
            tools_sha256: "3".repeat(64),
            mounts_sha256: "4".repeat(64),
            backend_sha256: "5".repeat(64),
            process_supervision_sha256: "6".repeat(64),
        },
        assertion,
        limits,
    });
    let candidate_id = uuid_id(seed + 1);
    let candidate_task = uuid_id(seed + 2);
    let candidate_attempt = uuid_id(seed + 3);
    let validation_id = uuid_id(seed + 4);
    let validation_task = uuid_id(seed + 5);
    let validation_attempt = uuid_id(seed + 6);
    let source = SourceRef {
        repository: "nac-test".into(),
        commit: commit.clone(),
        path: PILOT_PATH.into(),
        start_line: 1,
        end_line: 1,
        content_sha256: digest(&original),
    };
    let accepted = vec![
        Accepted {
            id: candidate_id,
            task_id: candidate_task,
            attempt_id: candidate_attempt,
            key: "candidate".into(),
            payload_hash: "3".repeat(64),
            accepted_ms: 10,
            payload: Payload::Candidate {
                candidate: Candidate {
                    claim: "an unauthenticated caller can read another owner's object".into(),
                    prerequisites: vec!["public HTTP access".into()],
                    unresolved_assumptions: vec![],
                    source,
                    experiments: vec![],
                },
            },
            evidence: vec![],
            evidence_state: Some(EvidenceState::Candidate),
            remediation_state: Some(RemediationState::NotStarted),
        },
        Accepted {
            id: validation_id,
            task_id: validation_task,
            attempt_id: validation_attempt,
            key: "validation".into(),
            payload_hash: "4".repeat(64),
            accepted_ms: 20,
            payload: Payload::Workflow {
                revision: 1,
                action: WorkflowAction::Validate {
                    validation: Validation {
                        outcome: ValidationOutcome::Supported,
                        prerequisites: "public HTTP access".into(),
                        reachability: "route is reachable".into(),
                        security_violation: "owner check is absent".into(),
                        sources: vec![],
                        counterevidence: vec![],
                        unknowns: vec![],
                        next_actions: vec![],
                        experiments: vec![],
                    },
                },
            },
            evidence: vec![],
            evidence_state: None,
            remediation_state: None,
        },
    ];
    let workflow = Workflow {
        root: candidate_task,
        scenario_sha256: "5".repeat(64),
        areas: vec![],
        unknowns: vec![],
        cells: vec![],
        inventory: BTreeMap::new(),
        jobs: BTreeMap::from([
            (
                candidate_task,
                ResearchJob {
                    role: ResearchRole::Discovery,
                    parent: None,
                    purpose: "fixture".into(),
                    round: 1,
                    cell: None,
                    candidate: None,
                    input: json!({}),
                    input_sha256: "6".repeat(64),
                    effective_inputs: BTreeMap::from([(
                        candidate_attempt,
                        effective_inputs("candidate"),
                    )]),
                },
            ),
            (
                validation_task,
                ResearchJob {
                    role: ResearchRole::Validation,
                    parent: Some(candidate_task),
                    purpose: "fixture".into(),
                    round: 1,
                    cell: None,
                    candidate: Some(candidate_id),
                    input: json!({}),
                    input_sha256: "7".repeat(64),
                    effective_inputs: BTreeMap::from([(
                        validation_attempt,
                        effective_inputs("validation"),
                    )]),
                },
            ),
        ]),
        families: BTreeMap::new(),
        candidate_validators: BTreeMap::from([(candidate_id, validation_task)]),
        candidate_fingerprints: BTreeMap::new(),
        rounds: vec![],
        effort: ResearchEffort::default(),
        complete: false,
    };
    let configuration_hash = digest(&serde_json::to_vec(&manifest)?);
    Ok(nac_appsec::Campaign {
        schema_version: 1,
        id: uuid_id(seed),
        revision: 0,
        created_ms: 1,
        updated_ms: 1,
        configuration_hash,
        manifest,
        cancelled: false,
        dispatch_blocker: None,
        tasks: vec![],
        accepted,
        pending_submissions: vec![],
        experiments: vec![],
        workflow: Some(workflow),
        remediations: vec![],
    })
}

fn uuid_id(value: u128) -> Id {
    use std::str::FromStr;
    Id::from_str(&uuid::Uuid::from_u128(value).to_string()).unwrap()
}

fn effective_inputs(label: &str) -> EffectiveInputs {
    EffectiveInputs {
        model: format!("model-{label}"),
        backend: "confined".into(),
        reasoning: Some("high".into()),
        runtime: "runtime-v1".into(),
        extractor: "extractor-v1".into(),
        prompt_sha256: "1".repeat(64),
        context_sha256: "2".repeat(64),
        session_id: format!("session-{label}"),
        thread_name: format!("thread-{label}"),
        dispatch_id: format!("dispatch-{label}"),
        action_sha256: "3".repeat(64),
        messages_sha256: "4".repeat(64),
    }
}

fn request(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &nac_appsec::Campaign,
) -> Result<RemediationCase> {
    let provenance = controller.remediation_provenance(campaign.id, campaign.accepted[0].id)?;
    controller.request_remediation(
        campaign.id,
        controller.status(campaign.id)?.revision,
        StartRemediation {
            schema_version: 1,
            key: "fix-authz".into(),
            assertion_review: Some(nac_appsec::AssertionReview {
                reason: AssertionReviewReason::StaticSupported,
                candidate_id: provenance.finding.candidate_id,
                validation_id: provenance.finding.validation_id,
                assertion_version: provenance.assertion.version.clone(),
                assertion_sha256: provenance.assertion.assertion_sha256.clone(),
                reviewer: "operator".into(),
                reviewed_ms: 100,
            }),
            provenance,
        },
    )
}

fn minimal_public_finding() -> PublicFinding {
    PublicFinding {
        revision: FindingRevision {
            candidate_id: uuid_id(9001),
            candidate_payload_sha256: "1".repeat(64),
            validation_id: uuid_id(9002),
            validation_payload_sha256: "2".repeat(64),
            workflow_decision_revision: 1,
        },
        claim: "an unauthenticated caller can read another owner's object".into(),
        prerequisites: vec!["public HTTP access".into()],
        source: SourceRef {
            repository: "nac-test".into(),
            commit: "0".repeat(40),
            path: PILOT_PATH.into(),
            start_line: 1,
            end_line: 1,
            content_sha256: "3".repeat(64),
        },
        evidence: vec![],
        validation_evidence: vec![],
    }
}

#[test]
fn patch_capture_produces_core_accepted_submission() -> Result<()> {
    let directory = TestDirectory::new("core-accepted")?;
    let state = directory.0.join("state");
    let backend: Arc<dyn ConfinedCodingBackend> =
        Arc::new(FakeBackend::new("backend-a", "mount-a"));
    let campaign = seeded_campaign(1, &backend)?;
    let repository = SqliteRepository::open_with_resource_capacity(&state, 4, 1, 1)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&state)?, TestClock::new());
    let case = request(&controller, &campaign)?;
    let revision = controller.status(campaign.id)?.revision;
    let desired = controller
        .desired_remediation_effect(campaign.id, case.id, revision)?
        .context("expected a pending generate-patch effect")?;
    assert!(!desired.stop);
    assert_eq!(desired.fence.phase, RemediationPhase::GeneratePatch);

    let original = pilot_bytes(&campaign.manifest.repositories[0].commit)?;
    let mut replacement = original.clone();
    replacement.extend_from_slice(b"\n// remediation pilot test edit\n");
    let mut generator = RemediationPatchGenerator::new(
        &state,
        campaign.manifest.repositories.clone(),
        Arc::clone(&backend),
        ScriptedDriver {
            calls: vec![(
                "replace_source",
                json!({
                    "path": PILOT_PATH,
                    "expected_sha256": digest(&original),
                    "content": String::from_utf8(replacement)?,
                }),
            )],
        },
    )?;
    let output = generator.reconcile_patch(&desired)?;
    let RemediationEffectOutput::PatchProposed { .. } = &output else {
        anyhow::bail!("expected a proposed patch, got {output:?}")
    };

    let case = controller.record_remediation_observation(
        campaign.id,
        case.id,
        RecordRemediationObservation {
            schema_version: 1,
            key: "generator-result".into(),
            fence: desired.fence,
            output,
        },
    )?;
    assert_eq!(case.patches.len(), 1);
    assert_eq!(case.patches[0].proposal.replacements.len(), 1);
    assert_eq!(case.patches[0].proposal.replacements[0].path, PILOT_PATH);
    Ok(())
}

#[tokio::test]
async fn out_of_policy_edit_is_rejected_before_submission() -> Result<()> {
    let owner = TestDirectory::new("out-of-policy")?;
    let files = vec![ControlledSourceFile {
        path: PILOT_PATH.into(),
        bytes: b"package main\n".to_vec(),
        mode: 0o644,
    }];
    let policy = controlled_policy(&[PILOT_ROOT.to_string()], PILOT_PATH, &remediation_limits());
    let facade = ControlledCodingFacade::materialize(
        &owner.0,
        files,
        policy,
        Arc::new(FakeBackend::new("backend-a", "mount-a")),
    )?;
    let tools = GeneratorTools {
        facade: Arc::new(tokio::sync::Mutex::new(facade)),
    };

    let error = tools
        .call(
            "replace_source",
            json!({
                "path": "crates/nac-server/tests/fixtures/other/evil.go",
                "expected_sha256": null,
                "content": "package other\n",
            }),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("outside editable roots"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn stop_yields_settled_cleanup_receipt() -> Result<()> {
    let source_package = SourcePackage {
        schema_version: 1,
        files: vec![],
        manifest_sha256: "f".repeat(64),
    };
    let finding = minimal_public_finding();
    let plan = RemediationEffectPlan::GeneratePatch {
        finding,
        source_package: source_package.clone(),
        dependencies: vec![],
        editable_roots: vec![PILOT_ROOT.to_string()],
        worker: RemediationWorkerIdentity {
            model: "generator-model".into(),
            runtime: "controlled-coding-v1".into(),
            extractor: "go-remediation-v1".into(),
            prompt_sha256: "f".repeat(64),
            environment_sha256: "0".repeat(64),
            tools_sha256: "1".repeat(64),
            mounts_sha256: "2".repeat(64),
            backend_sha256: "3".repeat(64),
            process_supervision_sha256: "4".repeat(64),
        },
        limits: remediation_limits(),
    };
    let fence = EffectFence {
        effect_id: uuid_id(9003),
        generation: 1,
        phase: RemediationPhase::GeneratePatch,
        plan_sha256: "0".repeat(64),
        patch_sha256: None,
    };
    let desired = RemediationDesiredEffect {
        remediation_id: uuid_id(9004),
        fence,
        stop: true,
        plan,
    };

    let directory = TestDirectory::new("stop-cleanup")?;
    let mut generator = RemediationPatchGenerator::new(
        &directory.0.join("state"),
        vec![],
        Arc::new(FakeBackend::new("backend-a", "mount-a")),
        ScriptedDriver { calls: vec![] },
    )?;
    let output = generator.reconcile_patch(&desired)?;
    let RemediationEffectOutput::CleanupSettled { receipt } = output else {
        anyhow::bail!("expected a settled cleanup receipt")
    };
    assert_eq!(receipt.workspace_sha256, source_package.manifest_sha256);
    assert!(receipt.delayed_launches_settled);
    assert!(receipt.descendants_terminated);
    assert!(receipt.target_sha256.is_none());
    Ok(())
}

#[test]
fn generator_prompt_and_action_omit_evaluator_and_assertion_data() {
    let finding = minimal_public_finding();
    let prompt = build_prompt(&finding, &[PILOT_ROOT.to_string()]);
    let action = build_action(&finding);
    for forbidden in [
        "assertion",
        "oracle",
        "evaluator",
        "rubric",
        "fixture_sha256",
        "required_checks",
    ] {
        assert!(
            !prompt.to_lowercase().contains(forbidden),
            "prompt leaked evaluator vocabulary: {forbidden}"
        );
        assert!(
            !action.to_lowercase().contains(forbidden),
            "action leaked evaluator vocabulary: {forbidden}"
        );
    }
}
