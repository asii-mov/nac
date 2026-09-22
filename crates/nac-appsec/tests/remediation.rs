#![allow(
    clippy::missing_assert_message,
    clippy::unwrap_used,
    reason = "integration fixtures use trusted constructed values"
)]

#[allow(
    dead_code,
    reason = "shared integration support exposes a broader fixture API"
)]
mod support;

use nac_appsec::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, str::FromStr};
use support::*;

fn id(value: u128) -> Id {
    Id::from_str(&uuid::Uuid::from_u128(value).to_string()).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn inputs(label: &str) -> EffectiveInputs {
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

fn authority(
    worker: &RemediationWorkerIdentity,
    workspace_sha256: &str,
) -> RemediationAuthorityReceipt {
    RemediationAuthorityReceipt {
        tools_sha256: worker.tools_sha256.clone(),
        mounts_sha256: worker.mounts_sha256.clone(),
        environment_sha256: worker.environment_sha256.clone(),
        backend_sha256: worker.backend_sha256.clone(),
        process_supervision_sha256: worker.process_supervision_sha256.clone(),
        workspace_sha256: workspace_sha256.into(),
    }
}

fn seeded_campaign(seed: u128) -> Result<Campaign> {
    let mut manifest = manifest(1)?;
    let path = "crates/nac-server/tests/fixtures/appsec-pilot/main.go";
    let package = SourcePackage::freeze(
        &manifest.repositories,
        &[("nac-test".into(), path.into())],
        &[],
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
        base_commit: manifest.repositories[0].commit.clone(),
        source_package: package,
        dependencies: vec![],
        configuration_sha256: "d".repeat(64),
        skill_bundle_sha256: "e".repeat(64),
        editable_roots: vec!["crates/nac-server/tests/fixtures/appsec-pilot".into()],
        generator: RemediationWorkerIdentity {
            model: "generator-model".into(),
            runtime: "coding-runtime-v1".into(),
            extractor: "patch-extractor-v1".into(),
            prompt_sha256: "f".repeat(64),
            environment_sha256: "0".repeat(64),
            tools_sha256: "1".repeat(64),
            mounts_sha256: "2".repeat(64),
            backend_sha256: "3".repeat(64),
            process_supervision_sha256: "4".repeat(64),
        },
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
        limits: RemediationLimits {
            operation_ms: 10_000,
            output_bytes: 1_000_000,
            max_files: 4,
            max_patch_bytes: 100_000,
        },
    });
    let candidate_id = id(seed + 1);
    let candidate_task = id(seed + 2);
    let candidate_attempt = id(seed + 3);
    let validation_id = id(seed + 4);
    let validation_task = id(seed + 5);
    let validation_attempt = id(seed + 6);
    let bytes = git(&[
        "show",
        &format!("{}:{path}", manifest.repositories[0].commit),
    ])?;
    let source = SourceRef {
        repository: "nac-test".into(),
        commit: manifest.repositories[0].commit.clone(),
        path: path.into(),
        start_line: 1,
        end_line: 1,
        content_sha256: digest(&bytes),
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
                    input: serde_json::json!({}),
                    input_sha256: "6".repeat(64),
                    effective_inputs: BTreeMap::from([(candidate_attempt, inputs("candidate"))]),
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
                    input: serde_json::json!({}),
                    input_sha256: "7".repeat(64),
                    effective_inputs: BTreeMap::from([(validation_attempt, inputs("validation"))]),
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
    Ok(Campaign {
        schema_version: 1,
        id: id(seed),
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

fn request(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
) -> Result<RemediationCase> {
    request_with_key(controller, campaign, "fix-authz")
}

fn request_with_key(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
    key: &str,
) -> Result<RemediationCase> {
    let provenance = controller.remediation_provenance(campaign.id, campaign.accepted[0].id)?;
    controller.request_remediation(
        campaign.id,
        controller.status(campaign.id)?.revision,
        StartRemediation {
            schema_version: 1,
            key: key.into(),
            assertion_review: Some(AssertionReview {
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

fn cleanup(phase: RemediationPhase, workspace_sha256: &str) -> RemediationEffectOutput {
    RemediationEffectOutput::CleanupSettled {
        receipt: CleanupReceipt {
            process_sha256: "a".repeat(64),
            workspace_sha256: workspace_sha256.into(),
            target_sha256: (phase == RemediationPhase::EvaluatePatch).then(|| "c".repeat(64)),
            network_sha256: Some("d".repeat(64)),
            delayed_launches_settled: true,
            descendants_terminated: true,
        },
    }
}

fn record(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: Id,
    remediation: Id,
    key: &str,
    fence: EffectFence,
    output: RemediationEffectOutput,
) -> Result<RemediationCase> {
    controller.record_remediation_observation(
        campaign,
        remediation,
        RecordRemediationObservation {
            schema_version: 1,
            key: key.into(),
            fence,
            output,
        },
    )
}

fn replacement_diff(path: &str, original: &[u8], replacement: &[u8]) -> Vec<u8> {
    let original = std::str::from_utf8(original).unwrap();
    let replacement = std::str::from_utf8(replacement).unwrap();
    let mut output = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n",
        original.lines().count(),
        replacement.lines().count()
    );
    for line in original.lines() {
        output.push_str(&format!("-{line}\n"));
    }
    for line in replacement.lines() {
        output.push_str(&format!("+{line}\n"));
    }
    output.into_bytes()
}

fn evaluation_evidence(
    store: &ArtifactStore,
    assertion: &EvaluatorAssertion,
    source_package_sha256: &str,
    patch_sha256: &str,
    patched_target: &TargetIdentity,
) -> Result<EvaluationEvidence> {
    let artifact = |label: &str| store.write(label.as_bytes(), 100_000);
    let legitimate = |artifact| LegitimateUseEvidence {
        artifact,
        health: true,
        public_access: true,
        owner_access: true,
        owner_write_readback: true,
        protected_route_bindings: true,
        complete: true,
    };
    let checks = |artifact| RequiredChecksEvidence {
        artifact,
        configuration_sha256: assertion.required_checks_sha256.clone(),
        total: 1,
        passed: 1,
        skipped: 0,
        truncated: false,
    };
    Ok(EvaluationEvidence {
        identities: TargetIdentityEvidence {
            artifact: artifact("paired target identities verified")?,
            source_package_sha256: source_package_sha256.into(),
            patch_sha256: patch_sha256.into(),
            original: assertion.original_target.clone(),
            patched: patched_target.clone(),
            effective_environment_sha256: assertion.original_target.environment_sha256.clone(),
            complete: true,
        },
        original_assertion: SecurityAssertionEvidence {
            artifact: artifact("original assertion: unauthorized access observed")?,
            violation_observed: true,
            expected_reason: Some(SecurityFailureReason::UnauthorizedAccessObserved),
            complete: true,
        },
        patched_assertion: SecurityAssertionEvidence {
            artifact: artifact("patched assertion: unauthorized access blocked")?,
            violation_observed: false,
            expected_reason: None,
            complete: true,
        },
        original_legitimate_use: legitimate(artifact("original legitimate-use checks passed")?),
        patched_legitimate_use: legitimate(artifact("patched legitimate-use checks passed")?),
        original_required_checks: checks(artifact("original required checks passed")?),
        patched_required_checks: checks(artifact("patched required checks passed")?),
        structural_review: StructuralReviewEvidence {
            artifact: artifact("structural review passed")?,
            changed_files: 1,
            production_change_nonempty: true,
            protected_symbols_preserved: true,
            route_bindings_preserved: true,
            tests_unchanged: true,
            assertions_unchanged: true,
            fixtures_unchanged: true,
            dependencies_unchanged: true,
            check_configuration_unchanged: true,
            complete: true,
        },
    })
}

fn settle_patch(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
    case: &RemediationCase,
    state_path: &std::path::Path,
) -> Result<RemediationCase> {
    let profile = campaign.manifest.remediation.as_ref().unwrap();
    let original = &profile.source_package.files[0];
    let store = ArtifactStore::open(state_path)?;
    let replacement = b"package main\n\nfunc authorized() bool { return true }\n";
    let content = store.write(replacement, 100_000)?;
    let original_bytes = git(&["show", &format!("{}:{}", original.commit, original.path)])?;
    let diff_bytes = replacement_diff(&original.path, &original_bytes, replacement);
    let diff = store.write(&diff_bytes, 100_000)?;
    let fence = case.effects.last().unwrap().fence.clone();
    record(
        controller,
        campaign.id,
        case.id,
        "patch-result",
        fence.clone(),
        RemediationEffectOutput::PatchProposed {
            proposal: PatchGeneratorSubmission {
                schema_version: 1,
                authority: authority(&profile.generator, &profile.source_package.manifest_sha256),
                replacements: vec![FileReplacement {
                    path: original.path.clone(),
                    original_sha256: Some(original.content_sha256.clone()),
                    replacement_sha256: content.sha256.clone(),
                    replacement_bytes: content.bytes,
                    content,
                }],
                unified_diff: diff,
                diagnostics: vec![],
            },
        },
    )?;
    record(
        controller,
        campaign.id,
        case.id,
        "patch-cleanup",
        fence,
        cleanup(
            RemediationPhase::GeneratePatch,
            &profile.source_package.manifest_sha256,
        ),
    )
}

fn settle_evaluation(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
    case: &RemediationCase,
    state_path: &std::path::Path,
) -> Result<RemediationCase> {
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    let RemediationEffectPlan::EvaluatePatch {
        assertion,
        patch,
        worker,
        ..
    } = desired.plan
    else {
        panic!("expected evaluation")
    };
    let source_package_sha256 = &campaign
        .manifest
        .remediation
        .as_ref()
        .unwrap()
        .source_package
        .manifest_sha256;
    let patched_target = TargetIdentity {
        source_sha256: digest(&serde_json::to_vec(&(
            1_u32,
            source_package_sha256,
            &patch.patch_sha256,
        ))?),
        build_sha256: "1".repeat(64),
        image_sha256: "2".repeat(64),
        environment_sha256: assertion.original_target.environment_sha256.clone(),
    };
    let store = ArtifactStore::open(state_path)?;
    let evidence = evaluation_evidence(
        &store,
        &assertion,
        source_package_sha256,
        &patch.patch_sha256,
        &patched_target,
    )?;
    let workspace_sha256 = digest(&serde_json::to_vec(&(
        1_u32,
        &campaign
            .manifest
            .remediation
            .as_ref()
            .unwrap()
            .source_package
            .manifest_sha256,
        &patch.patch_sha256,
        &assertion.assertion_sha256,
    ))?);
    let output = EvaluationOutput {
        verdict: EvaluationVerdict::Fixed,
        assertion_sha256: assertion.assertion_sha256,
        patch_sha256: desired.fence.patch_sha256.clone().unwrap(),
        original_target: assertion.original_target,
        patched_target,
        authority: authority(&worker, &workspace_sha256),
        evidence,
        complete: true,
        diagnostics: vec![],
    };
    let evaluated = record(
        controller,
        campaign.id,
        case.id,
        "evaluation-result",
        desired.fence.clone(),
        RemediationEffectOutput::EvaluationCompleted {
            evaluation: Box::new(output),
        },
    )?;
    assert_eq!(evaluated.status(), RemediationStatus::Proposed);
    record(
        controller,
        campaign.id,
        case.id,
        "evaluation-cleanup",
        desired.fence,
        cleanup(RemediationPhase::EvaluatePatch, &workspace_sha256),
    )
}

fn settle_package(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
    case: &RemediationCase,
    state_path: &std::path::Path,
) -> Result<RemediationCase> {
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    let RemediationEffectPlan::Package {
        finding,
        patch,
        evaluation,
        cleanup: receipts,
        report,
    } = desired.plan
    else {
        panic!("expected package")
    };
    let diff = ArtifactStore::open(state_path)?.read_range(
        &patch.proposal.unified_diff,
        0,
        patch.proposal.unified_diff.bytes,
    )?;
    let package =
        RemediationPackage::build(&finding, &patch, &evaluation, &receipts, &diff, &report)?;
    let packaged = record(
        controller,
        campaign.id,
        case.id,
        "package-result",
        desired.fence.clone(),
        RemediationEffectOutput::PackageBuilt { package },
    )?;
    assert_eq!(packaged.status(), RemediationStatus::TestsPassed);
    let workspace_sha256 = desired.fence.plan_sha256.clone();
    record(
        controller,
        campaign.id,
        case.id,
        "package-cleanup",
        desired.fence,
        cleanup(RemediationPhase::Package, &workspace_sha256),
    )
}

fn approved_case(
    controller: &Controller<SqliteRepository, TestClock>,
    campaign: &Campaign,
    state_path: &std::path::Path,
) -> Result<RemediationCase> {
    let case = settle_package(
        controller,
        campaign,
        &settle_evaluation(
            controller,
            campaign,
            &settle_patch(
                controller,
                campaign,
                &request(controller, campaign)?,
                state_path,
            )?,
            state_path,
        )?,
        state_path,
    )?;
    let package = case.packages.last().unwrap();
    controller.approve_remediation(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        RemediationApproval {
            schema_version: 1,
            generation: case.generation(),
            decision: ApprovalDecision::Approved,
            reviewer: "reviewer".into(),
            package_id: package.package_id.clone(),
            finding: case.provenance.finding.clone(),
            assertion_sha256: case.provenance.assertion.assertion_sha256.clone(),
        },
    )
}

struct ScriptedGenerator {
    proposal: PatchGeneratorSubmission,
}

impl PatchGenerator for ScriptedGenerator {
    fn reconcile_patch(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput> {
        let RemediationEffectPlan::GeneratePatch { source_package, .. } = &desired.plan else {
            anyhow::bail!("unexpected generator plan")
        };
        if desired.stop {
            Ok(cleanup(
                RemediationPhase::GeneratePatch,
                &source_package.manifest_sha256,
            ))
        } else {
            Ok(RemediationEffectOutput::PatchProposed {
                proposal: self.proposal.clone(),
            })
        }
    }
}

struct ScriptedEvaluator {
    store: ArtifactStore,
}

impl PatchEvaluator for ScriptedEvaluator {
    fn reconcile_evaluation(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput> {
        let RemediationEffectPlan::EvaluatePatch {
            source_package,
            patch,
            assertion,
            worker,
            ..
        } = &desired.plan
        else {
            anyhow::bail!("unexpected evaluator plan")
        };
        let workspace_sha256 = digest(&serde_json::to_vec(&(
            1_u32,
            &source_package.manifest_sha256,
            &patch.patch_sha256,
            &assertion.assertion_sha256,
        ))?);
        if desired.stop {
            return Ok(cleanup(RemediationPhase::EvaluatePatch, &workspace_sha256));
        }
        let patched_target = TargetIdentity {
            source_sha256: digest(&serde_json::to_vec(&(
                1_u32,
                &source_package.manifest_sha256,
                &patch.patch_sha256,
            ))?),
            build_sha256: "a".repeat(64),
            image_sha256: "b".repeat(64),
            environment_sha256: assertion.original_target.environment_sha256.clone(),
        };
        Ok(RemediationEffectOutput::EvaluationCompleted {
            evaluation: Box::new(EvaluationOutput {
                verdict: EvaluationVerdict::Fixed,
                assertion_sha256: assertion.assertion_sha256.clone(),
                patch_sha256: patch.patch_sha256.clone(),
                original_target: assertion.original_target.clone(),
                patched_target: patched_target.clone(),
                authority: authority(worker, &workspace_sha256),
                evidence: evaluation_evidence(
                    &self.store,
                    assertion,
                    &source_package.manifest_sha256,
                    &patch.patch_sha256,
                    &patched_target,
                )?,
                complete: true,
                diagnostics: vec![],
            }),
        })
    }
}

#[test]
fn legacy_json_defaults_to_no_remediation_without_changing_source_only_behavior() -> Result<()> {
    let input = manifest(1)?;
    let mut value = serde_json::to_value(&input)?;
    value.as_object_mut().unwrap().remove("remediation");
    assert!(serde_json::from_value::<Manifest>(value)?
        .remediation
        .is_none());
    let mut campaign = seeded_campaign(100)?;
    campaign.remediations.clear();
    let mut value = serde_json::to_value(&campaign)?;
    value.as_object_mut().unwrap().remove("remediations");
    assert!(serde_json::from_value::<Campaign>(value)?
        .remediations
        .is_empty());
    Ok(())
}

#[test]
fn one_reconcile_call_owns_generation_evaluation_cleanup_and_packaging() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(500)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = request(&controller, &campaign)?;
    let profile = campaign.manifest.remediation.as_ref().unwrap();
    let original = &profile.source_package.files[0];
    let replacement = b"package main\n\nfunc authorized() bool { return true }\n";
    let store = ArtifactStore::open(&path)?;
    let content = store.write(replacement, 100_000)?;
    let original_bytes = git(&["show", &format!("{}:{}", original.commit, original.path)])?;
    let diff = replacement_diff(&original.path, &original_bytes, replacement);
    let mut generator = ScriptedGenerator {
        proposal: PatchGeneratorSubmission {
            schema_version: 1,
            authority: authority(&profile.generator, &profile.source_package.manifest_sha256),
            replacements: vec![FileReplacement {
                path: original.path.clone(),
                original_sha256: Some(original.content_sha256.clone()),
                replacement_sha256: content.sha256.clone(),
                replacement_bytes: content.bytes,
                content,
            }],
            unified_diff: store.write(&diff, 100_000)?,
            diagnostics: vec![],
        },
    };
    let mut evaluator = ScriptedEvaluator {
        store: ArtifactStore::open(&path)?,
    };
    let settled =
        controller.reconcile_remediation(campaign.id, case.id, &mut generator, &mut evaluator)?;
    assert_eq!(settled.status(), RemediationStatus::ReviewRequired);
    assert_eq!(settled.patches.len(), 1);
    assert_eq!(settled.evaluations.len(), 1);
    assert_eq!(settled.packages.len(), 1);
    assert!(settled.effects.iter().all(|effect| {
        settled.observations[&effect.fence.effect_id]
            .iter()
            .any(|observation| {
                matches!(
                    observation.output,
                    RemediationEffectOutput::CleanupSettled { .. }
                )
            })
    }));
    Ok(())
}

#[test]
fn remediation_is_exactly_anchored_idempotent_fenced_and_transactionally_reserved() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(1_000)?;
    let other = seeded_campaign(2_000)?;
    repository.insert(&campaign)?;
    repository.insert(&other)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let accepted_before = serde_json::to_vec(&controller.status(campaign.id)?.accepted)?;
    let case = request(&controller, &campaign)?;
    assert_eq!(case.effects.len(), 1);
    assert_eq!(
        controller
            .status(campaign.id)?
            .occupied_remediation_workers(),
        1
    );
    assert!(
        request(&controller, &other).is_err(),
        "worker reservation is host-wide"
    );
    let replay = request(&controller, &campaign)?;
    assert_eq!(replay.id, case.id);
    assert_eq!(
        accepted_before,
        serde_json::to_vec(&controller.status(campaign.id)?.accepted)?
    );

    let store = ArtifactStore::open(&path)?;
    let profile = campaign.manifest.remediation.as_ref().unwrap();
    let original = &profile.source_package.files[0];
    let replacement = b"package main\n\nfunc authorized() bool { return true }\n";
    let content = store.write(replacement, 100_000)?;
    let original_bytes = git(&["show", &format!("{}:{}", original.commit, original.path)])?;
    let diff = store.write(
        &replacement_diff(&original.path, &original_bytes, replacement),
        100_000,
    )?;
    let fence = case.effects[0].fence.clone();
    assert!(record(
        &controller,
        campaign.id,
        case.id,
        "premature-cleanup",
        fence.clone(),
        cleanup(
            RemediationPhase::GeneratePatch,
            &profile.source_package.manifest_sha256,
        ),
    )
    .is_err());
    let observation = RecordRemediationObservation {
        schema_version: 1,
        key: "patch".into(),
        fence: fence.clone(),
        output: RemediationEffectOutput::PatchProposed {
            proposal: PatchGeneratorSubmission {
                schema_version: 1,
                authority: authority(&profile.generator, &profile.source_package.manifest_sha256),
                replacements: vec![FileReplacement {
                    path: original.path.clone(),
                    original_sha256: Some(original.content_sha256.clone()),
                    replacement_sha256: content.sha256.clone(),
                    replacement_bytes: content.bytes,
                    content,
                }],
                unified_diff: diff,
                diagnostics: vec![],
            },
        },
    };
    let mut wrong_authority = observation.clone();
    wrong_authority.key = "wrong-authority".into();
    let RemediationEffectOutput::PatchProposed { proposal } = &mut wrong_authority.output else {
        unreachable!()
    };
    proposal.authority.tools_sha256 = "f".repeat(64);
    assert!(controller
        .record_remediation_observation(campaign.id, case.id, wrong_authority)
        .is_err());
    let mut wrong_diff = observation.clone();
    wrong_diff.key = "wrong-diff".into();
    let RemediationEffectOutput::PatchProposed { proposal } = &mut wrong_diff.output else {
        unreachable!()
    };
    proposal.unified_diff = store.write(b"--- unrelated\n+++ unrelated\n", 100_000)?;
    assert!(controller
        .record_remediation_observation(campaign.id, case.id, wrong_diff)
        .is_err());
    let patched =
        controller.record_remediation_observation(campaign.id, case.id, observation.clone())?;
    assert_eq!(patched.patches.len(), 1);
    assert_eq!(
        controller
            .record_remediation_observation(campaign.id, case.id, observation)?
            .patches
            .len(),
        1
    );
    let cancelled = controller.cancel_remediation(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
    )?;
    assert!(controller
        .record_remediation_observation(
            campaign.id,
            case.id,
            RecordRemediationObservation {
                schema_version: 1,
                key: "late-success".into(),
                fence: fence.clone(),
                output: RemediationEffectOutput::Failed {
                    diagnostics: vec![PublicRemediationDiagnostic {
                        code: RemediationDiagnosticCode::Cancelled,
                        source: None,
                        byte_offset: None,
                        complete: true,
                        artifact_sha256: None,
                    }],
                    recovery_required: false,
                },
            },
        )
        .is_err());
    let cleaned = controller.record_remediation_observation(
        campaign.id,
        case.id,
        RecordRemediationObservation {
            schema_version: 1,
            key: "cleanup".into(),
            fence,
            output: RemediationEffectOutput::CleanupSettled {
                receipt: CleanupReceipt {
                    process_sha256: "1".repeat(64),
                    workspace_sha256: profile.source_package.manifest_sha256.clone(),
                    target_sha256: None,
                    network_sha256: Some("3".repeat(64)),
                    delayed_launches_settled: true,
                    descendants_terminated: true,
                },
            },
        },
    )?;
    assert_eq!(cleaned.id, cancelled.id);
    assert_eq!(
        controller
            .status(campaign.id)?
            .occupied_remediation_workers(),
        0
    );

    let updater = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    updater.update(campaign.id, None, &mut |stored, _| {
        stored
            .manifest
            .remediation
            .as_mut()
            .unwrap()
            .generator
            .prompt_sha256 = "e".repeat(64);
        let mut superseding = stored.accepted[1].clone();
        superseding.id = id(9_999);
        superseding.key = "new-validation".into();
        superseding.payload_hash = "9".repeat(64);
        if let Payload::Workflow { revision, .. } = &mut superseding.payload {
            *revision = 2;
        }
        stored.accepted.push(superseding);
        Ok(())
    })?;
    let view = controller.read_remediation(campaign.id, case.id)?;
    assert_eq!(view.freshness, RemediationFreshness::Superseded);
    assert!(!view.publication_ready);
    Ok(())
}

#[test]
fn accepted_evidence_and_remediation_history_are_append_only() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(4_000)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = request(&controller, &campaign)?;
    let updater = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    assert!(updater
        .update(campaign.id, None, &mut |stored, _| {
            let Payload::Candidate { candidate } = &mut stored.accepted[0].payload else {
                unreachable!()
            };
            candidate.claim = "rewritten accepted evidence".into();
            Ok(())
        })
        .is_err());
    assert!(updater
        .update(campaign.id, None, &mut |stored, _| {
            stored.remediations[0].effects.clear();
            Ok(())
        })
        .is_err());
    let stored = controller.status(campaign.id)?;
    let Payload::Candidate { candidate } = &stored.accepted[0].payload else {
        unreachable!()
    };
    assert_eq!(
        candidate.claim,
        "an unauthenticated caller can read another owner's object"
    );
    assert_eq!(stored.remediations[0].effects.len(), case.effects.len());
    Ok(())
}

#[test]
fn supersession_tombstones_a_live_effect_and_allows_cleanup_to_release_capacity() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(4_500)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = request(&controller, &campaign)?;
    let updater = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    updater.update(campaign.id, None, &mut |stored, _| {
        stored
            .manifest
            .remediation
            .as_mut()
            .unwrap()
            .generator
            .prompt_sha256 = "e".repeat(64);
        let mut superseding = stored.accepted[1].clone();
        superseding.id = id(4_599);
        superseding.key = "superseding-validation".into();
        superseding.payload_hash = "f".repeat(64);
        if let Payload::Workflow { revision, .. } = &mut superseding.payload {
            *revision = 2;
        }
        stored.accepted.push(superseding);
        Ok(())
    })?;
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    assert!(desired.stop);
    let settled = record(
        &controller,
        campaign.id,
        case.id,
        "superseded-cleanup",
        desired.fence,
        cleanup(
            RemediationPhase::GeneratePatch,
            &campaign
                .manifest
                .remediation
                .as_ref()
                .unwrap()
                .source_package
                .manifest_sha256,
        ),
    )?;
    assert!(settled.journal.iter().any(|entry| matches!(
        entry,
        RemediationJournalEntry::Tombstoned {
            reason: RemediationTombstoneReason::Superseded,
            ..
        }
    )));
    assert_eq!(
        controller
            .status(campaign.id)?
            .occupied_remediation_workers(),
        0
    );
    Ok(())
}

#[test]
fn cleanup_gates_acceptance_and_package_materialization_is_conflict_safe() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(5_000)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = request(&controller, &campaign)?;
    let case = settle_patch(&controller, &campaign, &case, &path)?;
    let case = settle_evaluation(&controller, &campaign, &case, &path)?;
    assert_eq!(case.status(), RemediationStatus::TestsPassed);
    let case = settle_package(&controller, &campaign, &case, &path)?;
    assert_eq!(case.status(), RemediationStatus::ReviewRequired);
    let package = case.packages.last().unwrap();
    let destination = directory.0.join("materialized");
    let first =
        controller.materialize_remediation_package(campaign.id, package.id, &destination)?;
    let second =
        controller.materialize_remediation_package(campaign.id, package.id, &destination)?;
    assert_eq!(first.package_id()?, second.package_id()?);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(destination.join("manifest.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let linked = directory.0.join("linked-materialization");
    std::os::unix::fs::symlink(&destination, &linked)?;
    assert!(controller
        .materialize_remediation_package(campaign.id, package.id, &linked)
        .is_err());
    std::fs::write(destination.join("report.md"), b"conflict\n")?;
    assert!(controller
        .materialize_remediation_package(campaign.id, package.id, &destination)
        .is_err());
    Ok(())
}

#[test]
fn approval_does_not_publish_without_an_explicit_generation_bound_request() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(6_000)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = settle_package(
        &controller,
        &campaign,
        &settle_evaluation(
            &controller,
            &campaign,
            &settle_patch(
                &controller,
                &campaign,
                &request(&controller, &campaign)?,
                &path,
            )?,
            &path,
        )?,
        &path,
    )?;
    let package = case.packages.last().unwrap();
    let approval = RemediationApproval {
        schema_version: 1,
        generation: case.generation(),
        decision: ApprovalDecision::Approved,
        reviewer: "reviewer".into(),
        package_id: package.package_id.clone(),
        finding: case.provenance.finding.clone(),
        assertion_sha256: case.provenance.assertion.assertion_sha256.clone(),
    };
    let approved = controller.approve_remediation(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        approval,
    )?;
    assert_eq!(approved.status(), RemediationStatus::Approved);
    assert!(controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .is_none());
    controller.request_remediation_publication(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        PublicationTarget {
            provider: "github".into(),
            repository: "owner/repository".into(),
        },
    )?;
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    assert_eq!(desired.fence.phase, RemediationPhase::PublishDraft);
    let failed = RecordRemediationObservation {
        schema_version: 1,
        key: "publish-failed".into(),
        fence: desired.fence.clone(),
        output: RemediationEffectOutput::Failed {
            diagnostics: vec![PublicRemediationDiagnostic {
                code: RemediationDiagnosticCode::RecoveryRequired,
                source: None,
                byte_offset: None,
                complete: true,
                artifact_sha256: None,
            }],
            recovery_required: true,
        },
    };
    controller.record_remediation_observation(campaign.id, case.id, failed)?;
    let workspace_sha256 = desired.fence.plan_sha256.clone();
    record(
        &controller,
        campaign.id,
        case.id,
        "publish-cleanup",
        desired.fence,
        cleanup(RemediationPhase::PublishDraft, &workspace_sha256),
    )?;
    let recovered = controller.recover_remediation(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
    )?;
    assert_eq!(recovered.status(), RemediationStatus::NotStarted);
    assert!(controller
        .recover_remediation(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )
        .is_err());
    Ok(())
}

#[test]
fn successful_publication_observation_is_replay_idempotent() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(6_500)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = settle_package(
        &controller,
        &campaign,
        &settle_evaluation(
            &controller,
            &campaign,
            &settle_patch(
                &controller,
                &campaign,
                &request(&controller, &campaign)?,
                &path,
            )?,
            &path,
        )?,
        &path,
    )?;
    let package = case.packages.last().unwrap();
    controller.approve_remediation(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        RemediationApproval {
            schema_version: 1,
            generation: case.generation(),
            decision: ApprovalDecision::Approved,
            reviewer: "reviewer".into(),
            package_id: package.package_id.clone(),
            finding: case.provenance.finding.clone(),
            assertion_sha256: case.provenance.assertion.assertion_sha256.clone(),
        },
    )?;
    controller.request_remediation_publication(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        PublicationTarget {
            provider: "github".into(),
            repository: "owner/repository".into(),
        },
    )?;
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    let RemediationEffectPlan::PublishDraft {
        base_commit,
        stable_finding_key,
        package,
        ..
    } = desired.plan
    else {
        panic!("expected publication")
    };
    let observation = RecordRemediationObservation {
        schema_version: 1,
        key: "publication-result".into(),
        fence: desired.fence.clone(),
        output: RemediationEffectOutput::PublicationCompleted {
            publication: PublicationOutput {
                stable_finding_key,
                package_id: package.package_id,
                base_commit,
                outcome: PublicationOutcome::DraftCreated,
                remote_reference_sha256: Some("e".repeat(64)),
                complete: true,
                diagnostics: vec![],
            },
        },
    };
    let first =
        controller.record_remediation_observation(campaign.id, case.id, observation.clone())?;
    let replay = controller.record_remediation_observation(campaign.id, case.id, observation)?;
    assert_eq!(first.publications.len(), 1);
    assert_eq!(replay.publications.len(), 1);
    assert_eq!(replay.status(), RemediationStatus::Approved);
    let workspace_sha256 = desired.fence.plan_sha256.clone();
    let published = record(
        &controller,
        campaign.id,
        case.id,
        "publication-cleanup",
        desired.fence,
        cleanup(RemediationPhase::PublishDraft, &workspace_sha256),
    )?;
    assert_eq!(published.status(), RemediationStatus::Published);
    Ok(())
}

#[test]
fn base_drift_closes_publication_readiness_until_renewed_acceptance() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(6_750)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = approved_case(&controller, &campaign, &path)?;
    controller.request_remediation_publication(
        campaign.id,
        case.id,
        controller.status(campaign.id)?.revision,
        PublicationTarget {
            provider: "github".into(),
            repository: "owner/repository".into(),
        },
    )?;
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    let RemediationEffectPlan::PublishDraft {
        base_commit,
        stable_finding_key,
        package,
        ..
    } = desired.plan
    else {
        panic!("expected publication")
    };
    let workspace_sha256 = desired.fence.plan_sha256.clone();
    record(
        &controller,
        campaign.id,
        case.id,
        "base-drift",
        desired.fence.clone(),
        RemediationEffectOutput::PublicationCompleted {
            publication: PublicationOutput {
                stable_finding_key,
                package_id: package.package_id,
                base_commit,
                outcome: PublicationOutcome::BaseDrift,
                remote_reference_sha256: None,
                complete: true,
                diagnostics: vec![PublicRemediationDiagnostic {
                    code: RemediationDiagnosticCode::BaseDrift,
                    source: None,
                    byte_offset: None,
                    complete: true,
                    artifact_sha256: None,
                }],
            },
        },
    )?;
    record(
        &controller,
        campaign.id,
        case.id,
        "base-drift-cleanup",
        desired.fence,
        cleanup(RemediationPhase::PublishDraft, &workspace_sha256),
    )?;
    let view = controller.read_remediation(campaign.id, case.id)?;
    assert_eq!(view.status, RemediationStatus::Approved);
    assert!(!view.publication_ready);
    assert!(controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .is_none());
    Ok(())
}

#[test]
fn stable_finding_key_serializes_publication_across_cases() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 2)?;
    let campaign = seeded_campaign(6_875)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let first = approved_case(&controller, &campaign, &path)?;
    let second = request_with_key(&controller, &campaign, "fix-authz-second")?;
    let second = settle_patch(&controller, &campaign, &second, &path)?;
    let second = settle_evaluation(&controller, &campaign, &second, &path)?;
    let second = settle_package(&controller, &campaign, &second, &path)?;
    let package = second.packages.last().unwrap();
    let second = controller.approve_remediation(
        campaign.id,
        second.id,
        controller.status(campaign.id)?.revision,
        RemediationApproval {
            schema_version: 1,
            generation: second.generation(),
            decision: ApprovalDecision::Approved,
            reviewer: "second-reviewer".into(),
            package_id: package.package_id.clone(),
            finding: second.provenance.finding.clone(),
            assertion_sha256: second.provenance.assertion.assertion_sha256.clone(),
        },
    )?;
    let target = PublicationTarget {
        provider: "github".into(),
        repository: "owner/repository".into(),
    };
    controller.request_remediation_publication(
        campaign.id,
        first.id,
        controller.status(campaign.id)?.revision,
        target.clone(),
    )?;
    assert!(controller
        .request_remediation_publication(
            campaign.id,
            second.id,
            controller.status(campaign.id)?.revision,
            target,
        )
        .is_err());
    Ok(())
}

#[test]
fn package_verification_rejects_semantically_forged_payloads() -> Result<()> {
    let campaign = seeded_campaign(7_000)?;
    let finding = PublicFinding {
        revision: FindingRevision {
            candidate_id: campaign.accepted[0].id,
            candidate_payload_sha256: campaign.accepted[0].payload_hash.clone(),
            validation_id: campaign.accepted[1].id,
            validation_payload_sha256: campaign.accepted[1].payload_hash.clone(),
            workflow_decision_revision: 1,
        },
        claim: "fixture".into(),
        prerequisites: vec![],
        source: match &campaign.accepted[0].payload {
            Payload::Candidate { candidate } => candidate.source.clone(),
            _ => unreachable!(),
        },
        evidence: vec![],
        validation_evidence: vec![],
    };
    let bytes = serde_json::to_vec(&finding)?;
    let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("finding.json".into(), bytes),
        ("patch.json".into(), b"{}".to_vec()),
        ("evaluation.json".into(), b"{}".to_vec()),
        ("patch.diff".into(), b"forged\n".to_vec()),
        ("report.md".into(), b"forged\n".to_vec()),
    ]);
    let files = payloads
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                PackagePayload {
                    bytes: bytes.len() as u64,
                    sha256: digest(bytes),
                    mode: 0o644,
                },
            )
        })
        .collect();
    let forged = RemediationPackage {
        manifest: RemediationPackageManifest {
            schema_version: 1,
            finding: finding.revision,
            plan_sha256: "1".repeat(64),
            patch_sha256: "2".repeat(64),
            evaluation_plan_sha256: "3".repeat(64),
            evaluation_sha256: digest(&payloads["evaluation.json"]),
            files,
        },
        payloads: std::mem::take(&mut payloads),
    };
    assert!(forged.verify().is_err());
    Ok(())
}

#[test]
fn replacement_assertions_require_a_new_version_bound_review() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 2)?;
    let campaign = seeded_campaign(8_000)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    request(&controller, &campaign)?;
    let updater = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 2)?;
    updater.update(campaign.id, None, &mut |stored, _| {
        let assertion = &mut stored.manifest.remediation.as_mut().unwrap().assertion;
        assertion.version = "go-authz-v2".into();
        assertion.rubric_sha256 = "f".repeat(64);
        assertion.assertion_sha256 = assertion.canonical_sha256()?;
        Ok(())
    })?;
    let provenance = controller.remediation_provenance(campaign.id, campaign.accepted[0].id)?;
    let wrong_review = StartRemediation {
        schema_version: 1,
        key: "fix-authz-v2".into(),
        assertion_review: Some(AssertionReview {
            reason: AssertionReviewReason::StaticSupported,
            candidate_id: provenance.finding.candidate_id,
            validation_id: provenance.finding.validation_id,
            assertion_version: provenance.assertion.version.clone(),
            assertion_sha256: provenance.assertion.assertion_sha256.clone(),
            reviewer: "operator".into(),
            reviewed_ms: 100,
        }),
        provenance: provenance.clone(),
    };
    assert!(controller
        .request_remediation(
            campaign.id,
            controller.status(campaign.id)?.revision,
            wrong_review,
        )
        .is_err());
    let case = controller.request_remediation(
        campaign.id,
        controller.status(campaign.id)?.revision,
        StartRemediation {
            schema_version: 1,
            key: "fix-authz-v2".into(),
            assertion_review: Some(AssertionReview {
                reason: AssertionReviewReason::AssertionReplacement,
                candidate_id: provenance.finding.candidate_id,
                validation_id: provenance.finding.validation_id,
                assertion_version: provenance.assertion.version.clone(),
                assertion_sha256: provenance.assertion.assertion_sha256.clone(),
                reviewer: "operator".into(),
                reviewed_ms: 100,
            }),
            provenance,
        },
    )?;
    assert_eq!(case.generation(), 1);
    Ok(())
}

#[test]
fn fixed_evaluation_requires_verdict_evidence() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let repository = SqliteRepository::open_with_resource_capacity(&path, 4, 1, 1)?;
    let campaign = seeded_campaign(9_000)?;
    repository.insert(&campaign)?;
    let controller = Controller::new(repository, ArtifactStore::open(&path)?, TestClock::new());
    let case = settle_patch(
        &controller,
        &campaign,
        &request(&controller, &campaign)?,
        &path,
    )?;
    let desired = controller
        .desired_remediation_effect(
            campaign.id,
            case.id,
            controller.status(campaign.id)?.revision,
        )?
        .unwrap();
    let RemediationEffectPlan::EvaluatePatch {
        assertion,
        patch,
        worker,
        ..
    } = desired.plan
    else {
        panic!("expected evaluation")
    };
    let source_package_sha256 = &campaign
        .manifest
        .remediation
        .as_ref()
        .unwrap()
        .source_package
        .manifest_sha256;
    let patched_target = TargetIdentity {
        source_sha256: digest(&serde_json::to_vec(&(
            1_u32,
            source_package_sha256,
            &patch.patch_sha256,
        ))?),
        build_sha256: "1".repeat(64),
        image_sha256: "2".repeat(64),
        environment_sha256: assertion.original_target.environment_sha256.clone(),
    };
    let mut evidence = evaluation_evidence(
        &ArtifactStore::open(&path)?,
        &assertion,
        source_package_sha256,
        &patch.patch_sha256,
        &patched_target,
    )?;
    evidence.original_assertion.complete = false;
    let workspace_sha256 = digest(&serde_json::to_vec(&(
        1_u32,
        &campaign
            .manifest
            .remediation
            .as_ref()
            .unwrap()
            .source_package
            .manifest_sha256,
        &patch.patch_sha256,
        &assertion.assertion_sha256,
    ))?);
    let result = record(
        &controller,
        campaign.id,
        case.id,
        "empty-evaluation",
        desired.fence.clone(),
        RemediationEffectOutput::EvaluationCompleted {
            evaluation: Box::new(EvaluationOutput {
                verdict: EvaluationVerdict::Fixed,
                assertion_sha256: assertion.assertion_sha256,
                patch_sha256: desired.fence.patch_sha256.unwrap(),
                original_target: assertion.original_target,
                patched_target,
                authority: authority(&worker, &workspace_sha256),
                evidence,
                complete: true,
                diagnostics: vec![],
            }),
        },
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn package_manifest_is_deterministic_and_never_hashes_itself() -> Result<()> {
    let campaign = seeded_campaign(3_000)?;
    let directory = Directory::new()?;
    let store = ArtifactStore::open(&directory.0.join("state"))?;
    let profile = campaign.manifest.remediation.as_ref().unwrap();
    let finding = PublicFinding {
        revision: FindingRevision {
            candidate_id: campaign.accepted[0].id,
            candidate_payload_sha256: campaign.accepted[0].payload_hash.clone(),
            validation_id: campaign.accepted[1].id,
            validation_payload_sha256: campaign.accepted[1].payload_hash.clone(),
            workflow_decision_revision: 1,
        },
        claim: "fixture".into(),
        prerequisites: vec![],
        source: match &campaign.accepted[0].payload {
            Payload::Candidate { candidate } => candidate.source.clone(),
            _ => unreachable!(),
        },
        evidence: vec![],
        validation_evidence: vec![],
    };
    let replacement_content = store.write(b"package main\n", 100_000)?;
    let original = &profile.source_package.files[0];
    let original_bytes = git(&["show", &format!("{}:{}", original.commit, original.path)])?;
    let package_diff = replacement_diff(&original.path, &original_bytes, b"package main\n");
    let proposal = PatchGeneratorSubmission {
        schema_version: 1,
        authority: authority(&profile.generator, &profile.source_package.manifest_sha256),
        replacements: vec![FileReplacement {
            path: profile.source_package.files[0].path.clone(),
            original_sha256: Some(profile.source_package.files[0].content_sha256.clone()),
            replacement_sha256: replacement_content.sha256.clone(),
            replacement_bytes: replacement_content.bytes,
            content: replacement_content,
        }],
        unified_diff: ArtifactRef {
            sha256: digest(&package_diff),
            bytes: package_diff.len() as u64,
        },
        diagnostics: vec![],
    };
    let patch = PatchRecord {
        id: id(3_100),
        generation: 1,
        effect_id: id(3_101),
        plan_sha256: "1".repeat(64),
        patch_sha256: digest(&serde_json::to_vec(&serde_json::to_value(
            &proposal.replacements,
        )?)?),
        source_package_sha256: profile.source_package.manifest_sha256.clone(),
        worker: profile.generator.clone(),
        diff_sha256: digest(&package_diff),
        proposal,
    };
    let target = campaign
        .manifest
        .remediation
        .as_ref()
        .unwrap()
        .assertion
        .original_target
        .clone();
    let patched_target = TargetIdentity {
        source_sha256: digest(&serde_json::to_vec(&(
            1_u32,
            &profile.source_package.manifest_sha256,
            &patch.patch_sha256,
        ))?),
        build_sha256: "f".repeat(64),
        image_sha256: "e".repeat(64),
        environment_sha256: target.environment_sha256.clone(),
    };
    let evidence = evaluation_evidence(
        &store,
        &profile.assertion,
        &profile.source_package.manifest_sha256,
        &patch.patch_sha256,
        &patched_target,
    )?;
    let evaluator_workspace = digest(&serde_json::to_vec(&(
        1_u32,
        &profile.source_package.manifest_sha256,
        &patch.patch_sha256,
        &profile.assertion.assertion_sha256,
    ))?);
    let evaluation = EvaluationRecord {
        id: id(3_102),
        generation: 1,
        effect_id: id(3_103),
        plan_sha256: "3".repeat(64),
        source_package_sha256: profile.source_package.manifest_sha256.clone(),
        worker: profile.evaluator.clone(),
        assertion: profile.assertion.clone(),
        output: EvaluationOutput {
            verdict: EvaluationVerdict::Fixed,
            assertion_sha256: profile.assertion.assertion_sha256.clone(),
            patch_sha256: patch.patch_sha256.clone(),
            original_target: target,
            patched_target,
            authority: authority(&profile.evaluator, &evaluator_workspace),
            evidence,
            complete: true,
            diagnostics: vec![],
        },
    };
    let cleanup = RemediationCleanupReceipts {
        generator: CleanupReceipt {
            process_sha256: "5".repeat(64),
            workspace_sha256: profile.source_package.manifest_sha256.clone(),
            target_sha256: None,
            network_sha256: Some("7".repeat(64)),
            delayed_launches_settled: true,
            descendants_terminated: true,
        },
        evaluator: CleanupReceipt {
            process_sha256: "8".repeat(64),
            workspace_sha256: evaluator_workspace,
            target_sha256: Some("a".repeat(64)),
            network_sha256: Some("b".repeat(64)),
            delayed_launches_settled: true,
            descendants_terminated: true,
        },
    };
    let report = "# Remediation report\n\n## Finding evidence\nfixture\n\n## Original target\nfixture\n\n## Patched target\nfixture\n\n## Reproduction and tests\nfixture\n\n## Limitations\nfixture\n\n## Owner\nfixture\n\n## Reviewer outcome\nfixture\n\n## Remaining rollout work\nfixture\n";
    let first = RemediationPackage::build(
        &finding,
        &patch,
        &evaluation,
        &cleanup,
        &package_diff,
        report,
    )?;
    let mut retried_patch = patch.clone();
    retried_patch.id = id(3_200);
    retried_patch.effect_id = id(3_201);
    retried_patch.generation = 9;
    let mut retried_evaluation = evaluation.clone();
    retried_evaluation.id = id(3_202);
    retried_evaluation.effect_id = id(3_203);
    retried_evaluation.generation = 9;
    let second = RemediationPackage::build(
        &finding,
        &retried_patch,
        &retried_evaluation,
        &cleanup,
        &package_diff,
        report,
    )?;
    assert_eq!(first.package_id()?, second.package_id()?);
    let mut different_cleanup = cleanup;
    different_cleanup.evaluator.process_sha256 = "f".repeat(64);
    let third = RemediationPackage::build(
        &finding,
        &patch,
        &evaluation,
        &different_cleanup,
        &package_diff,
        report,
    )?;
    assert_ne!(first.package_id()?, third.package_id()?);
    let mut forged = first.clone();
    let mut evaluation_payload: RemediationEvaluationPayload =
        serde_json::from_slice(&forged.payloads["evaluation.json"])?;
    evaluation_payload
        .output
        .evidence
        .original_assertion
        .complete = false;
    let bytes = serde_json::to_vec(&serde_json::to_value(&evaluation_payload)?)?;
    forged
        .payloads
        .insert("evaluation.json".into(), bytes.clone());
    forged.manifest.files.insert(
        "evaluation.json".into(),
        PackagePayload {
            bytes: bytes.len() as u64,
            sha256: digest(&bytes),
            mode: 0o644,
        },
    );
    forged.manifest.evaluation_sha256 = digest(&bytes);
    assert!(forged.verify().is_err());
    assert!(!first.manifest.files.contains_key("manifest.json"));
    assert_eq!(first.manifest.files.len(), 5);
    Ok(())
}
