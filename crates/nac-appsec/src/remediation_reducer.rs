use crate::{
    artifacts::valid_hash,
    remediation::{find_case, is_current, stable_finding_key, valid_key, within_root},
    source::{git, safe_source_path},
    *,
};
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn record_remediation_observation(
        &self,
        run: Id,
        remediation: Id,
        observation: RecordRemediationObservation,
    ) -> Result<RemediationCase> {
        require_version(observation.schema_version)?;
        valid_key(&observation.key)?;
        let payload_sha256 = hash(&serde_json::to_vec(&(
            &observation.fence,
            &observation.output,
        ))?);
        let snapshot = self.repository.read(run)?;
        let case = find_case(&snapshot, remediation)?;
        if let Some(existing) = case
            .observations
            .values()
            .flatten()
            .find(|accepted| accepted.key == observation.key)
        {
            ensure!(
                existing.payload_sha256 == payload_sha256,
                "remediation observation idempotency conflict"
            );
            return Ok(case.clone());
        }
        let effect = case
            .effects
            .iter()
            .find(|effect| effect.fence.effect_id == observation.fence.effect_id)
            .context("unknown remediation effect")?;
        ensure!(
            effect.fence == observation.fence,
            "stale remediation effect fence"
        );
        validate_output(&self.artifacts, &snapshot, case, &observation)?;
        let package_artifacts =
            if let RemediationEffectOutput::PackageBuilt { package } = &observation.output {
                package
                    .payloads
                    .iter()
                    .map(|(name, bytes)| {
                        Ok((
                            name.clone(),
                            self.artifacts.write(
                                bytes,
                                snapshot
                                    .manifest
                                    .remediation
                                    .as_ref()
                                    .context("remediation profile missing")?
                                    .limits
                                    .output_bytes,
                            )?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?
            } else {
                BTreeMap::new()
            };
        let mut result = None;
        self.repository.update(run, None, &mut |campaign, _| {
            let now = self.clock.now_ms()?;
            let index = campaign
                .remediations
                .iter()
                .position(|case| case.id == remediation)
                .context("unknown remediation")?;
            validate_output(
                &self.artifacts,
                campaign,
                &campaign.remediations[index],
                &observation,
            )?;
            let current = is_current(campaign, &campaign.remediations[index]);
            let case = &mut campaign.remediations[index];
            if let Some(existing) = case
                .observations
                .values()
                .flatten()
                .find(|accepted| accepted.key == observation.key)
            {
                ensure!(
                    existing.payload_sha256 == payload_sha256,
                    "remediation observation idempotency conflict"
                );
                result = Some(case.clone());
                return Ok(());
            }
            let fence = case
                .effects
                .iter()
                .find(|effect| effect.fence.effect_id == observation.fence.effect_id)
                .context("unknown remediation effect")?
                .fence
                .clone();
            ensure!(fence == observation.fence, "stale remediation effect fence");
            let cleanup = matches!(
                observation.output,
                RemediationEffectOutput::CleanupSettled { .. }
            );
            if cleanup {
                ensure!(
                    !case.effect_settled(fence.effect_id),
                    "remediation effect cleanup already settled"
                );
                ensure!(
                    case.pending_effect()
                        .is_some_and(|pending| pending.fence.effect_id == fence.effect_id)
                        || case.effect_tombstoned(fence.effect_id),
                    "stale cleanup observation"
                );
                ensure!(
                    case.effect_tombstoned(fence.effect_id)
                        || case
                            .observations
                            .get(&fence.effect_id)
                            .is_some_and(|observations| {
                                observations.iter().any(|accepted| {
                                    !matches!(
                                        accepted.output,
                                        RemediationEffectOutput::CleanupSettled { .. }
                                    )
                                })
                            }),
                    "active remediation cleanup requires a recorded result or failure"
                );
            } else {
                ensure!(current, "remediation is superseded");
                ensure!(
                    fence.generation == case.generation()
                        && !case.effect_tombstoned(fence.effect_id)
                        && case
                            .pending_effect()
                            .is_some_and(|pending| { pending.fence.effect_id == fence.effect_id }),
                    "tombstoned or stale remediation observation"
                );
                ensure!(
                    !case
                        .observations
                        .get(&fence.effect_id)
                        .into_iter()
                        .flatten()
                        .any(|accepted| !matches!(
                            accepted.output,
                            RemediationEffectOutput::CleanupSettled { .. }
                        )),
                    "remediation effect already has a result"
                );
                append_result(case, fence.clone(), &observation.output, &package_artifacts)?;
            }
            case.observations.entry(fence.effect_id).or_default().push(
                AcceptedRemediationObservation {
                    key: observation.key.clone(),
                    payload_sha256: payload_sha256.clone(),
                    observed_ms: now,
                    output: observation.output.clone(),
                },
            );
            result = Some(case.clone());
            campaign.updated_ms = now;
            Ok(())
        })?;
        result.context("unknown remediation")
    }
}

fn append_result(
    case: &mut RemediationCase,
    fence: EffectFence,
    output: &RemediationEffectOutput,
    package_artifacts: &BTreeMap<String, ArtifactRef>,
) -> Result<()> {
    match output {
        RemediationEffectOutput::PatchProposed { proposal } => {
            case.patches.push(PatchRecord {
                id: Id::new(),
                generation: fence.generation,
                effect_id: fence.effect_id,
                plan_sha256: fence.plan_sha256,
                patch_sha256: hash(&crate::remediation_package::canonical_json(
                    &proposal.replacements,
                )?),
                source_package_sha256: case.provenance.inputs.source_package_sha256.clone(),
                worker: case.provenance.inputs.generator.clone(),
                diff_sha256: proposal.unified_diff.sha256.clone(),
                proposal: proposal.clone(),
            });
        }
        RemediationEffectOutput::EvaluationCompleted { evaluation } => {
            case.evaluations.push(EvaluationRecord {
                id: Id::new(),
                generation: fence.generation,
                effect_id: fence.effect_id,
                plan_sha256: fence.plan_sha256,
                source_package_sha256: case.provenance.inputs.source_package_sha256.clone(),
                worker: case.provenance.inputs.evaluator.clone(),
                assertion: case.provenance.assertion.clone(),
                output: evaluation.as_ref().clone(),
            });
        }
        RemediationEffectOutput::PackageBuilt { package } => {
            case.packages.push(PackageRecord {
                id: Id::new(),
                generation: fence.generation,
                effect_id: fence.effect_id,
                package_id: package.package_id()?,
                manifest: package.manifest.clone(),
                payloads: package_artifacts.clone(),
            });
        }
        RemediationEffectOutput::PublicationCompleted { publication } => {
            case.publications.push(PublicationRecord {
                id: Id::new(),
                generation: fence.generation,
                effect_id: fence.effect_id,
                output: publication.clone(),
            });
        }
        RemediationEffectOutput::Failed { .. } => {}
        RemediationEffectOutput::CleanupSettled { .. } => unreachable!(),
    }
    Ok(())
}

fn validate_output(
    artifacts: &ArtifactStore,
    campaign: &Campaign,
    case: &RemediationCase,
    observation: &RecordRemediationObservation,
) -> Result<()> {
    let profile = campaign
        .manifest
        .remediation
        .as_ref()
        .context("remediation profile missing")?;
    let effect = case
        .effects
        .iter()
        .find(|effect| effect.fence.effect_id == observation.fence.effect_id)
        .context("unknown remediation effect")?;
    ensure!(
        effect.fence == observation.fence,
        "stale remediation effect fence"
    );
    match &observation.output {
        RemediationEffectOutput::PatchProposed { proposal } => {
            ensure!(
                effect.fence.phase == RemediationPhase::GeneratePatch,
                "patch result is not valid for this phase"
            );
            validate_patch(artifacts, campaign, case, profile, proposal)?;
        }
        RemediationEffectOutput::EvaluationCompleted { evaluation } => {
            ensure!(
                effect.fence.phase == RemediationPhase::EvaluatePatch,
                "evaluation result is not valid for this phase"
            );
            let patch = case.current_patch().context("current patch missing")?;
            ensure!(
                effect.fence.patch_sha256.as_deref() == Some(&patch.patch_sha256)
                    && evaluation.patch_sha256 == patch.patch_sha256
                    && evaluation.assertion_sha256 == profile.assertion.assertion_sha256
                    && evaluation.original_target == profile.assertion.original_target,
                "evaluation provenance drift"
            );
            ensure!(
                valid_target(&evaluation.patched_target),
                "invalid patched target identity"
            );
            validate_authority(
                &evaluation.authority,
                &profile.evaluator,
                &evaluation_workspace_sha256(profile, patch)?,
            )?;
            ensure!(
                (evaluation.complete || evaluation.verdict == EvaluationVerdict::Inconclusive)
                    && (evaluation.verdict != EvaluationVerdict::Fixed
                        || (evaluation.original_target.source_sha256
                            != evaluation.patched_target.source_sha256
                            && evaluation_evidence_valid(
                                &evaluation.evidence,
                                &profile.assertion,
                                &profile.source_package.manifest_sha256,
                                &patch.patch_sha256,
                                &evaluation.original_target,
                                &evaluation.patched_target,
                                profile.limits.max_files,
                            ))),
                "fixed evaluation requires complete evidence, distinct targets and closed checks"
            );
            for artifact in evaluation_artifacts(&evaluation.evidence) {
                artifacts.verify(artifact)?;
            }
            validate_diagnostics(&evaluation.diagnostics)?;
        }
        RemediationEffectOutput::PackageBuilt { package } => {
            ensure!(
                effect.fence.phase == RemediationPhase::Package,
                "package result is not valid for this phase"
            );
            package.verify()?;
            let patch = case.current_patch().context("current patch missing")?;
            let evaluation = case
                .current_evaluation()
                .context("current evaluation missing")?;
            let cleanup = case
                .cleanup_receipts()
                .context("generator and evaluator cleanup receipts missing")?;
            let diff = artifacts.read_range(
                &patch.proposal.unified_diff,
                0,
                patch.proposal.unified_diff.bytes,
            )?;
            let expected = RemediationPackage::build(
                &public_finding(campaign, case)?,
                patch,
                evaluation,
                &cleanup,
                &diff,
                &crate::remediation_package::render_report(case, evaluation),
            )?;
            ensure!(
                evaluation.output.verdict == EvaluationVerdict::Fixed && package == &expected,
                "package bytes are not the canonical accepted remediation package"
            );
        }
        RemediationEffectOutput::PublicationCompleted { publication } => {
            ensure!(
                effect.fence.phase == RemediationPhase::PublishDraft
                    && case.status() == RemediationStatus::Approved,
                "publication is not authorized"
            );
            let target = case
                .publication_target()
                .context("publication was not requested")?;
            let package = case.current_package().context("current package missing")?;
            ensure!(
                publication.stable_finding_key
                    == stable_finding_key(target, &case.provenance.finding)?
                    && publication.package_id == package.package_id
                    && publication.base_commit == profile.base_commit
                    && publication.complete,
                "publication provenance drift"
            );
            if let Some(reference) = &publication.remote_reference_sha256 {
                ensure!(
                    valid_hash(reference),
                    "invalid publication reference digest"
                );
            }
            ensure!(
                match publication.outcome {
                    PublicationOutcome::DraftCreated | PublicationOutcome::DraftUpdated => {
                        publication.remote_reference_sha256.is_some()
                    }
                    PublicationOutcome::BaseDrift => {
                        publication.remote_reference_sha256.is_none()
                            && publication.diagnostics.iter().any(|diagnostic| {
                                diagnostic.code == RemediationDiagnosticCode::BaseDrift
                                    && diagnostic.complete
                            })
                    }
                },
                "publication outcome lacks its required closed evidence"
            );
            validate_diagnostics(&publication.diagnostics)?;
        }
        RemediationEffectOutput::Failed { diagnostics, .. } => {
            ensure!(
                !diagnostics.is_empty(),
                "failed effect requires a diagnostic"
            );
            validate_diagnostics(diagnostics)?;
        }
        RemediationEffectOutput::CleanupSettled { receipt } => {
            let expected_workspace = match effect.fence.phase {
                RemediationPhase::GeneratePatch => {
                    case.provenance.inputs.source_package_sha256.clone()
                }
                RemediationPhase::EvaluatePatch => evaluation_workspace_identity(
                    &case.provenance.inputs.source_package_sha256,
                    &case
                        .current_patch()
                        .context("current patch missing")?
                        .patch_sha256,
                    &case.provenance.assertion.assertion_sha256,
                )?,
                RemediationPhase::Package | RemediationPhase::PublishDraft => {
                    effect.fence.plan_sha256.clone()
                }
            };
            ensure!(
                receipt.delayed_launches_settled
                    && receipt.descendants_terminated
                    && receipt.workspace_sha256 == expected_workspace
                    && valid_hash(&receipt.process_sha256)
                    && valid_hash(&receipt.workspace_sha256)
                    && receipt
                        .network_sha256
                        .as_ref()
                        .is_some_and(|digest| valid_hash(digest))
                    && (effect.fence.phase != RemediationPhase::EvaluatePatch
                        || receipt
                            .target_sha256
                            .as_ref()
                            .is_some_and(|digest| valid_hash(digest)))
                    && receipt
                        .target_sha256
                        .as_ref()
                        .is_none_or(|digest| valid_hash(digest)),
                "cleanup receipt does not prove settled descendants, launches, workspace, target and network"
            );
        }
    }
    Ok(())
}

fn validate_patch(
    artifacts: &ArtifactStore,
    campaign: &Campaign,
    case: &RemediationCase,
    profile: &GoAuthorizationRemediationProfile,
    proposal: &PatchGeneratorSubmission,
) -> Result<()> {
    require_version(proposal.schema_version)?;
    ensure!(
        !proposal.replacements.is_empty()
            && proposal.replacements.len() <= profile.limits.max_files as usize,
        "patch replacement count exceeds the frozen policy"
    );
    artifacts.verify(&proposal.unified_diff)?;
    ensure!(
        proposal.unified_diff.bytes <= profile.limits.max_patch_bytes,
        "patch diff exceeds the frozen limit"
    );
    validate_diagnostics(&proposal.diagnostics)?;
    validate_authority(
        &proposal.authority,
        &profile.generator,
        &profile.source_package.manifest_sha256,
    )?;
    let candidate = campaign
        .accepted
        .iter()
        .find(|accepted| accepted.id == case.provenance.finding.candidate_id)
        .context("candidate missing")?;
    let Payload::Candidate { candidate } = &candidate.payload else {
        anyhow::bail!("candidate payload drift")
    };
    let mut paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    let mut total = 0_u64;
    for replacement in &proposal.replacements {
        ensure!(
            previous_path.is_none_or(|previous| previous < replacement.path.as_str()),
            "patch replacements must be in canonical path order"
        );
        previous_path = Some(&replacement.path);
        ensure!(
            safe_source_path(&replacement.path)
                && replacement.path.ends_with(".go")
                && !replacement.path.ends_with("_test.go")
                && !replacement.path.split('/').any(|part| {
                    matches!(part.to_ascii_lowercase().as_str(), "vendor" | "generated")
                })
                && profile
                    .editable_roots
                    .iter()
                    .any(|root| within_root(&replacement.path, root))
                && paths.insert(&replacement.path),
            "patch contains a duplicate or forbidden production path"
        );
        artifacts.verify(&replacement.content)?;
        ensure!(
            valid_hash(&replacement.replacement_sha256)
                && replacement.replacement_sha256 == replacement.content.sha256
                && replacement.replacement_bytes == replacement.content.bytes,
            "replacement content identity drift"
        );
        let original =
            profile.source_package.files.iter().find(|file| {
                file.repository == profile.repository && file.path == replacement.path
            });
        match (original, &replacement.original_sha256) {
            (Some(file), Some(digest)) => ensure!(
                digest == &file.content_sha256 && digest != &replacement.replacement_sha256,
                "replacement preimage mismatch or no-op"
            ),
            (None, None) => {}
            _ => anyhow::bail!("replacement does not carry the exact frozen preimage"),
        }
        total = total
            .checked_add(replacement.replacement_bytes)
            .context("patch size overflow")?;
    }
    ensure!(
        total <= profile.limits.max_patch_bytes,
        "replacement set exceeds the frozen patch limit"
    );
    ensure!(
        proposal
            .replacements
            .iter()
            .any(|replacement| replacement.path == candidate.source.path),
        "patch does not change the finding production path"
    );
    let expected_diff = canonical_patch_diff(artifacts, campaign, profile, proposal)?;
    let observed_diff =
        artifacts.read_range(&proposal.unified_diff, 0, proposal.unified_diff.bytes)?;
    ensure!(
        observed_diff == expected_diff,
        "unified diff is not the canonical replacement projection"
    );
    Ok(())
}

fn canonical_patch_diff(
    artifacts: &ArtifactStore,
    campaign: &Campaign,
    profile: &GoAuthorizationRemediationProfile,
    proposal: &PatchGeneratorSubmission,
) -> Result<Vec<u8>> {
    let mut output = String::new();
    for replacement in &proposal.replacements {
        let replacement_bytes =
            artifacts.read_range(&replacement.content, 0, replacement.content.bytes)?;
        let replacement_text = canonical_go_text(&replacement_bytes)?;
        let original =
            profile.source_package.files.iter().find(|file| {
                file.repository == profile.repository && file.path == replacement.path
            });
        let original_text = if let Some(file) = original {
            let repository = campaign
                .manifest
                .repositories
                .iter()
                .find(|repository| repository.identity == file.repository)
                .context("patch repository missing")?;
            let bytes = git(&repository.checkout, &["cat-file", "blob", &file.blob])?;
            ensure!(
                hash(&bytes) == file.content_sha256,
                "patch preimage source drift"
            );
            canonical_go_text(&bytes)?.to_owned()
        } else {
            String::new()
        };
        let original_lines = original_text.lines().count();
        let replacement_lines = replacement_text.lines().count();
        if original.is_some() {
            output.push_str(&format!("--- a/{}\n", replacement.path));
        } else {
            output.push_str("--- /dev/null\n");
        }
        output.push_str(&format!("+++ b/{}\n", replacement.path));
        output.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            usize::from(original_lines > 0),
            original_lines,
            usize::from(replacement_lines > 0),
            replacement_lines
        ));
        for line in original_text.lines() {
            output.push('-');
            output.push_str(line);
            output.push('\n');
        }
        for line in replacement_text.lines() {
            output.push('+');
            output.push_str(line);
            output.push('\n');
        }
    }
    Ok(output.into_bytes())
}

fn canonical_go_text(bytes: &[u8]) -> Result<&str> {
    let value = std::str::from_utf8(bytes)?;
    ensure!(
        value.ends_with('\n') && !value.contains('\r'),
        "Go patch content must be LF-only UTF-8 with a final newline"
    );
    Ok(value)
}

fn validate_diagnostics(diagnostics: &[PublicRemediationDiagnostic]) -> Result<()> {
    ensure!(diagnostics.len() <= 32, "diagnostic count exceeds bound");
    for diagnostic in diagnostics {
        ensure!(
            diagnostic
                .byte_offset
                .is_none_or(|offset| offset <= 16_777_216)
                && diagnostic
                    .artifact_sha256
                    .as_ref()
                    .is_none_or(|digest| valid_hash(digest)),
            "invalid public remediation diagnostic"
        );
    }
    Ok(())
}

fn valid_target(target: &TargetIdentity) -> bool {
    [
        &target.source_sha256,
        &target.build_sha256,
        &target.image_sha256,
        &target.environment_sha256,
    ]
    .iter()
    .all(|digest| valid_hash(digest))
}

fn validate_authority(
    receipt: &RemediationAuthorityReceipt,
    worker: &RemediationWorkerIdentity,
    workspace_sha256: &str,
) -> Result<()> {
    ensure!(
        [
            &receipt.tools_sha256,
            &receipt.mounts_sha256,
            &receipt.environment_sha256,
            &receipt.backend_sha256,
            &receipt.process_supervision_sha256,
            &receipt.workspace_sha256,
        ]
        .iter()
        .all(|digest| valid_hash(digest))
            && receipt.environment_sha256 == worker.environment_sha256
            && receipt.tools_sha256 == worker.tools_sha256
            && receipt.mounts_sha256 == worker.mounts_sha256
            && receipt.backend_sha256 == worker.backend_sha256
            && receipt.process_supervision_sha256 == worker.process_supervision_sha256
            && receipt.workspace_sha256 == workspace_sha256,
        "remediation execution authority drift"
    );
    Ok(())
}

fn evaluation_workspace_sha256(
    profile: &GoAuthorizationRemediationProfile,
    patch: &PatchRecord,
) -> Result<String> {
    evaluation_workspace_identity(
        &profile.source_package.manifest_sha256,
        &patch.patch_sha256,
        &profile.assertion.assertion_sha256,
    )
}

fn evaluation_workspace_identity(
    source_package_sha256: &str,
    patch_sha256: &str,
    assertion_sha256: &str,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        1_u32,
        source_package_sha256,
        patch_sha256,
        assertion_sha256,
    ))?))
}

fn evaluation_artifacts(evidence: &EvaluationEvidence) -> [&ArtifactRef; 8] {
    [
        &evidence.identities.artifact,
        &evidence.original_assertion.artifact,
        &evidence.patched_assertion.artifact,
        &evidence.original_legitimate_use.artifact,
        &evidence.patched_legitimate_use.artifact,
        &evidence.original_required_checks.artifact,
        &evidence.patched_required_checks.artifact,
        &evidence.structural_review.artifact,
    ]
}

pub(crate) fn evaluation_evidence_valid(
    evidence: &EvaluationEvidence,
    assertion: &EvaluatorAssertion,
    source_package_sha256: &str,
    patch_sha256: &str,
    original_target: &TargetIdentity,
    patched_target: &TargetIdentity,
    max_files: u32,
) -> bool {
    let expected_reason = match assertion.oracle_class {
        OracleClass::Authorization => SecurityFailureReason::UnauthorizedAccessObserved,
        OracleClass::RceNonce => SecurityFailureReason::CanaryDisclosureObserved,
    };
    let legitimate = |value: &LegitimateUseEvidence| {
        value.complete
            && value.health
            && value.public_access
            && value.owner_access
            && value.owner_write_readback
            && value.protected_route_bindings
    };
    let checks = |value: &RequiredChecksEvidence| {
        value.configuration_sha256 == assertion.required_checks_sha256
            && value.total > 0
            && value.passed == value.total
            && value.skipped == 0
            && !value.truncated
    };
    let Ok(patched_source_bytes) =
        serde_json::to_vec(&(1_u32, source_package_sha256, patch_sha256))
    else {
        return false;
    };
    let patched_source_sha256 = hash(&patched_source_bytes);
    evidence.identities.complete
        && evidence.identities.source_package_sha256 == source_package_sha256
        && evidence.identities.patch_sha256 == patch_sha256
        && &evidence.identities.original == original_target
        && &evidence.identities.patched == patched_target
        && evidence.identities.original == assertion.original_target
        && evidence.identities.patched.source_sha256 == patched_source_sha256
        && evidence.identities.patched.environment_sha256
            == assertion.original_target.environment_sha256
        && evidence.identities.effective_environment_sha256
            == assertion.original_target.environment_sha256
        && evidence.original_assertion.complete
        && evidence.original_assertion.violation_observed
        && evidence.original_assertion.expected_reason == Some(expected_reason)
        && evidence.patched_assertion.complete
        && !evidence.patched_assertion.violation_observed
        && evidence.patched_assertion.expected_reason.is_none()
        && legitimate(&evidence.original_legitimate_use)
        && legitimate(&evidence.patched_legitimate_use)
        && checks(&evidence.original_required_checks)
        && checks(&evidence.patched_required_checks)
        && evidence.structural_review.complete
        && (1..=max_files).contains(&evidence.structural_review.changed_files)
        && evidence.structural_review.production_change_nonempty
        && evidence.structural_review.protected_symbols_preserved
        && evidence.structural_review.route_bindings_preserved
        && evidence.structural_review.tests_unchanged
        && evidence.structural_review.assertions_unchanged
        && evidence.structural_review.fixtures_unchanged
        && evidence.structural_review.dependencies_unchanged
        && evidence.structural_review.check_configuration_unchanged
}

fn public_finding(campaign: &Campaign, case: &RemediationCase) -> Result<PublicFinding> {
    let accepted = campaign
        .accepted
        .iter()
        .find(|accepted| accepted.id == case.provenance.finding.candidate_id)
        .context("candidate missing")?;
    let Payload::Candidate { candidate } = &accepted.payload else {
        anyhow::bail!("candidate payload drift")
    };
    Ok(PublicFinding {
        revision: case.provenance.finding.clone(),
        claim: candidate.claim.clone(),
        prerequisites: candidate.prerequisites.clone(),
        source: candidate.source.clone(),
        evidence: accepted.evidence.clone(),
        validation_evidence: campaign
            .accepted
            .iter()
            .find(|accepted| accepted.id == case.provenance.finding.validation_id)
            .context("validation missing")?
            .evidence
            .clone(),
    })
}
