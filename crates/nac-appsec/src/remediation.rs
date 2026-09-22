use crate::{artifacts::valid_hash, source::safe_source_path, *};
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};

impl GoAuthorizationRemediationProfile {
    pub(crate) fn verify(&self, manifest: &Manifest) -> Result<()> {
        require_version(self.schema_version)?;
        let repository = manifest
            .repositories
            .iter()
            .find(|repository| repository.identity == self.repository)
            .context("remediation repository is not pinned")?;
        ensure!(
            repository.commit == self.base_commit,
            "remediation base differs from the pinned repository commit"
        );
        self.source_package.verify(&manifest.repositories)?;
        ensure!(
            self.source_package
                .files
                .iter()
                .all(|file| file.repository == self.repository),
            "the Go pilot supports one remediation repository"
        );
        let mut dependencies = BTreeSet::new();
        for dependency in &self.dependencies {
            dependency.verify_provenance()?;
            ensure!(
                dependencies.insert((
                    &dependency.package,
                    &dependency.version,
                    &dependency.archive_sha256,
                )),
                "duplicate remediation dependency"
            );
        }
        ensure!(
            !self.editable_roots.is_empty()
                && self.editable_roots.len() <= 16
                && self
                    .editable_roots
                    .iter()
                    .all(|root| safe_source_path(root)),
            "invalid remediation editable roots"
        );
        ensure!(
            self.source_package.files.iter().any(|file| {
                file.path.ends_with(".go")
                    && self
                        .editable_roots
                        .iter()
                        .any(|root| within_root(&file.path, root))
            }),
            "remediation package has no editable production Go source"
        );
        for digest in [&self.configuration_sha256, &self.skill_bundle_sha256] {
            ensure!(valid_hash(digest), "invalid remediation input digest");
        }
        self.generator.verify()?;
        self.evaluator.verify()?;
        self.assertion.verify()?;
        ensure!(
            self.assertion.original_target.source_sha256 == self.source_package.manifest_sha256,
            "evaluator target is not derived from the remediation source package"
        );
        ensure!(
            (1..=300_000).contains(&self.limits.operation_ms)
                && (1..=16_777_216).contains(&self.limits.output_bytes)
                && (1..=64).contains(&self.limits.max_files)
                && (1..=16_777_216).contains(&self.limits.max_patch_bytes),
            "invalid remediation operation limits"
        );
        Ok(())
    }
}

impl RemediationWorkerIdentity {
    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            [&self.model, &self.runtime, &self.extractor]
                .iter()
                .all(|value| !value.trim().is_empty() && value.len() <= 256),
            "invalid remediation worker identity"
        );
        ensure!(
            [
                &self.prompt_sha256,
                &self.environment_sha256,
                &self.tools_sha256,
                &self.mounts_sha256,
                &self.backend_sha256,
                &self.process_supervision_sha256,
            ]
            .iter()
            .all(|digest| valid_hash(digest)),
            "invalid remediation worker digest"
        );
        Ok(())
    }
}

impl EvaluatorAssertion {
    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&(
            1_u32,
            &self.version,
            &self.recipe_id,
            &self.recipe_sha256,
            self.oracle_class,
            &self.oracle_sha256,
            &self.rubric_sha256,
            &self.fixture_sha256,
            &self.required_checks_sha256,
            &self.original_target,
        ))?))
    }

    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            !self.version.trim().is_empty()
                && self.version.len() <= 128
                && !self.recipe_id.trim().is_empty()
                && self.recipe_id.len() <= 128,
            "invalid evaluator assertion identity"
        );
        for digest in [
            &self.assertion_sha256,
            &self.recipe_sha256,
            &self.oracle_sha256,
            &self.rubric_sha256,
            &self.fixture_sha256,
            &self.required_checks_sha256,
            &self.original_target.source_sha256,
            &self.original_target.build_sha256,
            &self.original_target.image_sha256,
            &self.original_target.environment_sha256,
        ] {
            ensure!(valid_hash(digest), "invalid evaluator assertion digest");
        }
        ensure!(
            self.assertion_sha256 == self.canonical_sha256()?,
            "evaluator assertion identity drift"
        );
        Ok(())
    }
}

impl RemediationCase {
    pub fn generation(&self) -> u32 {
        self.journal
            .iter()
            .map(|entry| match entry {
                RemediationJournalEntry::Opened { generation, .. }
                | RemediationJournalEntry::Tombstoned { generation, .. }
                | RemediationJournalEntry::Recovered { generation, .. }
                | RemediationJournalEntry::Reviewed { generation, .. }
                | RemediationJournalEntry::PublicationRequested { generation, .. } => *generation,
            })
            .max()
            .unwrap_or(1)
    }

    pub fn status(&self) -> RemediationStatus {
        let generation = self.generation();
        if self.publications.iter().rev().any(|publication| {
            publication.generation == generation
                && self.effect_settled(publication.effect_id)
                && matches!(
                    publication.output.outcome,
                    PublicationOutcome::DraftCreated | PublicationOutcome::DraftUpdated
                )
        }) {
            return RemediationStatus::Published;
        }
        if let Some(review) = self.journal.iter().rev().find_map(|entry| match entry {
            RemediationJournalEntry::Reviewed {
                generation: reviewed_generation,
                review,
                ..
            } if *reviewed_generation == generation
                && self
                    .current_package()
                    .is_some_and(|package| package.package_id == review.package_id) =>
            {
                Some(review)
            }
            _ => None,
        }) {
            return match review.decision {
                ApprovalDecision::Approved => RemediationStatus::Approved,
                ApprovalDecision::Rejected => RemediationStatus::Rejected,
            };
        }
        let evaluation = self
            .evaluations
            .iter()
            .rev()
            .find(|evaluation| evaluation.generation == generation);
        if let Some(evaluation) = evaluation {
            if evaluation.output.verdict == EvaluationVerdict::Fixed
                && self.effect_settled(evaluation.effect_id)
            {
                if self.packages.iter().any(|package| {
                    package.generation == generation && self.effect_settled(package.effect_id)
                }) {
                    return RemediationStatus::ReviewRequired;
                }
                return RemediationStatus::TestsPassed;
            }
            if !matches!(
                evaluation.output.verdict,
                EvaluationVerdict::Fixed
                    | EvaluationVerdict::Inconclusive
                    | EvaluationVerdict::Drift
            ) {
                return RemediationStatus::Rejected;
            }
        }
        if self
            .patches
            .iter()
            .any(|patch| patch.generation == generation)
        {
            RemediationStatus::Proposed
        } else {
            RemediationStatus::NotStarted
        }
    }

    pub(crate) fn effect_settled(&self, effect: Id) -> bool {
        self.observations.get(&effect).is_some_and(|observations| {
            observations.iter().any(|observation| {
                matches!(
                    observation.output,
                    RemediationEffectOutput::CleanupSettled { .. }
                )
            })
        })
    }

    pub(crate) fn effect_tombstoned(&self, effect: Id) -> bool {
        self.journal.iter().any(|entry| {
            matches!(entry, RemediationJournalEntry::Tombstoned { effect_id: Some(id), .. } if *id == effect)
        })
    }

    pub(crate) fn pending_effect(&self) -> Option<&RemediationEffectIntent> {
        self.effects
            .iter()
            .rev()
            .find(|effect| !self.effect_settled(effect.fence.effect_id))
    }

    pub(crate) fn current_patch(&self) -> Option<&PatchRecord> {
        let generation = self.generation();
        self.patches
            .iter()
            .rev()
            .find(|patch| patch.generation == generation)
    }

    pub(crate) fn current_evaluation(&self) -> Option<&EvaluationRecord> {
        let generation = self.generation();
        self.evaluations
            .iter()
            .rev()
            .find(|evaluation| evaluation.generation == generation)
    }

    pub(crate) fn current_package(&self) -> Option<&PackageRecord> {
        let generation = self.generation();
        self.packages
            .iter()
            .rev()
            .find(|package| package.generation == generation)
    }

    pub(crate) fn cleanup_receipt(&self, phase: RemediationPhase) -> Option<&CleanupReceipt> {
        let generation = self.generation();
        let effect =
            self.effects.iter().rev().find(|effect| {
                effect.fence.generation == generation && effect.fence.phase == phase
            })?;
        self.observations
            .get(&effect.fence.effect_id)?
            .iter()
            .find_map(|observation| match &observation.output {
                RemediationEffectOutput::CleanupSettled { receipt } => Some(receipt),
                _ => None,
            })
    }

    pub(crate) fn cleanup_receipts(&self) -> Option<RemediationCleanupReceipts> {
        Some(RemediationCleanupReceipts {
            generator: self
                .cleanup_receipt(RemediationPhase::GeneratePatch)?
                .clone(),
            evaluator: self
                .cleanup_receipt(RemediationPhase::EvaluatePatch)?
                .clone(),
        })
    }

    pub(crate) fn publication_target(&self) -> Option<&PublicationTarget> {
        let generation = self.generation();
        self.journal.iter().rev().find_map(|entry| match entry {
            RemediationJournalEntry::PublicationRequested {
                generation: requested_generation,
                target,
                ..
            } if *requested_generation == generation => Some(target),
            _ => None,
        })
    }
}

impl Campaign {
    pub fn occupied_remediation_workers(&self) -> usize {
        self.remediations
            .iter()
            .flat_map(|case| &case.effects)
            .filter(|effect| {
                effect.fence.phase == RemediationPhase::GeneratePatch
                    && !self
                        .remediations
                        .iter()
                        .find(|case| {
                            case.effects
                                .iter()
                                .any(|item| item.fence.effect_id == effect.fence.effect_id)
                        })
                        .is_some_and(|case| case.effect_settled(effect.fence.effect_id))
            })
            .count()
    }

    pub(crate) fn occupied_remediation_targets(&self) -> usize {
        self.remediations
            .iter()
            .map(|case| {
                case.effects
                    .iter()
                    .filter(|effect| {
                        effect.fence.phase == RemediationPhase::EvaluatePatch
                            && !case.effect_settled(effect.fence.effect_id)
                    })
                    .count()
            })
            .sum()
    }
}

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn remediation_provenance(&self, run: Id, candidate: Id) -> Result<RemediationProvenance> {
        derive_provenance(&self.repository.read(run)?, candidate)
    }

    pub fn request_remediation(
        &self,
        run: Id,
        expected_revision: u64,
        request: StartRemediation,
    ) -> Result<RemediationCase> {
        require_version(request.schema_version)?;
        valid_key(&request.key)?;
        let request_sha256 = hash(&serde_json::to_vec(&request)?);
        let mut result = None;
        self.repository
            .update(run, Some(expected_revision), &mut |campaign, _| {
                if let Some(existing) = campaign
                    .remediations
                    .iter()
                    .find(|case| case.key == request.key)
                {
                    ensure!(
                        existing.request_sha256 == request_sha256,
                        "remediation request idempotency conflict"
                    );
                    result = Some(existing.clone());
                    return Ok(());
                }
                let now = self.clock.now_ms()?;
                let expected =
                    derive_provenance(campaign, request.provenance.finding.candidate_id)?;
                ensure!(
                    expected == request.provenance,
                    "remediation provenance drift"
                );
                validate_assertion_review(campaign, &request, now)?;
                let mut case = RemediationCase {
                    schema_version: 1,
                    id: Id::new(),
                    key: request.key.clone(),
                    request_sha256: request_sha256.clone(),
                    created_ms: now,
                    provenance: request.provenance.clone(),
                    assertion_review: request.assertion_review.clone(),
                    journal: vec![RemediationJournalEntry::Opened {
                        generation: 1,
                        at_ms: now,
                    }],
                    effects: vec![],
                    observations: Default::default(),
                    patches: vec![],
                    evaluations: vec![],
                    packages: vec![],
                    publications: vec![],
                };
                append_effect(campaign, &mut case, now)?;
                result = Some(case.clone());
                campaign.remediations.push(case);
                campaign.updated_ms = now;
                Ok(())
            })?;
        result.context("remediation request was not recorded")
    }

    pub fn read_remediation(&self, run: Id, remediation: Id) -> Result<RemediationCaseView> {
        let campaign = self.repository.read(run)?;
        let case = find_case(&campaign, remediation)?.clone();
        let current = is_current(&campaign, &case);
        let publication_ready = current
            && case.status() == RemediationStatus::Approved
            && case.current_package().is_some()
            && case
                .publications
                .iter()
                .all(|publication| publication.generation != case.generation());
        Ok(RemediationCaseView {
            status: case.status(),
            freshness: if current {
                RemediationFreshness::Current
            } else {
                RemediationFreshness::Superseded
            },
            publication_ready,
            case,
        })
    }

    pub fn materialize_remediation_package(
        &self,
        run: Id,
        package_id: Id,
        destination: &std::path::Path,
    ) -> Result<RemediationPackage> {
        let campaign = self.repository.read(run)?;
        let record = campaign
            .remediations
            .iter()
            .flat_map(|case| &case.packages)
            .find(|package| package.id == package_id)
            .context("unknown remediation package")?;
        let mut payloads = BTreeMap::new();
        for (name, reference) in &record.payloads {
            payloads.insert(
                name.clone(),
                self.artifacts.read_range(reference, 0, reference.bytes)?,
            );
        }
        let package = RemediationPackage {
            manifest: record.manifest.clone(),
            payloads,
        };
        ensure!(
            package.package_id()? == record.package_id,
            "stored remediation package identity drift"
        );
        package.materialize(destination)?;
        Ok(package)
    }

    pub fn desired_remediation_effect(
        &self,
        run: Id,
        remediation: Id,
        expected_revision: u64,
    ) -> Result<Option<RemediationDesiredEffect>> {
        let snapshot = self.repository.read(run)?;
        let existing = find_case(&snapshot, remediation)?;
        if is_current(&snapshot, existing) {
            if let Some(effect) = existing.pending_effect() {
                return Ok(Some(desired(&snapshot, existing, effect)?));
            }
        }
        if existing.pending_effect().is_some() && expected_revision != snapshot.revision {
            anyhow::bail!(
                "revision conflict: expected {expected_revision}, current {}",
                snapshot.revision
            );
        }
        let mut result = None;
        self.repository
            .update(run, Some(expected_revision), &mut |campaign, _| {
                let index = campaign
                    .remediations
                    .iter()
                    .position(|case| case.id == remediation)
                    .context("unknown remediation")?;
                let mut case = campaign.remediations.remove(index);
                if !is_current(campaign, &case) {
                    if let Some(effect_id) =
                        case.pending_effect().map(|effect| effect.fence.effect_id)
                    {
                        let generation = case.generation();
                        if !case.effect_tombstoned(effect_id) {
                            case.journal.push(RemediationJournalEntry::Tombstoned {
                                generation,
                                effect_id: Some(effect_id),
                                reason: RemediationTombstoneReason::Superseded,
                                at_ms: self.clock.now_ms()?,
                            });
                        }
                        result = case
                            .pending_effect()
                            .map(|effect| desired(campaign, &case, effect))
                            .transpose()?;
                    }
                    campaign.remediations.insert(index, case);
                    return Ok(());
                }
                if case.pending_effect().is_none() && next_phase(&case).is_some() {
                    append_effect(campaign, &mut case, self.clock.now_ms()?)?;
                }
                result = case
                    .pending_effect()
                    .map(|effect| desired(campaign, &case, effect))
                    .transpose()?;
                campaign.remediations.insert(index, case);
                Ok(())
            })?;
        Ok(result)
    }

    pub fn cancel_remediation(
        &self,
        run: Id,
        remediation: Id,
        expected_revision: u64,
    ) -> Result<RemediationCase> {
        update_case(self, run, remediation, expected_revision, |case, now| {
            let generation = case.generation();
            let effect_id = case.pending_effect().map(|effect| effect.fence.effect_id);
            if !case.journal.iter().any(|entry| matches!(entry, RemediationJournalEntry::Tombstoned { generation: old, reason: RemediationTombstoneReason::OperatorCancellation, .. } if *old == generation)) {
                case.journal.push(RemediationJournalEntry::Tombstoned {
                    generation,
                    effect_id,
                    reason: RemediationTombstoneReason::OperatorCancellation,
                    at_ms: now,
                });
            }
            Ok(())
        })
    }

    pub fn recover_remediation(
        &self,
        run: Id,
        remediation: Id,
        expected_revision: u64,
    ) -> Result<RemediationCase> {
        let mut result = None;
        self.repository
            .update(run, Some(expected_revision), &mut |campaign, _| {
                let index = campaign
                    .remediations
                    .iter()
                    .position(|case| case.id == remediation)
                    .context("unknown remediation")?;
                let mut case = campaign.remediations.remove(index);
                ensure!(is_current(campaign, &case), "remediation is superseded");
                let now = self.clock.now_ms()?;
                let effect = case.effects.last().context("remediation has no effect")?;
                ensure!(
                    effect.fence.generation == case.generation(),
                    "the stopped effect has already been recovered"
                );
                ensure!(
                    case.effect_settled(effect.fence.effect_id),
                    "cleanup must settle before recovery"
                );
                let recoverable = case
                    .observations
                    .get(&effect.fence.effect_id)
                    .into_iter()
                    .flatten()
                    .any(|observation| {
                        matches!(
                            observation.output,
                            RemediationEffectOutput::Failed {
                                recovery_required: true,
                                ..
                            }
                        )
                    });
                ensure!(recoverable, "recovery requires a diagnosed stopped effect");
                let generation = case
                    .generation()
                    .checked_add(1)
                    .context("generation overflow")?;
                case.journal.push(RemediationJournalEntry::Recovered {
                    generation,
                    at_ms: now,
                });
                result = Some(case.clone());
                campaign.remediations.insert(index, case);
                campaign.updated_ms = now;
                Ok(())
            })?;
        result.context("unknown remediation")
    }

    pub fn approve_remediation(
        &self,
        run: Id,
        remediation: Id,
        expected_revision: u64,
        approval: RemediationApproval,
    ) -> Result<RemediationCase> {
        require_version(approval.schema_version)?;
        let mut result = None;
        self.repository
            .update(run, Some(expected_revision), &mut |campaign, _| {
                let index = campaign
                    .remediations
                    .iter()
                    .position(|case| case.id == remediation)
                    .context("unknown remediation")?;
                let mut case = campaign.remediations.remove(index);
                ensure!(is_current(campaign, &case), "remediation is superseded");
                ensure!(
                    case.status() == RemediationStatus::ReviewRequired,
                    "remediation is not ready for review"
                );
                let package = case.current_package().context("current package missing")?;
                ensure!(
                    approval.generation == case.generation()
                        && case.effect_settled(package.effect_id)
                        && approval.package_id == package.package_id
                        && approval.finding == case.provenance.finding
                        && approval.assertion_sha256 == case.provenance.assertion.assertion_sha256
                        && !approval.reviewer.trim().is_empty(),
                    "approval is not bound to the current package and provenance"
                );
                let now = self.clock.now_ms()?;
                if let Some(existing) = case.journal.iter().rev().find_map(|entry| match entry {
                    RemediationJournalEntry::Reviewed {
                        generation, review, ..
                    } if *generation == approval.generation => Some(review),
                    _ => None,
                }) {
                    ensure!(existing == &approval, "remediation review conflict");
                } else {
                    case.journal.push(RemediationJournalEntry::Reviewed {
                        generation: approval.generation,
                        review: approval.clone(),
                        at_ms: now,
                    });
                }
                result = Some(case.clone());
                campaign.remediations.insert(index, case);
                campaign.updated_ms = now;
                Ok(())
            })?;
        result.context("unknown remediation")
    }

    pub fn request_remediation_publication(
        &self,
        run: Id,
        remediation: Id,
        expected_revision: u64,
        target: PublicationTarget,
    ) -> Result<RemediationCase> {
        ensure!(
            !target.provider.trim().is_empty()
                && target.provider.len() <= 128
                && !target.repository.trim().is_empty()
                && target.repository.len() <= 512,
            "invalid remediation publication target"
        );
        let mut result = None;
        self.repository
            .update(run, Some(expected_revision), &mut |campaign, _| {
                let index = campaign
                    .remediations
                    .iter()
                    .position(|case| case.id == remediation)
                    .context("unknown remediation")?;
                let mut case = campaign.remediations.remove(index);
                ensure!(is_current(campaign, &case), "remediation is superseded");
                ensure!(
                    case.status() == RemediationStatus::Approved,
                    "remediation is not approved"
                );
                let now = self.clock.now_ms()?;
                let generation = case.generation();
                if let Some(existing) = case.publication_target() {
                    ensure!(
                        existing == &target,
                        "remediation publication target conflict"
                    );
                } else {
                    case.journal
                        .push(RemediationJournalEntry::PublicationRequested {
                            generation,
                            target: target.clone(),
                            at_ms: now,
                        });
                }
                result = Some(case.clone());
                campaign.remediations.insert(index, case);
                campaign.updated_ms = now;
                Ok(())
            })?;
        result.context("unknown remediation")
    }
}

pub(crate) fn derive_provenance(
    campaign: &Campaign,
    candidate_id: Id,
) -> Result<RemediationProvenance> {
    let profile = campaign
        .manifest
        .remediation
        .as_ref()
        .context("remediation is not enabled")?;
    let workflow = campaign
        .workflow
        .as_ref()
        .context("remediation requires workflow evidence")?;
    let candidate = campaign
        .accepted
        .iter()
        .find(|accepted| {
            accepted.id == candidate_id && matches!(accepted.payload, Payload::Candidate { .. })
        })
        .context("accepted candidate unavailable")?;
    let validation_task = workflow
        .candidate_validators
        .get(&candidate_id)
        .copied()
        .context("candidate has no independent validator")?;
    let validation = campaign
        .accepted
        .iter()
        .rev()
        .find(|accepted| {
            accepted.task_id == validation_task
                && matches!(
                    accepted.payload,
                    Payload::Workflow {
                        action: WorkflowAction::Validate { .. },
                        ..
                    }
                )
        })
        .context("candidate has no accepted validation")?;
    let Payload::Workflow {
        revision,
        action: WorkflowAction::Validate {
            validation: verdict,
        },
    } = &validation.payload
    else {
        unreachable!()
    };
    ensure!(
        verdict.outcome == ValidationOutcome::Supported && verdict.is_resolved(),
        "latest accepted validation is not supportive and resolved"
    );
    let candidate_inputs = workflow
        .jobs
        .get(&candidate.task_id)
        .and_then(|job| job.effective_inputs.get(&candidate.attempt_id))
        .context("candidate effective inputs were not recorded")?;
    let validation_inputs = workflow
        .jobs
        .get(&validation.task_id)
        .and_then(|job| job.effective_inputs.get(&validation.attempt_id))
        .context("validation effective inputs were not recorded")?;
    let Payload::Candidate {
        candidate: candidate_finding,
    } = &candidate.payload
    else {
        unreachable!()
    };
    ensure!(
        profile.source_package.files.iter().any(|file| {
            file.repository == candidate_finding.source.repository
                && file.commit == candidate_finding.source.commit
                && file.path == candidate_finding.source.path
                && file.content_sha256 == candidate_finding.source.content_sha256
        }),
        "finding source is not an exact member of the remediation source package"
    );
    Ok(RemediationProvenance {
        finding: FindingRevision {
            candidate_id,
            candidate_payload_sha256: candidate.payload_hash.clone(),
            validation_id: validation.id,
            validation_payload_sha256: validation.payload_hash.clone(),
            workflow_decision_revision: *revision,
        },
        inputs: RemediationInputIdentity {
            repository: profile.repository.clone(),
            base_commit: profile.base_commit.clone(),
            source_package_sha256: profile.source_package.manifest_sha256.clone(),
            dependencies_sha256: hash(&serde_json::to_vec(&profile.dependencies)?),
            declared_inputs_sha256: hash(&serde_json::to_vec(&campaign.manifest.declared_inputs)?),
            campaign_configuration_sha256: campaign.configuration_hash.clone(),
            configuration_sha256: profile.configuration_sha256.clone(),
            skill_bundle_sha256: profile.skill_bundle_sha256.clone(),
            generator: profile.generator.clone(),
            evaluator: profile.evaluator.clone(),
            candidate_effective_inputs: candidate_inputs.clone(),
            validation_effective_inputs: validation_inputs.clone(),
        },
        assertion: profile.assertion.clone(),
    })
}

pub(crate) fn is_current(campaign: &Campaign, case: &RemediationCase) -> bool {
    derive_provenance(campaign, case.provenance.finding.candidate_id)
        .is_ok_and(|current| current == case.provenance)
}

fn validate_assertion_review(
    campaign: &Campaign,
    request: &StartRemediation,
    now: u64,
) -> Result<()> {
    let workflow = campaign.workflow.as_ref().context("workflow missing")?;
    let state = workflow.finding_evidence_state(campaign, request.provenance.finding.candidate_id);
    ensure!(
        matches!(
            state,
            EvidenceState::StaticSupported | EvidenceState::Reproduced
        ),
        "finding lacks supportive accepted evidence"
    );
    let validation = campaign
        .accepted
        .iter()
        .find(|accepted| accepted.id == request.provenance.finding.validation_id)
        .context("accepted validation unavailable")?;
    let Payload::Workflow {
        action: WorkflowAction::Validate { validation },
        ..
    } = &validation.payload
    else {
        anyhow::bail!("accepted validation payload changed")
    };
    let exact_reproduction = state == EvidenceState::Reproduced
        && !validation.experiments.is_empty()
        && validation.experiments.iter().all(|id| {
            campaign
                .experiments
                .iter()
                .find(|experiment| experiment.id == *id)
                .is_some_and(|experiment| {
                    experiment.recipe.id == request.provenance.assertion.recipe_id
                        && experiment.recipe.recipe_sha256
                            == request.provenance.assertion.recipe_sha256
                        && experiment.recipe.oracle_class
                            == request.provenance.assertion.oracle_class
                        && experiment.recipe.target == request.provenance.assertion.original_target
                        && experiment.trials.iter().all(|trial| {
                            trial.execution_receipt.as_ref().is_some_and(|receipt| {
                                receipt.evaluator_sha256
                                    == request.provenance.assertion.oracle_sha256
                            })
                        })
                })
        });
    let replacement = campaign.remediations.iter().any(|case| {
        case.provenance.finding.candidate_id == request.provenance.finding.candidate_id
            && case.provenance.assertion.assertion_sha256
                != request.provenance.assertion.assertion_sha256
    });
    let required = if replacement {
        Some(AssertionReviewReason::AssertionReplacement)
    } else if state == EvidenceState::StaticSupported {
        Some(AssertionReviewReason::StaticSupported)
    } else if exact_reproduction {
        None
    } else {
        Some(AssertionReviewReason::ReproductionSubstitution)
    };
    if let Some(reason) = required {
        let review = request
            .assertion_review
            .as_ref()
            .context("explicit assertion review required")?;
        ensure!(
            review.reason == reason
                && review.candidate_id == request.provenance.finding.candidate_id
                && review.validation_id == request.provenance.finding.validation_id
                && review.assertion_version == request.provenance.assertion.version
                && review.assertion_sha256 == request.provenance.assertion.assertion_sha256
                && !review.reviewer.trim().is_empty()
                && review.reviewed_ms <= now,
            "assertion review is not bound to the accepted finding and assertion version"
        );
    } else {
        ensure!(
            request.assertion_review.is_none(),
            "unnecessary assertion substitution review"
        );
    }
    Ok(())
}

fn append_effect(campaign: &Campaign, case: &mut RemediationCase, now: u64) -> Result<()> {
    ensure!(
        case.pending_effect().is_none(),
        "remediation already has a pending effect"
    );
    let phase = next_phase(case).context("remediation has no desired effect")?;
    let plan = build_plan(campaign, case, phase)?;
    let patch_sha256 = case.current_patch().map(|patch| patch.patch_sha256.clone());
    case.effects.push(RemediationEffectIntent {
        fence: EffectFence {
            effect_id: Id::new(),
            generation: case.generation(),
            phase,
            plan_sha256: hash(&serde_json::to_vec(&plan)?),
            patch_sha256,
        },
        requested_ms: now,
        plan,
    });
    Ok(())
}

fn next_phase(case: &RemediationCase) -> Option<RemediationPhase> {
    let generation = case.generation();
    if case.journal.iter().any(|entry| matches!(entry, RemediationJournalEntry::Tombstoned { generation: old, .. } if *old == generation)) {
        return None;
    }
    let last = case
        .effects
        .iter()
        .rev()
        .find(|effect| effect.fence.generation == generation);
    if let Some(effect) = last {
        let output = case
            .observations
            .get(&effect.fence.effect_id)
            .into_iter()
            .flatten();
        if output
            .clone()
            .any(|observation| matches!(observation.output, RemediationEffectOutput::Failed { .. }))
        {
            return None;
        }
    }
    let Some(patch) = case.current_patch() else {
        return Some(RemediationPhase::GeneratePatch);
    };
    let Some(evaluation) = case.current_evaluation() else {
        return Some(RemediationPhase::EvaluatePatch);
    };
    if evaluation.output.verdict != EvaluationVerdict::Fixed {
        return None;
    }
    let Some(_) = case.current_package() else {
        return Some(RemediationPhase::Package);
    };
    if case.status() == RemediationStatus::Approved
        && case.publication_target().is_some()
        && case
            .publications
            .iter()
            .all(|publication| publication.generation != generation)
    {
        return Some(RemediationPhase::PublishDraft);
    }
    let _ = patch;
    None
}

fn desired(
    campaign: &Campaign,
    case: &RemediationCase,
    effect: &RemediationEffectIntent,
) -> Result<RemediationDesiredEffect> {
    ensure!(
        hash(&serde_json::to_vec(&effect.plan)?) == effect.fence.plan_sha256,
        "remediation plan drift"
    );
    Ok(RemediationDesiredEffect {
        remediation_id: case.id,
        fence: effect.fence.clone(),
        stop: case.effect_tombstoned(effect.fence.effect_id)
            || !is_current(campaign, case)
            || case
                .observations
                .get(&effect.fence.effect_id)
                .is_some_and(|observations| {
                    observations.iter().any(|observation| {
                        !matches!(
                            observation.output,
                            RemediationEffectOutput::CleanupSettled { .. }
                        )
                    })
                }),
        plan: effect.plan.clone(),
    })
}

fn build_plan(
    campaign: &Campaign,
    case: &RemediationCase,
    phase: RemediationPhase,
) -> Result<RemediationEffectPlan> {
    let profile = campaign
        .manifest
        .remediation
        .as_ref()
        .context("remediation profile missing")?;
    let candidate = campaign
        .accepted
        .iter()
        .find(|accepted| accepted.id == case.provenance.finding.candidate_id)
        .context("candidate missing")?;
    let Payload::Candidate { candidate: finding } = &candidate.payload else {
        anyhow::bail!("finding payload drift")
    };
    let public = PublicFinding {
        revision: case.provenance.finding.clone(),
        claim: finding.claim.clone(),
        prerequisites: finding.prerequisites.clone(),
        source: finding.source.clone(),
        evidence: candidate.evidence.clone(),
        validation_evidence: campaign
            .accepted
            .iter()
            .find(|accepted| accepted.id == case.provenance.finding.validation_id)
            .context("validation missing")?
            .evidence
            .clone(),
    };
    Ok(match phase {
        RemediationPhase::GeneratePatch => RemediationEffectPlan::GeneratePatch {
            finding: public,
            source_package: profile.source_package.clone(),
            dependencies: profile.dependencies.clone(),
            editable_roots: profile.editable_roots.clone(),
            worker: profile.generator.clone(),
            limits: profile.limits,
        },
        RemediationPhase::EvaluatePatch => RemediationEffectPlan::EvaluatePatch {
            source_package: profile.source_package.clone(),
            dependencies: profile.dependencies.clone(),
            patch: case
                .current_patch()
                .context("current patch missing")?
                .clone(),
            assertion: profile.assertion.clone(),
            worker: profile.evaluator.clone(),
            limits: profile.limits,
        },
        RemediationPhase::Package => RemediationEffectPlan::Package {
            finding: public,
            patch: case
                .current_patch()
                .context("current patch missing")?
                .clone(),
            evaluation: Box::new(
                case.current_evaluation()
                    .context("current evaluation missing")?
                    .clone(),
            ),
            cleanup: case
                .cleanup_receipts()
                .context("generator and evaluator cleanup receipts missing")?,
            report: crate::remediation_package::render_report(
                case,
                case.current_evaluation()
                    .context("current evaluation missing")?,
            ),
        },
        RemediationPhase::PublishDraft => {
            let target = case
                .publication_target()
                .cloned()
                .context("publication was not requested")?;
            RemediationEffectPlan::PublishDraft {
                stable_finding_key: stable_finding_key(&target, &case.provenance.finding)?,
                target,
                base_commit: profile.base_commit.clone(),
                package: case
                    .current_package()
                    .context("current package missing")?
                    .clone(),
            }
        }
    })
}

pub(crate) fn stable_finding_key(
    target: &PublicationTarget,
    finding: &FindingRevision,
) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&(
        1_u32,
        &target.provider,
        &target.repository,
        finding.candidate_id,
        &finding.candidate_payload_sha256,
    ))?))
}

pub(crate) fn active_publication_key(case: &RemediationCase) -> Result<Option<String>> {
    let Some(target) = case.publication_target() else {
        return Ok(None);
    };
    let generation = case.generation();
    let effect = case.effects.iter().rev().find(|effect| {
        effect.fence.generation == generation
            && effect.fence.phase == RemediationPhase::PublishDraft
    });
    if effect.is_some_and(|effect| case.effect_settled(effect.fence.effect_id)) {
        return Ok(None);
    }
    Ok(Some(stable_finding_key(target, &case.provenance.finding)?))
}

fn update_case<R: Repository, C: Clock>(
    controller: &Controller<R, C>,
    run: Id,
    remediation: Id,
    expected_revision: u64,
    mut operation: impl FnMut(&mut RemediationCase, u64) -> Result<()>,
) -> Result<RemediationCase> {
    let mut result = None;
    controller
        .repository
        .update(run, Some(expected_revision), &mut |campaign, _| {
            let now = controller.clock.now_ms()?;
            let case = campaign
                .remediations
                .iter_mut()
                .find(|case| case.id == remediation)
                .context("unknown remediation")?;
            operation(case, now)?;
            result = Some(case.clone());
            campaign.updated_ms = now;
            Ok(())
        })?;
    result.context("unknown remediation")
}

pub(crate) fn find_case(campaign: &Campaign, id: Id) -> Result<&RemediationCase> {
    campaign
        .remediations
        .iter()
        .find(|case| case.id == id)
        .context("unknown remediation")
}

pub(crate) fn within_root(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

pub(crate) fn valid_key(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "idempotency key must be 1-128 ASCII letters, digits, underscores or hyphens"
    );
    Ok(())
}
