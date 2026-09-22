use crate::*;
use anyhow::{ensure, Context};

pub trait PatchGenerator {
    fn reconcile_patch(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput>;
}

pub trait PatchEvaluator {
    fn reconcile_evaluation(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput>;
}

pub trait DraftPublisher {
    fn reconcile_publication(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput>;
}

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn reconcile_remediation<G: PatchGenerator, E: PatchEvaluator>(
        &self,
        run: Id,
        remediation: Id,
        generator: &mut G,
        evaluator: &mut E,
    ) -> Result<RemediationCase> {
        for _ in 0..16 {
            let revision = self.repository.read(run)?.revision;
            let Some(desired) = self.desired_remediation_effect(run, remediation, revision)? else {
                return Ok(crate::remediation::find_case(
                    &self.repository.read(run)?,
                    remediation,
                )?
                .clone());
            };
            let output = match desired.fence.phase {
                RemediationPhase::GeneratePatch => generator.reconcile_patch(&desired)?,
                RemediationPhase::EvaluatePatch => evaluator.reconcile_evaluation(&desired)?,
                RemediationPhase::Package => self.reconcile_package_effect(&desired)?,
                RemediationPhase::PublishDraft => {
                    return Ok(crate::remediation::find_case(
                        &self.repository.read(run)?,
                        remediation,
                    )?
                    .clone());
                }
            };
            let suffix = if matches!(output, RemediationEffectOutput::CleanupSettled { .. }) {
                "cleanup"
            } else {
                "result"
            };
            self.record_remediation_observation(
                run,
                remediation,
                RecordRemediationObservation {
                    schema_version: 1,
                    key: format!("reconcile-{}-{suffix}", desired.fence.effect_id),
                    fence: desired.fence,
                    output,
                },
            )?;
        }
        anyhow::bail!("remediation reconciliation exceeded the bounded phase count")
    }

    pub fn reconcile_remediation_publication<P: DraftPublisher>(
        &self,
        run: Id,
        remediation: Id,
        publisher: &mut P,
    ) -> Result<RemediationCase> {
        for _ in 0..2 {
            let revision = self.repository.read(run)?.revision;
            let Some(desired) = self.desired_remediation_effect(run, remediation, revision)? else {
                return Ok(crate::remediation::find_case(
                    &self.repository.read(run)?,
                    remediation,
                )?
                .clone());
            };
            ensure!(
                desired.fence.phase == RemediationPhase::PublishDraft,
                "remediation has unfinished local acceptance work"
            );
            let output = publisher.reconcile_publication(&desired)?;
            let suffix = if matches!(output, RemediationEffectOutput::CleanupSettled { .. }) {
                "cleanup"
            } else {
                "result"
            };
            self.record_remediation_observation(
                run,
                remediation,
                RecordRemediationObservation {
                    schema_version: 1,
                    key: format!("publish-{}-{suffix}", desired.fence.effect_id),
                    fence: desired.fence,
                    output,
                },
            )?;
        }
        anyhow::bail!("publication reconciliation did not settle cleanup")
    }

    fn reconcile_package_effect(
        &self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput> {
        ensure!(
            desired.fence.phase == RemediationPhase::Package,
            "not a package effect"
        );
        if desired.stop {
            let digest = hash(&serde_json::to_vec(&(
                desired.remediation_id,
                &desired.fence,
                "local-package-cleanup-v1",
            ))?);
            return Ok(RemediationEffectOutput::CleanupSettled {
                receipt: CleanupReceipt {
                    process_sha256: digest.clone(),
                    workspace_sha256: desired.fence.plan_sha256.clone(),
                    target_sha256: None,
                    network_sha256: Some(digest),
                    delayed_launches_settled: true,
                    descendants_terminated: true,
                },
            });
        }
        let RemediationEffectPlan::Package {
            finding,
            patch,
            evaluation,
            cleanup,
            report,
        } = &desired.plan
        else {
            anyhow::bail!("package effect plan drift")
        };
        let diff = self.artifacts.read_range(
            &patch.proposal.unified_diff,
            0,
            patch.proposal.unified_diff.bytes,
        )?;
        Ok(RemediationEffectOutput::PackageBuilt {
            package: RemediationPackage::build(finding, patch, evaluation, cleanup, &diff, report)
                .context("canonical remediation package construction failed")?,
        })
    }
}
