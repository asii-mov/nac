use crate::{
    ArtifactRef, EffectiveInputs, Id, OracleClass, PrefetchedDependency, SourcePackage, SourceRef,
    TargetIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoAuthorizationRemediationProfile {
    pub schema_version: u32,
    pub repository: String,
    pub base_commit: String,
    pub source_package: SourcePackage,
    pub dependencies: Vec<PrefetchedDependency>,
    pub configuration_sha256: String,
    pub skill_bundle_sha256: String,
    pub editable_roots: Vec<String>,
    pub generator: RemediationWorkerIdentity,
    pub evaluator: RemediationWorkerIdentity,
    pub assertion: EvaluatorAssertion,
    pub limits: RemediationLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationWorkerIdentity {
    pub model: String,
    pub runtime: String,
    pub extractor: String,
    pub prompt_sha256: String,
    pub environment_sha256: String,
    pub tools_sha256: String,
    pub mounts_sha256: String,
    pub backend_sha256: String,
    pub process_supervision_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationLimits {
    pub operation_ms: u64,
    pub output_bytes: u64,
    pub max_files: u32,
    pub max_patch_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorAssertion {
    pub version: String,
    pub assertion_sha256: String,
    pub recipe_id: String,
    pub recipe_sha256: String,
    pub oracle_class: OracleClass,
    pub oracle_sha256: String,
    pub rubric_sha256: String,
    pub fixture_sha256: String,
    pub required_checks_sha256: String,
    pub original_target: TargetIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRevision {
    pub candidate_id: Id,
    pub candidate_payload_sha256: String,
    pub validation_id: Id,
    pub validation_payload_sha256: String,
    pub workflow_decision_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationInputIdentity {
    pub repository: String,
    pub base_commit: String,
    pub source_package_sha256: String,
    pub dependencies_sha256: String,
    pub declared_inputs_sha256: String,
    pub campaign_configuration_sha256: String,
    pub configuration_sha256: String,
    pub skill_bundle_sha256: String,
    pub generator: RemediationWorkerIdentity,
    pub evaluator: RemediationWorkerIdentity,
    pub candidate_effective_inputs: EffectiveInputs,
    pub validation_effective_inputs: EffectiveInputs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationProvenance {
    pub finding: FindingRevision,
    pub inputs: RemediationInputIdentity,
    pub assertion: EvaluatorAssertion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionReviewReason {
    StaticSupported,
    ReproductionSubstitution,
    AssertionReplacement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionReview {
    pub reason: AssertionReviewReason,
    pub candidate_id: Id,
    pub validation_id: Id,
    pub assertion_version: String,
    pub assertion_sha256: String,
    pub reviewer: String,
    pub reviewed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationTarget {
    pub provider: String,
    pub repository: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRemediation {
    pub schema_version: u32,
    pub key: String,
    pub provenance: RemediationProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_review: Option<AssertionReview>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationPhase {
    GeneratePatch,
    EvaluatePatch,
    Package,
    PublishDraft,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFence {
    pub effect_id: Id,
    pub generation: u32,
    pub phase: RemediationPhase,
    pub plan_sha256: String,
    pub patch_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationEffectIntent {
    pub fence: EffectFence,
    pub requested_ms: u64,
    pub plan: RemediationEffectPlan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicFinding {
    pub revision: FindingRevision,
    pub claim: String,
    pub prerequisites: Vec<String>,
    pub source: SourceRef,
    pub evidence: Vec<ArtifactRef>,
    pub validation_evidence: Vec<ArtifactRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemediationEffectPlan {
    GeneratePatch {
        finding: PublicFinding,
        source_package: SourcePackage,
        dependencies: Vec<PrefetchedDependency>,
        editable_roots: Vec<String>,
        worker: RemediationWorkerIdentity,
        limits: RemediationLimits,
    },
    EvaluatePatch {
        source_package: SourcePackage,
        dependencies: Vec<PrefetchedDependency>,
        patch: PatchRecord,
        assertion: EvaluatorAssertion,
        worker: RemediationWorkerIdentity,
        limits: RemediationLimits,
    },
    Package {
        finding: PublicFinding,
        patch: PatchRecord,
        evaluation: Box<EvaluationRecord>,
        cleanup: RemediationCleanupReceipts,
        report: String,
    },
    PublishDraft {
        target: PublicationTarget,
        base_commit: String,
        stable_finding_key: String,
        package: PackageRecord,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationDesiredEffect {
    pub remediation_id: Id,
    pub fence: EffectFence,
    pub stop: bool,
    pub plan: RemediationEffectPlan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReplacement {
    pub path: String,
    pub original_sha256: Option<String>,
    pub replacement_sha256: String,
    pub replacement_bytes: u64,
    pub content: ArtifactRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchGeneratorSubmission {
    pub schema_version: u32,
    pub authority: RemediationAuthorityReceipt,
    pub replacements: Vec<FileReplacement>,
    pub unified_diff: ArtifactRef,
    pub diagnostics: Vec<PublicRemediationDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRecord {
    pub id: Id,
    pub generation: u32,
    pub effect_id: Id,
    pub plan_sha256: String,
    pub patch_sha256: String,
    pub source_package_sha256: String,
    pub worker: RemediationWorkerIdentity,
    pub diff_sha256: String,
    pub proposal: PatchGeneratorSubmission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationVerdict {
    Fixed,
    NotFixed,
    NoOp,
    Regressed,
    Weakened,
    Drift,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityFailureReason {
    UnauthorizedAccessObserved,
    CanaryDisclosureObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAssertionEvidence {
    pub artifact: ArtifactRef,
    pub violation_observed: bool,
    pub expected_reason: Option<SecurityFailureReason>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegitimateUseEvidence {
    pub artifact: ArtifactRef,
    pub health: bool,
    pub public_access: bool,
    pub owner_access: bool,
    pub owner_write_readback: bool,
    pub protected_route_bindings: bool,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredChecksEvidence {
    pub artifact: ArtifactRef,
    pub configuration_sha256: String,
    pub total: u32,
    pub passed: u32,
    pub skipped: u32,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralReviewEvidence {
    pub artifact: ArtifactRef,
    pub changed_files: u32,
    pub production_change_nonempty: bool,
    pub protected_symbols_preserved: bool,
    pub route_bindings_preserved: bool,
    pub tests_unchanged: bool,
    pub assertions_unchanged: bool,
    pub fixtures_unchanged: bool,
    pub dependencies_unchanged: bool,
    pub check_configuration_unchanged: bool,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentityEvidence {
    pub artifact: ArtifactRef,
    pub source_package_sha256: String,
    pub patch_sha256: String,
    pub original: TargetIdentity,
    pub patched: TargetIdentity,
    pub effective_environment_sha256: String,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationEvidence {
    pub identities: TargetIdentityEvidence,
    pub original_assertion: SecurityAssertionEvidence,
    pub patched_assertion: SecurityAssertionEvidence,
    pub original_legitimate_use: LegitimateUseEvidence,
    pub patched_legitimate_use: LegitimateUseEvidence,
    pub original_required_checks: RequiredChecksEvidence,
    pub patched_required_checks: RequiredChecksEvidence,
    pub structural_review: StructuralReviewEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationOutput {
    pub verdict: EvaluationVerdict,
    pub assertion_sha256: String,
    pub patch_sha256: String,
    pub original_target: TargetIdentity,
    pub patched_target: TargetIdentity,
    pub authority: RemediationAuthorityReceipt,
    pub evidence: EvaluationEvidence,
    pub complete: bool,
    pub diagnostics: Vec<PublicRemediationDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRecord {
    pub id: Id,
    pub generation: u32,
    pub effect_id: Id,
    pub plan_sha256: String,
    pub source_package_sha256: String,
    pub worker: RemediationWorkerIdentity,
    pub assertion: EvaluatorAssertion,
    pub output: EvaluationOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationAuthorityReceipt {
    pub tools_sha256: String,
    pub mounts_sha256: String,
    pub environment_sha256: String,
    pub backend_sha256: String,
    pub process_supervision_sha256: String,
    pub workspace_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationCleanupReceipts {
    pub generator: CleanupReceipt,
    pub evaluator: CleanupReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationPatchPayload {
    pub plan_sha256: String,
    pub patch_sha256: String,
    pub source_package_sha256: String,
    pub worker: RemediationWorkerIdentity,
    pub diff_sha256: String,
    pub proposal: PatchGeneratorSubmission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationEvaluationPayload {
    pub plan_sha256: String,
    pub source_package_sha256: String,
    pub worker: RemediationWorkerIdentity,
    pub assertion: EvaluatorAssertion,
    pub output: EvaluationOutput,
    pub cleanup: RemediationCleanupReceipts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePayload {
    pub bytes: u64,
    pub sha256: String,
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationPackageManifest {
    pub schema_version: u32,
    pub finding: FindingRevision,
    pub plan_sha256: String,
    pub patch_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evaluation_sha256: String,
    pub files: BTreeMap<String, PackagePayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationPackage {
    pub manifest: RemediationPackageManifest,
    pub payloads: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRecord {
    pub id: Id,
    pub generation: u32,
    pub effect_id: Id,
    pub package_id: String,
    pub manifest: RemediationPackageManifest,
    pub payloads: BTreeMap<String, ArtifactRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationOutcome {
    DraftCreated,
    DraftUpdated,
    BaseDrift,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationOutput {
    pub stable_finding_key: String,
    pub package_id: String,
    pub base_commit: String,
    pub outcome: PublicationOutcome,
    pub remote_reference_sha256: Option<String>,
    pub complete: bool,
    pub diagnostics: Vec<PublicRemediationDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRecord {
    pub id: Id,
    pub generation: u32,
    pub effect_id: Id,
    pub output: PublicationOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationDiagnosticCode {
    Pending,
    InvalidPatch,
    AdapterUnavailable,
    DeliveryUncertain,
    CaptureIncomplete,
    IdentityDrift,
    ValidationSuperseded,
    AssertionSuperseded,
    InputDrift,
    CapacityExhausted,
    CleanupUncertain,
    BaseDrift,
    CheckFailed,
    Nondeterministic,
    Cancelled,
    RecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRemediationDiagnostic {
    pub code: RemediationDiagnosticCode,
    pub source: Option<SourceRef>,
    pub byte_offset: Option<u64>,
    pub complete: bool,
    pub artifact_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReceipt {
    pub process_sha256: String,
    pub workspace_sha256: String,
    pub target_sha256: Option<String>,
    pub network_sha256: Option<String>,
    pub delayed_launches_settled: bool,
    pub descendants_terminated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemediationEffectOutput {
    PatchProposed {
        proposal: PatchGeneratorSubmission,
    },
    EvaluationCompleted {
        evaluation: Box<EvaluationOutput>,
    },
    PackageBuilt {
        package: RemediationPackage,
    },
    PublicationCompleted {
        publication: PublicationOutput,
    },
    Failed {
        diagnostics: Vec<PublicRemediationDiagnostic>,
        recovery_required: bool,
    },
    CleanupSettled {
        receipt: CleanupReceipt,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRemediationObservation {
    pub schema_version: u32,
    pub key: String,
    pub fence: EffectFence,
    pub output: RemediationEffectOutput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRemediationObservation {
    pub key: String,
    pub payload_sha256: String,
    pub observed_ms: u64,
    pub output: RemediationEffectOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationTombstoneReason {
    OperatorCancellation,
    Superseded,
    Recovery,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemediationJournalEntry {
    Opened {
        generation: u32,
        at_ms: u64,
    },
    Tombstoned {
        generation: u32,
        effect_id: Option<Id>,
        reason: RemediationTombstoneReason,
        at_ms: u64,
    },
    Recovered {
        generation: u32,
        at_ms: u64,
    },
    Reviewed {
        generation: u32,
        review: RemediationApproval,
        at_ms: u64,
    },
    PublicationRequested {
        generation: u32,
        target: PublicationTarget,
        at_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationApproval {
    pub schema_version: u32,
    pub generation: u32,
    pub decision: ApprovalDecision,
    pub reviewer: String,
    pub package_id: String,
    pub finding: FindingRevision,
    pub assertion_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationCase {
    pub schema_version: u32,
    pub id: Id,
    pub key: String,
    pub request_sha256: String,
    pub created_ms: u64,
    pub provenance: RemediationProvenance,
    pub assertion_review: Option<AssertionReview>,
    pub journal: Vec<RemediationJournalEntry>,
    pub effects: Vec<RemediationEffectIntent>,
    pub observations: BTreeMap<Id, Vec<AcceptedRemediationObservation>>,
    pub patches: Vec<PatchRecord>,
    pub evaluations: Vec<EvaluationRecord>,
    pub packages: Vec<PackageRecord>,
    pub publications: Vec<PublicationRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    NotStarted,
    Proposed,
    TestsPassed,
    ReviewRequired,
    Approved,
    Published,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFreshness {
    Current,
    Superseded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationCaseView {
    pub case: RemediationCase,
    pub status: RemediationStatus,
    pub freshness: RemediationFreshness,
    pub publication_ready: bool,
}
