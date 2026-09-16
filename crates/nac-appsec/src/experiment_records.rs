use crate::{hash, Id, SourcePackage, SourceRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentProfile {
    pub schema_version: u32,
    pub package: crate::SourcePackage,
    pub recipes: Vec<RecipeBinding>,
    pub dependencies: Vec<crate::PrefetchedDependency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBinding {
    pub id: String,
    pub recipe_sha256: String,
    pub target: TargetIdentity,
    pub scope: TargetScope,
    pub oracle_class: OracleClass,
    pub interface: HttpInterface,
    pub production: crate::SourcePackage,
    pub repetitions: u32,
    pub operation_ms: u64,
    pub capture_bytes: u64,
}

impl RecipeBinding {
    pub fn canonical_sha256(&self) -> crate::Result<String> {
        Ok(hash(&serde_json::to_vec(&(
            1_u32,
            &self.id,
            &self.target,
            &self.scope,
            self.oracle_class,
            &self.interface,
            &self.production,
            self.repetitions,
            self.operation_ms,
            self.capture_bytes,
        ))?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpInterface {
    pub max_requests: u32,
    pub routes: Vec<HttpRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    pub actor: String,
    pub method: HttpMethod,
    pub path_prefix: String,
    pub max_body_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleClass {
    Authorization,
    RceNonce,
}

impl OracleClass {
    pub fn required_controls(self) -> &'static [ControlKind] {
        match self {
            Self::Authorization => &[
                ControlKind::OwnerAccess,
                ControlKind::PublicAccess,
                ControlKind::LegitimateUse,
                ControlKind::Health,
            ],
            Self::RceNonce => &[
                ControlKind::Benign,
                ControlKind::NoPrerequisite,
                ControlKind::LegitimateUse,
                ControlKind::Health,
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentity {
    pub source_sha256: String,
    pub build_sha256: String,
    pub image_sha256: String,
    pub environment_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetScope {
    OriginalTarget,
    ReducedDemo {
        original: TargetIdentity,
        tested: SourcePackage,
        declared_changes: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub actor: String,
    pub method: HttpMethod,
    pub path: String,
    pub body: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPlan {
    pub schema_version: u32,
    pub key: String,
    pub recipe_id: String,
    pub hypothesis: String,
    pub sources: Vec<SourceRef>,
    pub requests: Vec<HttpRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentPhase {
    Reserved,
    PendingCreate,
    PendingStart,
    Ready,
    PendingRequest,
    Captured,
    Assessed,
    CleanupPending,
    Cleaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentCode {
    Pending,
    Unsupported,
    EnvironmentUnavailable,
    IdentityDrift,
    DeliveryUncertain,
    CaptureIncomplete,
    ControlFailed,
    Cancelled,
    AdapterUnavailable,
    CleanupUncertain,
    HealthFailed,
    RecognizedTargetError,
    UnknownOutputWithheld,
    RecoveryExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Confirmed,
    NotObserved,
    Blocked,
    Invalid,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    OwnerAccess,
    PublicAccess,
    Benign,
    NoPrerequisite,
    LegitimateUse,
    Health,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResult {
    pub control: ControlKind,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentVerdict {
    pub assessment: Assessment,
    pub controls: Vec<ControlResult>,
    pub diagnostics: Vec<PublicDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDiagnostic {
    pub code: ExperimentCode,
    pub byte_offset: Option<u64>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentEvent {
    pub at_ms: u64,
    pub phase: ExperimentPhase,
    pub code: ExperimentCode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentTrial {
    pub run_key: Id,
    pub epoch: u32,
    pub repetition: u32,
    pub phase: ExperimentPhase,
    pub stop_requested: bool,
    #[serde(default)]
    pub consecutive_recovery_attempts: u32,
    #[serde(default)]
    pub operator_recovery_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_phase: Option<ExperimentPhase>,
    pub effective_target: Option<TargetIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_receipt: Option<ExecutionReceipt>,
    pub verdict: Option<ExperimentVerdict>,
    pub events: Vec<ExperimentEvent>,
}

impl ExperimentTrial {
    pub fn holds_target(&self) -> bool {
        self.phase != ExperimentPhase::Cleaned
    }

    pub fn blocks_campaign(&self) -> bool {
        self.holds_target()
            && (self.stop_requested
                || self
                    .events
                    .last()
                    .is_some_and(|event| !matches!(event.code, ExperimentCode::Pending)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    pub schema_version: u32,
    pub id: Id,
    pub task_id: Id,
    pub attempt_id: Id,
    pub plan: ExperimentPlan,
    pub plan_sha256: String,
    pub recipe: RecipeBinding,
    pub trials: Vec<ExperimentTrial>,
}

#[derive(Clone, Debug)]
pub struct ExperimentDesired {
    pub experiment_id: Id,
    pub plan_sha256: String,
    pub run_key: Id,
    pub stop: bool,
    pub phase: ExperimentPhase,
    pub recipe: RecipeBinding,
    pub requests: Vec<HttpRequest>,
}

pub struct RunnerObservation {
    pub run_key: Id,
    pub phase: ExperimentPhase,
    pub code: ExperimentCode,
    pub effective_target: Option<TargetIdentity>,
    pub execution_receipt: Option<ExecutionReceipt>,
    pub evaluation: Option<EvaluatorVerdict>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub adapter_version: String,
    pub broker_sha256: String,
    pub evaluator_sha256: String,
    pub source_manifest_sha256: String,
    pub build_sha256: String,
    pub image_sha256: String,
    pub environment_sha256: String,
    pub launch_sha256: String,
    pub mount_sha256: String,
    pub network_sha256: String,
    pub log_sha256: String,
    pub resource_sha256: String,
    pub request_plan_sha256: String,
}

pub struct EvaluatorVerdict(pub ExperimentVerdict);

pub trait ExperimentRunner: Send {
    fn reconcile(
        &mut self,
        desired: &ExperimentDesired,
    ) -> Result<RunnerObservation, ExperimentCode>;
}
