use crate::WorkflowAction;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(Uuid);

impl Id {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for Id {
    type Err = uuid::Error;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Queued,
    Running,
    Completed,
    Partial,
    Blocked,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInput {
    pub identity: String,
    pub checkout: PathBuf,
    pub commit: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLimits {
    pub wall_ms: u64,
    pub output_bytes: u64,
}

impl OperationLimits {
    pub(crate) fn validate(self) -> crate::Result<()> {
        anyhow::ensure!(
            self.wall_ms > 0 && self.output_bytes > 0,
            "individual operation limits must be finite and positive"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPlan {
    pub key: String,
    pub scope: String,
    pub dependencies: Vec<String>,
    pub operation_limits: OperationLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<crate::GoAuthorizationRemediationProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiments: Option<crate::ExperimentProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub research: Option<crate::FrozenResearch>,
    pub repositories: Vec<RepositoryInput>,
    pub declared_inputs: BTreeMap<String, Option<String>>,
    pub monetary_policy: MonetaryPolicy,
    pub token_policy: TokenPolicy,
    pub watchdog: WatchdogPolicy,
    pub max_concurrency: u32,
    pub tasks: Vec<TaskPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonetaryPolicy {
    Uncapped,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenPolicy {
    ObserveOnly,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogPolicy {
    pub warn_after_ms: u64,
    pub stall_after_ms: u64,
    pub diagnostic_grace_ms: u64,
    pub lease_ms: u64,
    pub max_failed_recoveries: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogState {
    Healthy,
    Warning,
    SuspectedStall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub run_id: Id,
    pub task_id: Id,
    pub attempt_id: Id,
    pub generation: u32,
    pub token: Id,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub tokens: Option<u64>,
    pub output_bytes: Option<u64>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperation {
    pub id: String,
    pub started_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopIntent {
    AcceptedResultCleanup,
    WatchdogRecovery,
    LeaseExpired,
    OperationTimeout,
    OperatorCancellation,
    LaunchFailure,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub lease: Lease,
    pub started_ms: u64,
    pub deadline_ms: u64,
    pub terminated_ms: Option<u64>,
    pub revoked: bool,
    pub runtime_slot_held: bool,
    pub usage: Usage,
    pub reserved_submission_bytes: u64,
    pub input_fingerprint: String,
    pub last_liveness_ms: u64,
    pub last_progress_ms: u64,
    pub watchdog_state: WatchdogState,
    pub diagnostic_ms: Option<u64>,
    pub diagnostic_evidence: Option<ArtifactRef>,
    pub last_operation: Option<RuntimeOperation>,
    pub made_meaningful_progress: bool,
    pub stop_intent: Option<StopIntent>,
    pub runtime_exit: Option<crate::RuntimeExit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: Id,
    pub plan: TaskPlan,
    pub state: ExecutionState,
    pub reason: Option<String>,
    pub handoff: Option<String>,
    pub attempts: Vec<Attempt>,
    pub failed_recoveries: u32,
    pub progress_fingerprints: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Candidate,
    StaticSupported,
    Reproduced,
    Disproved,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationState {
    NotStarted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub claim: String,
    pub prerequisites: Vec<String>,
    pub unresolved_assumptions: Vec<String>,
    pub source: SourceRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub experiments: Vec<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Candidate {
        candidate: Candidate,
    },
    StageResult {
        result: StageResult,
    },
    Workflow {
        revision: u64,
        action: WorkflowAction,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum StageResult {
    Completed { scope: String },
    Partial { reason: String },
    Blocked { reason: String },
    Failed { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceInput {
    Upload { bytes: Vec<u8> },
    Stored { artifact: ArtifactRef },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub schema_version: u32,
    pub payload: Payload,
    pub evidence: Vec<EvidenceInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub id: Id,
    pub task_id: Id,
    pub attempt_id: Id,
    pub key: String,
    pub payload_hash: String,
    pub accepted_ms: u64,
    pub payload: Payload,
    pub evidence: Vec<ArtifactRef>,
    pub evidence_state: Option<EvidenceState>,
    pub remediation_state: Option<RemediationState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedSubmission {
    pub task_id: Id,
    pub attempt_id: Id,
    pub key: String,
    pub payload_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Campaign {
    pub schema_version: u32,
    pub id: Id,
    pub revision: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub configuration_hash: String,
    pub manifest: Manifest,
    pub cancelled: bool,
    pub dispatch_blocker: Option<String>,
    pub tasks: Vec<Task>,
    pub accepted: Vec<Accepted>,
    pub pending_submissions: Vec<ReservedSubmission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub experiments: Vec<crate::Experiment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<crate::Workflow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediations: Vec<crate::RemediationCase>,
}

impl Campaign {
    pub fn state(&self) -> ExecutionState {
        if self.cancelled {
            return ExecutionState::Cancelled;
        }
        if self
            .experiments
            .iter()
            .flat_map(|experiment| &experiment.trials)
            .any(crate::ExperimentTrial::blocks_campaign)
        {
            return ExecutionState::Blocked;
        }
        let has = |state| self.tasks.iter().any(|task| task.state == state);
        if has(ExecutionState::Running) {
            ExecutionState::Running
        } else if self
            .tasks
            .iter()
            .all(|task| task.state == ExecutionState::Completed)
        {
            if self
                .workflow
                .as_ref()
                .is_none_or(|workflow| workflow.completion_supported(self))
            {
                ExecutionState::Completed
            } else {
                ExecutionState::Partial
            }
        } else if self.dispatch_blocker.is_some() || has(ExecutionState::Blocked) {
            ExecutionState::Blocked
        } else if has(ExecutionState::Partial) || has(ExecutionState::Completed) {
            ExecutionState::Partial
        } else if has(ExecutionState::Failed) {
            ExecutionState::Failed
        } else if has(ExecutionState::Queued) {
            ExecutionState::Queued
        } else {
            ExecutionState::Cancelled
        }
    }

    pub fn markdown(&self) -> String {
        let completed = self
            .tasks
            .iter()
            .filter(|t| {
                t.state == ExecutionState::Completed
                    && self
                        .workflow
                        .as_ref()
                        .is_none_or(|workflow| workflow.assigned_class_work_supported(t.id))
            })
            .count();
        let candidates = self
            .accepted
            .iter()
            .filter(|a| matches!(a.payload, Payload::Candidate { .. }))
            .count();
        let validation = if self.workflow.is_some() {
            "Candidate submissions are not verdicts; independent source review outcomes are listed below."
        } else {
            "Candidates are not independently validated."
        };
        let mut text = format!("# Application security controller report\n\nRun: {}\n\nState: {:?}\n\nCompleted scope: {completed}/{} tasks. Candidate findings: {candidates}.\n\nZero findings does not establish security assurance. {validation} Money and token consumption have no ceiling. Tokens are observation-only; missing observed usage is unknown, not zero. A progress watchdog warns and diagnoses suspected stalls, independently of process liveness.\n\n", self.id, self.state(), self.tasks.len());
        if let Some(reason) = &self.dispatch_blocker {
            text.push_str(&format!("Dispatch blocked: {reason}\n\n"));
        }
        text.push_str("## Declared inputs\n\n");
        for (key, value) in &self.manifest.declared_inputs {
            text.push_str(&format!(
                "- {key}: {}\n",
                value.as_deref().unwrap_or("unknown")
            ));
        }
        text.push_str("\n## Scope\n\n");
        for task in &self.tasks {
            text.push_str(&format!(
                "- {}: {:?}; {}\n",
                task.plan.scope,
                task.state,
                task.reason
                    .as_deref()
                    .unwrap_or("no terminal reason recorded")
            ));
            if let Some(attempt) = task.attempts.last() {
                text.push_str(&format!("  Watchdog: {:?}; last liveness: {}; last meaningful progress: {}; occupied attempt: {}; consecutive failed recoveries: {}.\n", attempt.watchdog_state, attempt.last_liveness_ms, attempt.last_progress_ms, self.attempt_occupied(attempt), task.failed_recoveries));
                text.push_str(&format!(
                    "  Stop intent: {:?}; observed physical exit: {:?}.\n",
                    attempt.stop_intent, attempt.runtime_exit
                ));
            }
        }
        text.push_str("\nThe accompanying JSON contains pinned inputs, revisions, occupied slots, usage, watchdog state, attempts and accepted evidence. Live-provider conformance, reproduction, remediation and release acceptance are not established by this controller report.\n");
        if let Some(workflow) = &self.workflow {
            text.push_str(&workflow.markdown(self));
        }
        text
    }
}
