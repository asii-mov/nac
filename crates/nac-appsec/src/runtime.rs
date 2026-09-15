use crate::{
    ArtifactRef, Id, Lease, OperationLimits, RepositoryInput, Result, RuntimeOperation, Usage,
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Assignment {
    pub lease: Lease,
    pub scope: String,
    pub repositories: Vec<RepositoryInput>,
    pub input_fingerprint: String,
    pub handoff: Option<String>,
    pub limits: OperationLimits,
    pub deadline_ms: u64,
    pub research: Option<crate::PreparedResearch>,
}

pub enum RuntimeObservation {
    Live {
        usage: Usage,
        progress: Option<ArtifactRef>,
        oldest_active_operation: Option<RuntimeOperation>,
    },
    Terminated {
        usage: Usage,
        exit: RuntimeExit,
        progress: Option<ArtifactRef>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExit {
    Success,
    ProviderFailure,
    EnvironmentBlocked,
    Cancelled,
}

pub trait Runtime {
    fn check_capabilities(&self) -> Result<()>;
    fn start(&mut self, assignment: &Assignment) -> Result<()>;
    fn observe(&mut self, attempt: Id) -> Result<RuntimeObservation>;
    fn cancel(&mut self, attempt: Id) -> Result<()>;
    fn diagnose(&mut self, attempt: Id) -> Result<ArtifactRef>;
}
