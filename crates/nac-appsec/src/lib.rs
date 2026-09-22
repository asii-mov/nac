mod artifacts;
mod brief;
mod controller;
mod dependencies;
mod experiment_records;
mod experiments;
mod package;
mod records;
mod remediation;
mod remediation_package;
mod remediation_records;
mod remediation_reducer;
mod remediation_runtime;
mod repository;
mod retrieval;
mod runtime;
mod skills;
mod source;
mod submission;
mod workflow;
mod workflow_admission;
mod workflow_questions;
mod workflow_records;

pub use artifacts::ArtifactStore;
pub use brief::{Assurance, RenderedBrief, ResearchBrief};
pub use controller::Controller;
pub use dependencies::{DependencyRead, PrefetchedDependency};
pub use experiment_records::*;
pub use package::{PackageFile, SourcePackage};
pub use records::*;
pub use remediation_records::*;
pub use remediation_reducer::{canonical_replacement_diff, ReplacementDiffEntry};
pub use remediation_runtime::{DraftPublisher, PatchEvaluator, PatchGenerator};
pub use repository::{Repository, SqliteRepository};
pub use retrieval::{
    DependencySourceRead, InventoryEnumeration, InventoryReceipt, SourceFiles, SourceInventory,
    SourceRead, SourceReceipt,
};
pub use runtime::{Assignment, Runtime, RuntimeExit, RuntimeObservation};
pub use skills::{FrozenResearch, FrozenSkill, LockedSkill, PreparedResearch, SkillLock};
pub use workflow_records::*;

pub type Result<T> = anyhow::Result<T>;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?)
    }
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn require_version(version: u32) -> Result<()> {
    anyhow::ensure!(version == 1, "unsupported schema version {version}");
    Ok(())
}
