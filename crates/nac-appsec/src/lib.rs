mod artifacts;
mod brief;
mod controller;
mod records;
mod repository;
mod retrieval;
mod runtime;
mod skills;
mod source;
mod submission;

pub use artifacts::ArtifactStore;
pub use brief::{Assurance, RenderedBrief, ResearchBrief};
pub use controller::Controller;
pub use records::*;
pub use repository::{Repository, SqliteRepository};
pub use retrieval::{SourceFiles, SourceInventory, SourceRead, SourceReceipt};
pub use runtime::{Assignment, Runtime, RuntimeExit, RuntimeObservation};
pub use skills::{FrozenResearch, FrozenSkill, LockedSkill, PreparedResearch, SkillLock};

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
