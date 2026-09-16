use nac_appsec::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub struct Directory(pub PathBuf);

impl Directory {
    pub fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("nac-appsec-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        #[cfg(unix)]
        restore_owner_write(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn restore_owner_write(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    if metadata.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            restore_owner_write(&entry.path());
        }
    }
}

#[derive(Clone)]
pub struct TestClock(pub Arc<AtomicU64>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1000)))
    }
    pub fn advance(&self, milliseconds: u64) {
        self.0.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

pub fn open(
    path: &Path,
    clock: TestClock,
    capacity: u32,
) -> Result<Controller<SqliteRepository, TestClock>> {
    Ok(Controller::new(
        SqliteRepository::open(path, capacity)?,
        ArtifactStore::open(path)?,
        clock,
    ))
}

pub fn git(arguments: &[&str]) -> Result<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    anyhow::ensure!(output.status.success(), "fixture Git lookup failed");
    Ok(output.stdout)
}

pub fn manifest(tasks: usize) -> Result<Manifest> {
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?
        .trim()
        .to_string();
    let declared_inputs = [
        "environment",
        "dependencies",
        "fixtures",
        "deployment",
        "harness_commit",
        "runtime_version",
        "model_configuration",
        "skill_bundle",
    ]
    .into_iter()
    .map(|key| (key.to_string(), None))
    .collect();
    Ok(Manifest {
        schema_version: 1,
        experiments: None,
        research: None,
        repositories: vec![RepositoryInput {
            identity: "nac-test".into(),
            checkout: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()?,
            commit,
        }],
        declared_inputs,
        monetary_policy: MonetaryPolicy::Uncapped,
        token_policy: TokenPolicy::ObserveOnly,
        watchdog: WatchdogPolicy {
            warn_after_ms: 10000,
            stall_after_ms: 20000,
            diagnostic_grace_ms: 5000,
            lease_ms: 100000,
            max_failed_recoveries: 3,
        },
        max_concurrency: 4,
        tasks: (0..tasks)
            .map(|index| TaskPlan {
                key: format!("cell-{index}"),
                scope: format!("inspect manifest cell {index}"),
                dependencies: vec![],
                operation_limits: OperationLimits {
                    wall_ms: 100000,
                    output_bytes: 100000,
                },
            })
            .collect(),
    })
}

pub fn candidate(manifest: &Manifest) -> Result<Submission> {
    let source = git(&[
        "show",
        &format!("{}:Cargo.toml", manifest.repositories[0].commit),
    ])?;
    Ok(Submission {
        schema_version: 1,
        payload: Payload::Candidate {
            candidate: Candidate {
                claim:
                    "deterministic test observation of a pinned manifest; not a vulnerability claim"
                        .into(),
                prerequisites: vec![],
                unresolved_assumptions: vec!["test only".into()],
                source: SourceRef {
                    repository: "nac-test".into(),
                    commit: manifest.repositories[0].commit.clone(),
                    path: "Cargo.toml".into(),
                    start_line: 1,
                    end_line: 1,
                    content_sha256: format!("{:x}", Sha256::digest(&source)),
                },
                experiments: vec![],
            },
        },
        evidence: vec![EvidenceInput::Upload { bytes: source }],
    })
}

pub fn completed(scope: &str) -> Submission {
    Submission {
        schema_version: 1,
        payload: Payload::StageResult {
            result: StageResult::Completed {
                scope: scope.into(),
            },
        },
        evidence: vec![EvidenceInput::Upload {
            bytes: b"fixture observed all declared inputs".to_vec(),
        }],
    }
}

#[derive(Default)]
pub struct Worker {
    pub starts: Vec<Assignment>,
    pub cancelled: Vec<Id>,
    pub terminated: BTreeMap<Id, bool>,
    pub usage: Usage,
    pub unsupported: bool,
    pub launch_error: bool,
    pub diagnostics: Vec<Id>,
    pub progress: Option<ArtifactRef>,
    pub operation: Option<RuntimeOperation>,
    pub diagnostic_evidence: Option<ArtifactRef>,
}

impl Runtime for Worker {
    fn check_capabilities(&self) -> Result<()> {
        anyhow::ensure!(
            !self.unsupported,
            "watchdog and bounded operations unproved"
        );
        Ok(())
    }
    fn start(&mut self, assignment: &Assignment) -> Result<()> {
        self.starts.push(assignment.clone());
        anyhow::ensure!(!self.launch_error, "fixture uncertain launch failure");
        Ok(())
    }
    fn observe(&mut self, attempt: Id) -> Result<RuntimeObservation> {
        if self.terminated.get(&attempt).copied().unwrap_or(false) {
            Ok(RuntimeObservation::Terminated {
                usage: self.usage.clone(),
                exit: RuntimeExit::Success,
                progress: self.progress.clone(),
            })
        } else {
            Ok(RuntimeObservation::Live {
                usage: self.usage.clone(),
                progress: self.progress.clone(),
                oldest_active_operation: self.operation.clone(),
            })
        }
    }
    fn cancel(&mut self, attempt: Id) -> Result<()> {
        self.cancelled.push(attempt);
        Ok(())
    }
    fn diagnose(&mut self, attempt: Id) -> Result<ArtifactRef> {
        self.diagnostics.push(attempt);
        self.diagnostic_evidence
            .clone()
            .ok_or_else(|| anyhow::anyhow!("fixture diagnosis unavailable"))
    }
}

pub fn diagnostic(path: &Path) -> Result<ArtifactRef> {
    ArtifactStore::open(path)?.write(
        format!(
            "trusted in-process fixture observer; host PID {}",
            std::process::id()
        )
        .as_bytes(),
        4096,
    )
}
