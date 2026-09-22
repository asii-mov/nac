//! History-free, capability-shaped workspace for narrowly controlled coding.

use anyhow::{ensure, Context, Result};
use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};

use nac_process::ProcessTreeGuard;

const TOOL_PROTOCOL: &str = "nac-controlled-coding-v1:read,search,replace,gofmt,go-check";
const PROCESS_PROTOCOL: &str = "nac-process:spawn-supervised:v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledSourceFile {
    pub path: String,
    #[serde(with = "bytes_serde")]
    pub bytes: Vec<u8>,
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlledCodingLimits {
    pub operation_timeout: Duration,
    pub max_output_bytes: usize,
    pub max_read_bytes: usize,
    pub max_files: usize,
    pub max_patch_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledGoCheck {
    pub args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlledCodingPolicy {
    pub editable_roots: Vec<String>,
    pub required_production_path: String,
    pub go_check: ControlledGoCheck,
    pub environment: BTreeMap<String, String>,
    pub limits: ControlledCodingLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledCodingAuthorityReceipt {
    pub tools_sha256: String,
    pub mounts_sha256: String,
    pub environment_sha256: String,
    pub backend_sha256: String,
    pub process_supervision_sha256: String,
    pub workspace_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFileReplacement {
    pub path: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_bytes_serde"
    )]
    pub original: Option<Vec<u8>>,
    #[serde(with = "bytes_serde")]
    pub replacement: Vec<u8>,
    pub original_sha256: Option<String>,
    pub replacement_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledCodingCapture {
    pub authority: ControlledCodingAuthorityReceipt,
    pub replacements: Vec<CanonicalFileReplacement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlledCommandOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Construction port for a non-local backend whose command has access only to
/// the supplied workspace. Implementations must not substitute a local runner.
pub trait ConfinedCodingBackend: Send + Sync {
    fn backend_identity(&self) -> &[u8];
    fn mount_identity(&self) -> &[u8];
    fn command(
        &self,
        workspace: &Path,
        program: &str,
        args: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<Command>;
}

pub struct ControlledCodingFacade {
    root_path: PathBuf,
    root: Dir,
    original: BTreeMap<String, SourceSnapshot>,
    editable_roots: Vec<String>,
    required_production_path: String,
    go_check: ControlledGoCheck,
    environment: BTreeMap<String, String>,
    limits: ControlledCodingLimits,
    backend: Arc<dyn ConfinedCodingBackend>,
    authority: ControlledCodingAuthorityReceipt,
    check_used: bool,
}

#[derive(Clone)]
struct SourceSnapshot {
    bytes: Vec<u8>,
    mode: u32,
}

impl ControlledCodingFacade {
    pub fn materialize(
        owner_root: &Path,
        files: Vec<ControlledSourceFile>,
        policy: ControlledCodingPolicy,
        backend: Arc<dyn ConfinedCodingBackend>,
    ) -> Result<Self> {
        validate_policy(&policy)?;
        ensure!(!files.is_empty(), "controlled workspace source is empty");
        ensure!(
            files.len() <= policy.limits.max_files,
            "source file limit exceeded"
        );
        ensure!(
            !backend.backend_identity().is_empty(),
            "confined backend identity is empty"
        );
        ensure!(
            !backend.mount_identity().is_empty(),
            "confined mount identity is empty"
        );

        let owner_root = owner_root
            .canonicalize()
            .context("failed to resolve controlled workspace owner root")?;
        let owner_metadata = std::fs::symlink_metadata(&owner_root)?;
        ensure!(
            owner_metadata.is_dir(),
            "controlled workspace owner root is not a directory"
        );
        let root_path = owner_root.join(format!("controlled-coding-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root_path)?;
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))?;
        let root = Dir::open_ambient_dir(&root_path, ambient_authority())?;
        let mut original = BTreeMap::new();
        let result = (|| {
            for file in files {
                let path = safe_relative_path(&file.path)?;
                ensure!(
                    file.path != ".git" && !file.path.starts_with(".git/"),
                    "Git metadata is forbidden"
                );
                ensure!(
                    file.mode & 0o777 == 0o644,
                    "source files must have mode 0644"
                );
                ensure!(
                    original
                        .insert(
                            file.path.clone(),
                            SourceSnapshot {
                                bytes: file.bytes.clone(),
                                mode: file.mode
                            }
                        )
                        .is_none(),
                    "duplicate source path"
                );
                create_parent_dirs(&root, path.parent().unwrap_or(Path::new("")))?;
                let mut options = std::fs::OpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .mode(file.mode)
                    .custom_flags(libc::O_NOFOLLOW);
                let mut output = options.open(root_path.join(path))?;
                output.write_all(&file.bytes)?;
                output.sync_all()?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_dir_all(&root_path);
            return Err(error);
        }

        let workspace_sha256 = hash_json(&(
            1_u32,
            &original
                .iter()
                .map(|(path, source)| (path, source.mode, hash(&source.bytes), source.bytes.len()))
                .collect::<Vec<_>>(),
        ))?;
        let authority = ControlledCodingAuthorityReceipt {
            tools_sha256: hash_json(&(
                TOOL_PROTOCOL,
                &policy.editable_roots,
                &policy.required_production_path,
                &policy.go_check,
                policy.limits.operation_timeout.as_millis(),
                policy.limits.max_output_bytes,
                policy.limits.max_read_bytes,
                policy.limits.max_files,
                policy.limits.max_patch_bytes,
            ))?,
            mounts_sha256: hash(backend.mount_identity()),
            environment_sha256: hash_json(&policy.environment)?,
            backend_sha256: hash(backend.backend_identity()),
            process_supervision_sha256: hash(PROCESS_PROTOCOL.as_bytes()),
            workspace_sha256,
        };
        Ok(Self {
            root_path,
            root,
            original,
            editable_roots: policy.editable_roots,
            required_production_path: policy.required_production_path,
            go_check: policy.go_check,
            environment: policy.environment,
            limits: policy.limits,
            backend,
            authority,
            check_used: false,
        })
    }

    pub fn authority(&self) -> &ControlledCodingAuthorityReceipt {
        &self.authority
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        let path = safe_relative_path(path)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = self.root.open_with(path, &options)?;
        ensure!(
            file.metadata()?.is_file(),
            "controlled read target is not a regular file"
        );
        let mut bytes = Vec::new();
        file.take((self.limits.max_read_bytes + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= self.limits.max_read_bytes,
            "controlled read limit exceeded"
        );
        Ok(bytes)
    }

    pub fn search(&self, needle: &[u8]) -> Result<Vec<String>> {
        ensure!(!needle.is_empty(), "search needle is empty");
        let mut matches = Vec::new();
        for path in collect_regular_files(&self.root)? {
            let bytes = self.read(&path)?;
            if bytes.windows(needle.len()).any(|window| window == needle) {
                matches.push(path);
            }
        }
        Ok(matches)
    }

    pub fn replace(
        &self,
        path: &str,
        expected_sha256: Option<&str>,
        replacement: &[u8],
    ) -> Result<()> {
        validate_edit_path(path, &self.editable_roots)?;
        ensure!(
            replacement.len() <= self.limits.max_patch_bytes,
            "replacement byte limit exceeded"
        );
        let relative = safe_relative_path(path)?;
        let current = match self.read(path) {
            Ok(bytes) => Some(bytes),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        match (&current, expected_sha256) {
            (Some(bytes), Some(expected)) => {
                ensure!(hash(bytes) == expected, "controlled edit preimage mismatch");
            }
            (None, None) => {}
            _ => anyhow::bail!("controlled edit existence precondition mismatch"),
        }
        ensure!(
            current.as_deref() != Some(replacement),
            "controlled edit is a no-op"
        );
        atomic_write(&self.root, relative, replacement, current.is_some())
    }

    pub async fn gofmt(&self, paths: &[String]) -> Result<ControlledCommandOutput> {
        ensure!(!paths.is_empty(), "gofmt path set is empty");
        let mut unique = BTreeSet::new();
        for path in paths {
            validate_edit_path(path, &self.editable_roots)?;
            ensure!(unique.insert(path), "duplicate gofmt path");
            self.read(path)?;
        }
        let mut args = vec!["-w".to_string(), "--".to_string()];
        args.extend(paths.iter().cloned());
        self.run_confined("gofmt", &args).await
    }

    pub async fn run_go_check(&mut self) -> Result<ControlledCommandOutput> {
        ensure!(!self.check_used, "the bounded Go check was already used");
        self.check_used = true;
        self.run_confined("go", &self.go_check.args).await
    }

    pub fn capture(&self) -> Result<ControlledCodingCapture> {
        let observed = snapshot_workspace(&self.root, &self.original, &self.editable_roots)?;
        let mut replacements = Vec::new();
        let mut total = 0_usize;
        for (path, bytes) in observed {
            let source = self.original.get(&path);
            if source.is_some_and(|source| source.bytes == bytes) {
                continue;
            }
            validate_edit_path(&path, &self.editable_roots)?;
            total = total
                .checked_add(bytes.len())
                .context("replacement byte count overflow")?;
            ensure!(
                total <= self.limits.max_patch_bytes,
                "replacement byte limit exceeded"
            );
            replacements.push(CanonicalFileReplacement {
                path,
                original: source.map(|source| source.bytes.clone()),
                replacement_sha256: hash(&bytes),
                original_sha256: source.map(|source| hash(&source.bytes)),
                replacement: bytes,
            });
        }
        ensure!(!replacements.is_empty(), "controlled change set is empty");
        ensure!(
            replacements.len() <= self.limits.max_files,
            "replacement file limit exceeded"
        );
        ensure!(
            replacements
                .iter()
                .any(|replacement| replacement.path == self.required_production_path),
            "required production path is unchanged"
        );
        Ok(ControlledCodingCapture {
            authority: self.authority.clone(),
            replacements,
        })
    }

    async fn run_confined(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<ControlledCommandOutput> {
        let mut command =
            self.backend
                .command(&self.root_path, program, args, &self.environment)?;
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let (mut child, mut guard) = ProcessTreeGuard::spawn_supervised(&mut command)
            .with_context(|| format!("failed to launch confined {program}"))?;
        let stdout = child
            .stdout
            .take()
            .context("confined command stdout unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("confined command stderr unavailable")?;
        let maximum = self.limits.max_output_bytes;
        let stdout_task = tokio::spawn(read_bounded(stdout, maximum));
        let stderr_task = tokio::spawn(read_bounded(stderr, maximum));
        let status = match tokio::time::timeout(self.limits.operation_timeout, child.wait()).await {
            Ok(status) => status.context("failed waiting for confined command")?,
            Err(_) => {
                guard
                    .terminate(&mut child)
                    .await
                    .context("failed to clean up timed-out confined command")?;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                anyhow::bail!("confined command timed out");
            }
        };
        guard
            .terminate(&mut child)
            .await
            .context("failed to settle confined command descendants")?;
        let stdout = stdout_task.await.context("stdout reader failed")??;
        let stderr = stderr_task.await.context("stderr reader failed")??;
        Ok(ControlledCommandOutput {
            success: status.success(),
            code: status.code(),
            stdout,
            stderr,
        })
    }
}

impl Drop for ControlledCodingFacade {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_path);
    }
}

fn validate_policy(policy: &ControlledCodingPolicy) -> Result<()> {
    ensure!(
        !policy.editable_roots.is_empty(),
        "editable roots are empty"
    );
    ensure!(
        policy.limits.operation_timeout > Duration::ZERO,
        "operation timeout is zero"
    );
    ensure!(
        policy.limits.max_output_bytes > 0
            && policy.limits.max_read_bytes > 0
            && policy.limits.max_files > 0
            && policy.limits.max_patch_bytes > 0,
        "controlled coding limits must be positive"
    );
    for root in &policy.editable_roots {
        safe_relative_path(root)?;
        ensure!(!forbidden_path(root), "editable root is forbidden");
    }
    validate_edit_path(&policy.required_production_path, &policy.editable_roots)?;
    ensure!(
        !policy.go_check.args.is_empty(),
        "Go check arguments are empty"
    );
    ensure!(
        matches!(policy.go_check.args[0].as_str(), "test" | "vet"),
        "unsupported Go check"
    );
    ensure!(
        policy.environment.keys().all(|key| !key.is_empty()
            && key
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())),
        "invalid environment name"
    );
    Ok(())
}

fn validate_edit_path(path: &str, editable_roots: &[String]) -> Result<()> {
    safe_relative_path(path)?;
    ensure!(path.ends_with(".go"), "only Go source files are editable");
    ensure!(!forbidden_path(path), "controlled edit path is forbidden");
    ensure!(
        editable_roots
            .iter()
            .any(|root| path == root || path.starts_with(&format!("{root}/"))),
        "controlled edit is outside editable roots"
    );
    Ok(())
}

fn forbidden_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    lower == ".git"
        || lower.starts_with(".git/")
        || lower.contains("/vendor/")
        || lower.starts_with("vendor/")
        || name == "go.mod"
        || name == "go.sum"
        || name.ends_with("_test.go")
        || name.ends_with(".generated.go")
        || name.starts_with("zz_generated.")
        || lower.contains("/testdata/")
        || lower.starts_with("testdata/")
}

fn safe_relative_path(path: &str) -> Result<&Path> {
    ensure!(
        !path.is_empty() && !path.contains('\0') && !path.contains('\\'),
        "invalid controlled path"
    );
    let path = Path::new(path);
    ensure!(
        !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "controlled path must be normalized and relative"
    );
    Ok(path)
}

fn create_parent_dirs(root: &Dir, path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("invalid controlled directory")
        };
        current.push(name);
        match root.symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "controlled directory is not a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                root.create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn atomic_write(root: &Dir, path: &Path, bytes: &[u8], exists: bool) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new(""));
    create_parent_dirs(root, parent)?;
    let directory = open_dir_nofollow(root, parent)?;
    let name = path
        .file_name()
        .context("controlled edit path has no file name")?;
    if exists {
        let metadata = directory.symlink_metadata(name)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "controlled edit target is not a regular file"
        );
        use cap_std::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o644,
            "controlled edit mode changed"
        );
    }
    let temporary = format!(".nac-edit-{}", uuid::Uuid::new_v4());
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    use cap_std::fs::OpenOptionsExt;
    options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    let mut output = directory.open_with(&temporary, &options)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    drop(output);
    let result = directory.rename(&temporary, &directory, name);
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn open_dir_nofollow(root: &Dir, relative: &Path) -> Result<Dir> {
    let mut directory = root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("invalid controlled directory")
        };
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        directory = Dir::from_std_file(directory.open_with(name, &options)?.into_std());
    }
    Ok(directory)
}

fn collect_regular_files(root: &Dir) -> Result<Vec<String>> {
    fn visit(directory: &Dir, prefix: &Path, files: &mut Vec<String>) -> Result<()> {
        for entry in directory.entries()? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(
                !kind.is_symlink() && (kind.is_file() || kind.is_dir()),
                "workspace contains a link or special file"
            );
            let path = prefix.join(entry.file_name());
            if kind.is_dir() {
                let child = open_dir_nofollow(directory, Path::new(&entry.file_name()))?;
                visit(&child, &path, files)?;
            } else {
                files.push(
                    path.to_str()
                        .context("workspace path is not UTF-8")?
                        .to_string(),
                );
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, Path::new(""), &mut files)?;
    files.sort();
    Ok(files)
}

fn snapshot_workspace(
    root: &Dir,
    original: &BTreeMap<String, SourceSnapshot>,
    editable_roots: &[String],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let paths = collect_regular_files(root)?;
    ensure!(
        paths.len() >= original.len(),
        "controlled workspace file deletion is forbidden"
    );
    let actual: BTreeSet<_> = paths.iter().cloned().collect();
    ensure!(
        original.keys().all(|path| actual.contains(path)),
        "controlled workspace file deletion or rename is forbidden"
    );
    let mut observed = BTreeMap::new();
    for path in paths {
        let relative = safe_relative_path(&path)?;
        let metadata = root.symlink_metadata(relative)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "workspace contains a link or special file"
        );
        use cap_std::fs::PermissionsExt;
        if let Some(source) = original.get(&path) {
            ensure!(
                metadata.permissions().mode() & 0o777 == source.mode & 0o777,
                "controlled workspace mode change is forbidden"
            );
        } else {
            validate_edit_path(&path, editable_roots)?;
            ensure!(
                metadata.permissions().mode() & 0o777 == 0o644,
                "new controlled files must have mode 0644"
            );
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = root.open_with(relative, &options)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        observed.insert(path, bytes);
    }
    Ok(observed)
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= maximum,
        "confined command output limit exceeded"
    );
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash_json(value: &impl Serialize) -> Result<String> {
    Ok(hash(&serde_json::to_vec(value)?))
}

mod bytes_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(deserializer)
    }
}

mod optional_bytes_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_bytes(bytes),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<Vec<u8>>::deserialize(deserializer)
    }
}

#[cfg(test)]
#[path = "controlled_coding_tests.rs"]
mod tests;
