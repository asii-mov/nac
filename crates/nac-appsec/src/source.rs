use crate::{artifacts::valid_hash, Manifest, Result, SourceRef};
use anyhow::ensure;
use std::{
    collections::BTreeSet,
    path::{Component, Path},
    process::Command,
};

pub(crate) fn validate_manifest(manifest: &Manifest) -> Result<()> {
    crate::require_version(manifest.schema_version)?;
    if let Some(profile) = &manifest.remediation {
        profile.verify(manifest)?;
    }
    if let Some(profile) = &manifest.experiments {
        profile.verify(&manifest.repositories)?;
        ensure!(
            manifest.research.is_some(),
            "controlled experiments require frozen research inputs"
        );
    }
    if let Some(research) = &manifest.research {
        research.verify()?;
        ensure!(
            manifest.experiments.is_some() == research.controlled_experiments,
            "controlled experiment skills and profile must be frozen together"
        );
        ensure!(
            research.stages.len() == manifest.tasks.len()
                && manifest
                    .tasks
                    .iter()
                    .all(|task| research.stages.contains_key(&task.key)),
            "every task must have exactly one frozen stage assignment"
        );
        ensure!(
            research.brief.max_investigative_agents == manifest.max_concurrency,
            "brief concurrency differs from admission policy"
        );
    }
    let watchdog = manifest.watchdog;
    ensure!(
        watchdog.warn_after_ms > 0
            && watchdog.diagnostic_grace_ms > 0
            && watchdog.stall_after_ms > watchdog.warn_after_ms
            && watchdog.lease_ms > 0
            && watchdog.max_failed_recoveries > 0,
        "watchdog intervals and recovery limit must be positive; stall must follow warning"
    );
    ensure!(
        !manifest.repositories.is_empty(),
        "at least one pinned repository is required"
    );
    let mut repositories = BTreeSet::new();
    for repo in &manifest.repositories {
        ensure!(
            repo.checkout.is_absolute(),
            "repository checkout must be absolute so resume cannot change its resolution"
        );
        ensure!(
            !repo.identity.trim().is_empty() && repositories.insert(&repo.identity),
            "repository identities must be nonempty and unique"
        );
        ensure!(
            [40, 64].contains(&repo.commit.len())
                && repo
                    .commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "repository commit must be a full lowercase object ID"
        );
        let output = git(
            &repo.checkout,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", repo.commit),
            ],
        )?;
        ensure!(
            String::from_utf8(output)?.trim() == repo.commit,
            "repository commit mismatch"
        );
    }
    for key in [
        "environment",
        "dependencies",
        "fixtures",
        "deployment",
        "harness_commit",
        "runtime_version",
        "model_configuration",
        "skill_bundle",
    ] {
        ensure!(
            manifest.declared_inputs.contains_key(key),
            "declare input {key}, using null when unknown"
        );
    }
    ensure!(
        (1..=4).contains(&manifest.max_concurrency) && !manifest.tasks.is_empty(),
        "campaign requires a task graph and one to four investigative slots"
    );
    let mut keys = BTreeSet::new();
    for task in &manifest.tasks {
        ensure!(
            !task.key.trim().is_empty() && keys.insert(task.key.as_str()),
            "task keys must be nonempty and unique"
        );
        ensure!(
            !task.scope.trim().is_empty() && task.scope.len() <= 4096,
            "task scope must be bounded and nonempty"
        );
        task.operation_limits.validate()?;
    }
    let mut ready = BTreeSet::new();
    loop {
        let before = ready.len();
        for task in &manifest.tasks {
            ensure!(
                task.dependencies.iter().all(|d| keys.contains(d.as_str())),
                "unknown dependency"
            );
            if task.dependencies.iter().all(|d| ready.contains(d.as_str())) {
                ready.insert(task.key.as_str());
            }
        }
        if ready.len() == keys.len() {
            break;
        }
        ensure!(before != ready.len(), "task graph contains a cycle");
    }
    Ok(())
}

pub(crate) fn validate_source(manifest: &Manifest, source: &SourceRef) -> Result<()> {
    crate::package::require_member(manifest, &source.repository, &source.path)?;
    let repo = manifest
        .repositories
        .iter()
        .find(|r| r.identity == source.repository)
        .ok_or_else(|| anyhow::anyhow!("unknown source repository"))?;
    ensure!(
        repo.commit == source.commit,
        "source commit differs from pinned input"
    );
    ensure!(
        safe_source_path(&source.path),
        "source path must be a safe relative path"
    );
    ensure!(valid_hash(&source.content_sha256), "malformed source hash");
    let listing = git(
        &repo.checkout,
        &["ls-tree", "-z", &repo.commit, "--", &source.path],
    )?;
    ensure!(
        listing.starts_with(b"100644 blob ") || listing.starts_with(b"100755 blob "),
        "source is missing, a directory or a symlink"
    );
    let bytes = git(
        &repo.checkout,
        &["show", &format!("{}:{}", repo.commit, source.path)],
    )?;
    ensure!(
        crate::hash(&bytes) == source.content_sha256,
        "source content hash mismatch"
    );
    let source_text = std::str::from_utf8(&bytes)?;
    ensure!(
        source.start_line > 0
            && source.end_line >= source.start_line
            && source.end_line as usize <= source_text.lines().count(),
        "source line range does not exist"
    );
    Ok(())
}

pub(crate) fn safe_source_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.eq_ignore_ascii_case(".git")
        })
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.contains(['\0', '\n', '\r', ':', '\\'])
}

pub(crate) fn git(checkout: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    use std::{
        io::Read,
        process::Stdio,
        time::{Duration, Instant},
    };
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    let mut child = Command::new("git")
        .arg("--no-pager")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("--no-replace-objects")
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("source pipe missing"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("pinned source operation timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("source reader failed"))??;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "pinned source output exceeds bound"
    );
    ensure!(status.success(), "pinned source lookup failed; required objects must already be local; implicit fetch is prohibited");
    Ok(bytes)
}
