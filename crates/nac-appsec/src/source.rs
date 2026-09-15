use crate::{artifacts::valid_hash, Manifest, Result, SourceRef};
use anyhow::ensure;
use std::{
    collections::BTreeSet,
    path::{Component, Path},
    process::Command,
};

pub(crate) fn validate_manifest(manifest: &Manifest) -> Result<()> {
    crate::require_version(manifest.schema_version)?;
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
        !source.path.is_empty()
            && source
                .path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(&source.path)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
            && !source.path.contains(['\0', '\n', '\r', ':', '\\']),
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

fn git(checkout: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
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
        .output()?;
    ensure!(output.status.success(), "pinned source lookup failed; required objects must already be local; implicit fetch is prohibited");
    Ok(output.stdout)
}
