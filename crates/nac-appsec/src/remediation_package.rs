use crate::*;
use anyhow::{ensure, Context};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, OpenOptionsExt},
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const PAYLOAD_NAMES: [&str; 5] = [
    "evaluation.json",
    "finding.json",
    "patch.diff",
    "patch.json",
    "report.md",
];

impl RemediationPackage {
    pub fn build(
        finding: &PublicFinding,
        patch: &PatchRecord,
        evaluation: &EvaluationRecord,
        cleanup: &RemediationCleanupReceipts,
        patch_diff: &[u8],
        report: &str,
    ) -> Result<Self> {
        let patch_payload = RemediationPatchPayload {
            plan_sha256: patch.plan_sha256.clone(),
            patch_sha256: patch.patch_sha256.clone(),
            source_package_sha256: patch.source_package_sha256.clone(),
            worker: patch.worker.clone(),
            diff_sha256: patch.diff_sha256.clone(),
            proposal: patch.proposal.clone(),
        };
        let evaluation_payload = RemediationEvaluationPayload {
            plan_sha256: evaluation.plan_sha256.clone(),
            source_package_sha256: evaluation.source_package_sha256.clone(),
            worker: evaluation.worker.clone(),
            assertion: evaluation.assertion.clone(),
            output: evaluation.output.clone(),
            cleanup: cleanup.clone(),
        };
        let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        payloads.insert("finding.json".into(), canonical_json(finding)?);
        payloads.insert("patch.json".into(), canonical_json(&patch_payload)?);
        payloads.insert(
            "evaluation.json".into(),
            canonical_json(&evaluation_payload)?,
        );
        payloads.insert("patch.diff".into(), patch_diff.to_vec());
        payloads.insert("report.md".into(), report.as_bytes().to_vec());
        let files = payloads
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    PackagePayload {
                        bytes: bytes.len().try_into().unwrap_or(u64::MAX),
                        sha256: hash(bytes),
                        mode: 0o644,
                    },
                )
            })
            .collect();
        let package = Self {
            manifest: RemediationPackageManifest {
                schema_version: 1,
                finding: finding.revision.clone(),
                plan_sha256: patch.plan_sha256.clone(),
                patch_sha256: patch.patch_sha256.clone(),
                evaluation_plan_sha256: evaluation.plan_sha256.clone(),
                evaluation_sha256: hash(&payloads["evaluation.json"]),
                files,
            },
            payloads,
        };
        package.verify()?;
        Ok(package)
    }

    pub fn verify(&self) -> Result<()> {
        require_version(self.manifest.schema_version)?;
        let expected: BTreeSet<_> = PAYLOAD_NAMES.into_iter().map(str::to_string).collect();
        ensure!(
            self.manifest.files.keys().cloned().collect::<BTreeSet<_>>() == expected
                && self.payloads.keys().cloned().collect::<BTreeSet<_>>() == expected,
            "remediation package payload inventory must be exact and exclude manifest.json"
        );
        for (name, bytes) in &self.payloads {
            let inventory = &self.manifest.files[name];
            ensure!(
                inventory.mode == 0o644
                    && inventory.bytes == u64::try_from(bytes.len())?
                    && inventory.sha256 == hash(bytes),
                "remediation package payload drift"
            );
            ensure!(
                std::str::from_utf8(bytes).is_ok() && !bytes.contains(&b'\r'),
                "remediation package payloads must be canonical LF-only UTF-8"
            );
        }
        let finding: PublicFinding = canonical_payload(&self.payloads["finding.json"])?;
        let patch: RemediationPatchPayload = canonical_payload(&self.payloads["patch.json"])?;
        let evaluation: RemediationEvaluationPayload =
            canonical_payload(&self.payloads["evaluation.json"])?;
        ensure!(
            self.manifest.finding == finding.revision
                && self.manifest.plan_sha256 == patch.plan_sha256
                && self.manifest.patch_sha256 == patch.patch_sha256
                && self.manifest.evaluation_plan_sha256 == evaluation.plan_sha256
                && evaluation.output.patch_sha256 == patch.patch_sha256
                && self.manifest.evaluation_sha256 == hash(&self.payloads["evaluation.json"]),
            "remediation package payload provenance drift"
        );
        ensure!(
            !patch.proposal.replacements.is_empty()
                && patch.patch_sha256 == hash(&canonical_json(&patch.proposal.replacements)?)
                && patch.diff_sha256 == hash(&self.payloads["patch.diff"])
                && patch.proposal.unified_diff.sha256 == patch.diff_sha256
                && canonical_diff_matches_replacements(
                    &self.payloads["patch.diff"],
                    &patch.proposal.replacements,
                )
                && patch.source_package_sha256 == evaluation.source_package_sha256
                && patch.worker.verify().is_ok()
                && evaluation.worker.verify().is_ok()
                && evaluation.assertion.verify().is_ok()
                && evaluation.output.verdict == EvaluationVerdict::Fixed
                && evaluation.output.complete
                && evaluation.output.original_target.source_sha256
                    != evaluation.output.patched_target.source_sha256
                && crate::remediation_reducer::evaluation_evidence_valid(
                    &evaluation.output.evidence,
                    &evaluation.assertion,
                    &evaluation.source_package_sha256,
                    &patch.patch_sha256,
                    &evaluation.output.original_target,
                    &evaluation.output.patched_target,
                    u32::MAX,
                )
                && evidence_artifacts_valid(&evaluation.output.evidence)
                && valid_authority(
                    &patch.proposal.authority,
                    &patch.worker,
                    &patch.source_package_sha256,
                )
                && valid_authority(
                    &evaluation.output.authority,
                    &evaluation.worker,
                    &hash(&serde_json::to_vec(&(
                        1_u32,
                        &evaluation.source_package_sha256,
                        &patch.patch_sha256,
                        &evaluation.assertion.assertion_sha256,
                    ))?),
                )
                && valid_cleanup(&evaluation.cleanup.generator, false)
                && valid_cleanup(&evaluation.cleanup.evaluator, true)
                && evaluation.cleanup.generator.workspace_sha256
                    == patch.proposal.authority.workspace_sha256
                && evaluation.cleanup.evaluator.workspace_sha256
                    == evaluation.output.authority.workspace_sha256,
            "remediation package contains unaccepted patch, evaluation or cleanup evidence"
        );
        ensure!(
            patch.proposal.unified_diff.sha256 == hash(&self.payloads["patch.diff"])
                && patch.proposal.unified_diff.bytes
                    == u64::try_from(self.payloads["patch.diff"].len())?,
            "remediation package diff is not the accepted patch projection"
        );
        let report = std::str::from_utf8(&self.payloads["report.md"])?;
        ensure!(
            [
                "Finding evidence",
                "Original target",
                "Patched target",
                "Reproduction and tests",
                "Limitations",
                "Owner",
                "Reviewer outcome",
                "Remaining rollout work",
            ]
            .iter()
            .all(|heading| report.contains(heading)),
            "remediation report is incomplete"
        );
        Ok(())
    }

    pub fn package_id(&self) -> Result<String> {
        self.manifest.package_id()
    }

    pub fn materialize(&self, destination: &Path) -> Result<()> {
        self.verify()?;
        let mut files = self.payloads.clone();
        files.insert("manifest.json".into(), self.manifest.canonical_bytes()?);
        let (parent, destination_name) = package_parent(destination)?;
        if let Ok(directory) = open_directory(&parent, &destination_name) {
            return verify_materialization(&directory, &files);
        }
        let temporary_name = format!(
            ".{}.{}",
            destination_name.to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        let mut builder = cap_std::fs::DirBuilder::new();
        use cap_std::fs::DirBuilderExt;
        builder.mode(0o700);
        parent.create_dir_with(&temporary_name, &builder)?;
        let temporary = open_directory(&parent, temporary_name.as_ref())?;
        write_materialization(&temporary, &files)?;
        match rename_noreplace(&parent, &temporary_name, &destination_name) {
            Ok(()) => parent.try_clone()?.into_std_file().sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = open_directory(&parent, &destination_name)?;
                verify_materialization(&existing, &files)?;
                parent.remove_dir_all(&temporary_name)?;
            }
            Err(error) => return Err(error.into()),
        }
        verify_materialization(&open_directory(&parent, &destination_name)?, &files)
    }
}

impl RemediationPackageManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn package_id(&self) -> Result<String> {
        Ok(hash(&self.canonical_bytes()?))
    }
}

pub(crate) fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}

fn canonical_payload<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes).context("invalid remediation package JSON")?;
    ensure!(
        canonical_json(&value)? == bytes,
        "noncanonical package JSON"
    );
    Ok(value)
}

fn valid_artifact(reference: &ArtifactRef) -> bool {
    reference.bytes > 0 && crate::artifacts::valid_hash(&reference.sha256)
}

fn evidence_artifacts_valid(evidence: &EvaluationEvidence) -> bool {
    [
        &evidence.identities.artifact,
        &evidence.original_assertion.artifact,
        &evidence.patched_assertion.artifact,
        &evidence.original_legitimate_use.artifact,
        &evidence.patched_legitimate_use.artifact,
        &evidence.original_required_checks.artifact,
        &evidence.patched_required_checks.artifact,
        &evidence.structural_review.artifact,
    ]
    .iter()
    .all(|reference| valid_artifact(reference))
}

fn canonical_diff_matches_replacements(diff: &[u8], replacements: &[FileReplacement]) -> bool {
    let Ok(text) = std::str::from_utf8(diff) else {
        return false;
    };
    if text.contains('\r') || !text.ends_with('\n') {
        return false;
    }
    let mut lines = text.split_inclusive('\n');
    let mut previous: Option<&str> = None;
    for replacement in replacements {
        if previous.is_some_and(|path| path >= replacement.path.as_str()) {
            return false;
        }
        previous = Some(&replacement.path);
        let expected_old = if replacement.original_sha256.is_some() {
            format!("--- a/{}\n", replacement.path)
        } else {
            "--- /dev/null\n".into()
        };
        if lines.next() != Some(expected_old.as_str())
            || lines.next() != Some(format!("+++ b/{}\n", replacement.path).as_str())
        {
            return false;
        }
        let Some(hunk) = lines.next() else {
            return false;
        };
        let Some((old_start, old_count, new_start, new_count)) = parse_hunk(hunk) else {
            return false;
        };
        if old_start != usize::from(old_count > 0) || new_start != usize::from(new_count > 0) {
            return false;
        }
        let mut original = Vec::new();
        for _ in 0..old_count {
            let Some(line) = lines.next().and_then(|line| line.strip_prefix('-')) else {
                return false;
            };
            original.extend_from_slice(line.as_bytes());
        }
        let mut replacement_bytes = Vec::new();
        for _ in 0..new_count {
            let Some(line) = lines.next().and_then(|line| line.strip_prefix('+')) else {
                return false;
            };
            replacement_bytes.extend_from_slice(line.as_bytes());
        }
        if replacement
            .original_sha256
            .as_ref()
            .is_some_and(|digest| digest != &hash(&original))
            || (replacement.original_sha256.is_none() && !original.is_empty())
            || replacement.replacement_sha256 != hash(&replacement_bytes)
            || replacement.replacement_bytes != replacement_bytes.len() as u64
            || replacement.content.sha256 != replacement.replacement_sha256
            || replacement.content.bytes != replacement.replacement_bytes
        {
            return false;
        }
    }
    lines.next().is_none()
}

fn parse_hunk(line: &str) -> Option<(usize, usize, usize, usize)> {
    let value = line.strip_prefix("@@ -")?.strip_suffix(" @@\n")?;
    let (old, new) = value.split_once(" +")?;
    let (old_start, old_count) = old.split_once(',')?;
    let (new_start, new_count) = new.split_once(',')?;
    Some((
        old_start.parse().ok()?,
        old_count.parse().ok()?,
        new_start.parse().ok()?,
        new_count.parse().ok()?,
    ))
}

fn valid_authority(
    receipt: &RemediationAuthorityReceipt,
    worker: &RemediationWorkerIdentity,
    workspace_sha256: &str,
) -> bool {
    [
        &receipt.tools_sha256,
        &receipt.mounts_sha256,
        &receipt.environment_sha256,
        &receipt.backend_sha256,
        &receipt.process_supervision_sha256,
        &receipt.workspace_sha256,
    ]
    .iter()
    .all(|digest| crate::artifacts::valid_hash(digest))
        && receipt.tools_sha256 == worker.tools_sha256
        && receipt.mounts_sha256 == worker.mounts_sha256
        && receipt.environment_sha256 == worker.environment_sha256
        && receipt.backend_sha256 == worker.backend_sha256
        && receipt.process_supervision_sha256 == worker.process_supervision_sha256
        && receipt.workspace_sha256 == workspace_sha256
}

fn valid_cleanup(receipt: &CleanupReceipt, target_required: bool) -> bool {
    receipt.delayed_launches_settled
        && receipt.descendants_terminated
        && crate::artifacts::valid_hash(&receipt.process_sha256)
        && crate::artifacts::valid_hash(&receipt.workspace_sha256)
        && receipt
            .network_sha256
            .as_ref()
            .is_some_and(|digest| crate::artifacts::valid_hash(digest))
        && (!target_required
            || receipt
                .target_sha256
                .as_ref()
                .is_some_and(|digest| crate::artifacts::valid_hash(digest)))
}

fn write_materialization(directory: &Dir, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    use cap_std::fs::PermissionsExt;
    use std::io::Write;
    for (name, bytes) in files {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW);
        let mut output = directory.open_with(name, &options)?;
        output.set_permissions(cap_std::fs::Permissions::from_mode(0o644))?;
        output.write_all(bytes)?;
        output.sync_all()?;
    }
    directory.try_clone()?.into_std_file().sync_all()?;
    verify_materialization(directory, files)
}

fn verify_materialization(directory: &Dir, expected: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    use cap_std::fs::PermissionsExt;
    use std::io::Read;
    let mut names = BTreeSet::new();
    for entry in directory.entries()? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("package entry name is not UTF-8"))?;
        let bytes = expected
            .get(&name)
            .context("remediation package destination has extra files")?;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = directory.open_with(&name, &options)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o644,
            "unsafe package entry mode or type"
        );
        let mut observed = Vec::new();
        file.read_to_end(&mut observed)?;
        ensure!(observed == *bytes, "package byte conflict");
        names.insert(name);
    }
    ensure!(
        names == expected.keys().cloned().collect(),
        "remediation package destination is incomplete"
    );
    Ok(())
}

fn package_parent(destination: &Path) -> Result<(Dir, std::ffi::OsString)> {
    let absolute = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    let mut components: Vec<_> = absolute.components().collect();
    let name = match components.pop() {
        Some(Component::Normal(name)) => name.to_os_string(),
        _ => anyhow::bail!("remediation package destination requires a normal name"),
    };
    let mut directory = Dir::open_ambient_dir("/", ambient_authority())?;
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let mut options = OpenOptions::new();
                options
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
                directory = Dir::from_std_file(directory.open_with(name, &options)?.into_std());
            }
            _ => anyhow::bail!("remediation package path must not contain links or traversal"),
        }
    }
    Ok((directory, name))
}

fn open_directory(parent: &Dir, name: &std::ffi::OsStr) -> Result<Dir> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    Ok(Dir::from_std_file(
        parent.open_with(name, &options)?.into_std(),
    ))
}

#[allow(
    clippy::undocumented_unsafe_blocks,
    reason = "Linux renameat2 is required for atomic no-replace directory publication"
)]
fn rename_noreplace(
    parent: &Dir,
    source: &str,
    destination: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd, os::unix::ffi::OsStrExt};
    let source = CString::new(source)?;
    let destination = CString::new(destination.as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn render_report(case: &RemediationCase, evaluation: &EvaluationRecord) -> String {
    format!(
        "# Remediation report\n\n## Finding evidence\nCandidate: {}\nValidation: {}\n\n## Original target\n{}\n\n## Patched target\n{}\n\n## Reproduction and tests\nAssertion: {}\n\n## Limitations\nThe package records local acceptance only.\n\n## Owner\nUnassigned\n\n## Reviewer outcome\nPending\n\n## Remaining rollout work\nHuman review, merge, deployment, and production verification remain.\n",
        case.provenance.finding.candidate_payload_sha256,
        case.provenance.finding.validation_payload_sha256,
        evaluation.output.original_target.source_sha256,
        evaluation.output.patched_target.source_sha256,
        evaluation.output.assertion_sha256,
    )
}
