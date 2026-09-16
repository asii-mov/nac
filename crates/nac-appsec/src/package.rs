use crate::{hash, source::git, source::safe_source_path, Manifest, RepositoryInput, Result};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePackage {
    pub schema_version: u32,
    pub files: Vec<PackageFile>,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub blob: String,
    pub content_sha256: String,
    pub bytes: u64,
}

impl SourcePackage {
    pub fn freeze(
        repositories: &[RepositoryInput],
        includes: &[(String, String)],
        excluded: &[(String, String)],
    ) -> Result<Self> {
        ensure!(
            !includes.is_empty() && includes.len() <= 100_000,
            "invalid package membership"
        );
        let mut files = Vec::new();
        let mut unique = BTreeSet::new();
        for (identity, path) in includes {
            ensure!(package_path(path), "invalid public package path");
            ensure!(unique.insert((identity, path)), "duplicate package entry");
            ensure!(
                !excluded.iter().any(|(repo, denied)| repo == identity
                    && (path == denied || path.starts_with(&format!("{denied}/")))),
                "excluded package entry"
            );
            let repo = repositories
                .iter()
                .find(|repo| repo.identity == *identity)
                .context("undeclared package repository")?;
            let (blob, bytes) = regular_blob(repo, path)?;
            files.push(PackageFile {
                repository: identity.clone(),
                commit: repo.commit.clone(),
                path: path.clone(),
                blob,
                content_sha256: hash(&bytes),
                bytes: bytes.len().try_into()?,
            });
        }
        files.sort_by(|a, b| (&a.repository, &a.path).cmp(&(&b.repository, &b.path)));
        Ok(Self {
            schema_version: 1,
            manifest_sha256: hash(&serde_json::to_vec(&files)?),
            files,
        })
    }

    pub fn contains(&self, repository: &str, path: &str) -> bool {
        self.files
            .iter()
            .any(|file| file.repository == repository && file.path == path)
    }

    pub fn verify(&self, repositories: &[RepositoryInput]) -> Result<()> {
        crate::require_version(self.schema_version)?;
        ensure!(
            hash(&serde_json::to_vec(&self.files)?) == self.manifest_sha256,
            "package manifest drift"
        );
        let includes: Vec<_> = self
            .files
            .iter()
            .map(|file| (file.repository.clone(), file.path.clone()))
            .collect();
        let observed = Self::freeze(repositories, &includes, &[])?;
        ensure!(
            observed.manifest_sha256 == self.manifest_sha256,
            "package source drift"
        );
        Ok(())
    }

    pub fn export(&self, repositories: &[RepositoryInput], destination: &Path) -> Result<()> {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        self.verify(repositories)?;
        ensure!(!destination.exists(), "package export must be fresh");
        fs::create_dir(destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
        let result = (|| {
            let main = destination.join("main");
            fs::create_dir(&main)?;
            for file in &self.files {
                let repo = repositories
                    .iter()
                    .find(|repo| repo.identity == file.repository)
                    .context("missing package repository")?;
                ensure!(
                    package_path(&repo.identity) && !repo.identity.contains('/'),
                    "invalid export repository name"
                );
                let path = main.join(&repo.identity).join(&file.path);
                fs::create_dir_all(path.parent().context("invalid package parent")?)?;
                let (_, bytes) = regular_blob(repo, &file.path)?;
                ensure!(hash(&bytes) == file.content_sha256, "package source drift");
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)?;
                output.write_all(&bytes)?;
                output.sync_all()?;
            }
            freeze_directories(&main)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o500))?;
            Ok(())
        })();
        result
    }

    pub fn verify_export(&self, destination: &Path) -> Result<()> {
        use std::{collections::BTreeSet, fs};
        ensure!(destination.is_dir(), "package export missing");
        let expected: BTreeSet<_> = self
            .files
            .iter()
            .map(|file| format!("main/{}/{}", file.repository, file.path))
            .collect();
        let mut actual = BTreeSet::new();
        collect_files(destination, destination, &mut actual)?;
        ensure!(actual == expected, "package export membership drift");
        for file in &self.files {
            let path = destination
                .join("main")
                .join(&file.repository)
                .join(&file.path);
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && metadata.len() == file.bytes,
                "package export file drift"
            );
            ensure!(
                hash(&fs::read(path)?) == file.content_sha256,
                "package export content drift"
            );
        }
        Ok(())
    }
}

fn collect_files(
    root: &Path,
    path: &Path,
    files: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink() && (kind.is_file() || kind.is_dir()),
            "package export contains a link or special file"
        );
        if kind.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else {
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("package export path is not UTF-8"))?
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

pub(crate) fn freeze_directories(path: &Path) -> Result<()> {
    use std::{fs, os::unix::fs::PermissionsExt};
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            freeze_directories(&entry.path())?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    Ok(())
}

fn regular_blob(repo: &RepositoryInput, path: &str) -> Result<(String, Vec<u8>)> {
    let listing = git(&repo.checkout, &["ls-tree", "-z", &repo.commit, "--", path])?;
    ensure!(
        listing.starts_with(b"100644 blob ") || listing.starts_with(b"100755 blob "),
        "package requires a local pinned regular Git blob"
    );
    let entry = std::str::from_utf8(&listing)?;
    let (header, name) = entry.split_once('\t').context("invalid Git entry")?;
    ensure!(
        name.strip_suffix('\0') == Some(path),
        "package path mismatch"
    );
    let blob = header
        .split_whitespace()
        .nth(2)
        .context("missing blob identity")?
        .to_string();
    let bytes = git(&repo.checkout, &["cat-file", "blob", &blob])?;
    Ok((blob, bytes))
}

fn package_path(path: &str) -> bool {
    safe_source_path(path)
        && path.split('/').all(|part| {
            !part.starts_with('.')
                && !matches!(
                    part.to_ascii_lowercase().as_str(),
                    "reference"
                        | "references"
                        | "hidden_tests"
                        | "reference_patch"
                        | "vulnerability_labels"
                )
        })
}

pub(crate) fn require_member(manifest: &Manifest, repository: &str, path: &str) -> Result<()> {
    if let Some(profile) = &manifest.experiments {
        ensure!(
            profile.package.contains(repository, path),
            "source is outside the public package"
        );
    }
    Ok(())
}
