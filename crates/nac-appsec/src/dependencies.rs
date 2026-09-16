use crate::{hash, source::safe_source_path, Result};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefetchedDependency {
    pub schema_version: u32,
    pub package: String,
    pub version: String,
    pub source_url: String,
    pub source_ref: String,
    pub archive_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRead {
    pub package: String,
    pub version: String,
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub archive_sha256: String,
    pub content_sha256: String,
    pub bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<crate::ArtifactRef>,
}

impl PrefetchedDependency {
    pub fn verify_provenance(&self) -> Result<()> {
        crate::require_version(self.schema_version)?;
        ensure!(
            !self.package.is_empty()
                && self.package.len() <= 128
                && !self.version.is_empty()
                && self.version.len() <= 128
                && !self.source_ref.is_empty()
                && self.source_ref.len() <= 256,
            "invalid dependency provenance"
        );
        let authority = self
            .source_url
            .strip_prefix("https://")
            .context("dependency provenance requires an HTTPS source URL")?;
        ensure!(
            !authority.is_empty()
                && self.source_url.len() <= 2048
                && !authority.contains(['@', '?', '#', '\\', '%', '\r', '\n', '\0'])
                && !authority.starts_with('/'),
            "credential-bearing or ambiguous dependency URL"
        );
        ensure!(
            self.archive_sha256.len() == 64
                && self
                    .archive_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid dependency content hash"
        );
        Ok(())
    }

    pub fn read_range(
        &self,
        archive: &Path,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<DependencyRead> {
        self.verify_provenance()?;
        ensure!(safe_source_path(path), "unsafe dependency source path");
        ensure!(
            length <= 256 * 1024,
            "dependency read exceeds response bound"
        );
        let bytes = archive_bytes(self, archive)?;
        let entries = tar_entries(&bytes)?;
        let contents = entries
            .into_iter()
            .find_map(|(name, contents)| (name == path).then_some(contents))
            .context("dependency source path is not in the pinned archive")?;
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(usize::try_from(length)?)
            .context("dependency range overflow")?;
        ensure!(
            start <= contents.len() && end <= contents.len(),
            "dependency range outside pinned source"
        );
        let selected = contents[start..end].to_vec();
        Ok(DependencyRead {
            package: self.package.clone(),
            version: self.version.clone(),
            path: path.into(),
            offset,
            length: selected.len().try_into()?,
            archive_sha256: self.archive_sha256.clone(),
            content_sha256: hash(contents),
            bytes: selected,
            progress: None,
        })
    }

    pub fn materialize(&self, archive: &Path, destination: &Path) -> Result<()> {
        self.verify_provenance()?;
        let bytes = archive_bytes(self, archive)?;
        let entries = tar_entries(&bytes)?;
        ensure!(
            !destination.exists(),
            "dependency destination must be fresh"
        );
        std::fs::create_dir(destination)?;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))?;
        for (name, contents) in entries {
            let path = destination.join(name);
            std::fs::create_dir_all(path.parent().context("invalid archive parent")?)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        crate::package::freeze_directories(destination)?;
        Ok(())
    }
}

fn archive_bytes(dependency: &PrefetchedDependency, archive: &Path) -> Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(archive)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 64 * 1024 * 1024,
        "dependency archive is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024 && hash(&bytes) == dependency.archive_sha256,
        "prefetched dependency content drift"
    );
    Ok(bytes)
}

fn tar_entries(bytes: &[u8]) -> Result<Vec<(String, &[u8])>> {
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut offset = 0usize;
    loop {
        let header = bytes
            .get(offset..offset + 512)
            .context("incomplete prefetched tar header")?;
        if header.iter().all(|byte| *byte == 0) {
            ensure!(
                bytes.len() >= offset + 1024 && bytes[offset..].iter().all(|byte| *byte == 0),
                "invalid prefetched tar terminator"
            );
            return Ok(entries);
        }
        ensure!(
            &header[257..263] == b"ustar\0" && &header[263..265] == b"00",
            "only plain POSIX ustar archives are supported"
        );
        let expected = octal(&header[148..156])?;
        let actual: usize = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    32
                } else {
                    usize::from(*byte)
                }
            })
            .sum();
        ensure!(actual == expected, "invalid prefetched tar checksum");
        ensure!(
            matches!(header[156], 0 | b'0' | b'5'),
            "dependency links and special files are forbidden"
        );
        ensure!(
            header[157..257].iter().all(|byte| *byte == 0),
            "dependency links are forbidden"
        );
        let mut name = text(&header[..100])?.to_string();
        let prefix = text(&header[345..500])?;
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let directory = header[156] == b'5';
        if directory {
            name = name.trim_end_matches('/').to_string();
        }
        ensure!(
            safe_source_path(&name) && name.split('/').all(|part| !part.starts_with('.')),
            "unsafe dependency archive path"
        );
        ensure!(
            names.insert(name.clone()) && names.len() <= 100_000,
            "duplicate or excessive dependency entries"
        );
        let size = octal(&header[124..136])?;
        ensure!(
            size <= 16 * 1024 * 1024 && (!directory || size == 0),
            "dependency entry exceeds bound"
        );
        offset = offset.checked_add(512).context("tar offset overflow")?;
        let end = offset.checked_add(size).context("tar size overflow")?;
        let contents = bytes
            .get(offset..end)
            .context("incomplete dependency entry")?;
        if !directory {
            entries.push((name, contents));
        }
        offset = offset
            .checked_add(size.div_ceil(512) * 512)
            .context("tar alignment overflow")?;
    }
}

fn text(bytes: &[u8]) -> Result<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    ensure!(
        bytes[end..].iter().all(|byte| *byte == 0),
        "ambiguous tar text"
    );
    Ok(std::str::from_utf8(&bytes[..end])?)
}

fn octal(bytes: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        !text.is_empty() && text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "invalid tar number"
    );
    Ok(usize::from_str_radix(text, 8)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(name: &str, kind: u8, contents: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(contents);
        bytes.resize(512 + contents.len().div_ceil(512) * 512 + 1024, 0);
        bytes
    }

    #[test]
    fn prefetched_archive_rejects_traversal_links_special_files_and_truncation() -> Result<()> {
        let bytes = archive(
            "lib/source.rs",
            b'0',
            b"locally authored dependency fixture",
        );
        let entries = tar_entries(&bytes)?;
        assert_eq!(entries[0].0, "lib/source.rs");
        assert_eq!(entries[0].1, b"locally authored dependency fixture");
        for path in [
            "../escape",
            "/absolute",
            "lib/../../escape",
            ".git/config",
            "lib/.secret",
            "a\\b",
        ] {
            assert!(tar_entries(&archive(path, b'0', b"x")).is_err(), "{path}");
        }
        for kind in *b"12346xg" {
            assert!(tar_entries(&archive("lib/file", kind, b"x")).is_err());
        }
        assert!(tar_entries(&bytes[..bytes.len() - 1]).is_err());
        Ok(())
    }

    #[test]
    fn only_matching_prefetched_archive_with_noncredential_https_provenance_materializes(
    ) -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("nac-dependency-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        let bytes = archive("lib/source.rs", b'0', b"operator-prefetched-local-fixture");
        let input = root.join("dependency.tar");
        std::fs::write(&input, &bytes)?;
        let mut dependency = PrefetchedDependency {
            schema_version: 1,
            package: "fixture".into(),
            version: "1.0.0".into(),
            source_url: "https://example.invalid/fixture.tar".into(),
            source_ref: "fixture-v1".into(),
            archive_sha256: hash(&bytes),
        };
        let output = root.join("materialized");
        dependency.materialize(&input, &output)?;
        assert_eq!(
            std::fs::read(output.join("lib/source.rs"))?,
            b"operator-prefetched-local-fixture"
        );
        dependency.archive_sha256 = "0".repeat(64);
        assert!(dependency.materialize(&input, &root.join("drift")).is_err());
        dependency.archive_sha256 = hash(&bytes);
        dependency.source_url = "https://user:secret@example.invalid/fixture.tar".into();
        assert!(dependency
            .materialize(&input, &root.join("credential-url"))
            .is_err());
        std::fs::set_permissions(output.join("lib"), std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
