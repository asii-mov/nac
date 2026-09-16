use anyhow::{ensure, Context, Result};
use nac_appsec::SourcePackage;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub(super) fn copy(source: &Path, destination: &Path) -> Result<String> {
    ensure!(
        source.is_absolute() && !destination.exists(),
        "production export must be absolute and fresh"
    );
    let mut files = Vec::new();
    enumerate(source, source, &mut files)?;
    ensure!(
        !files.is_empty() && files.len() <= 100_000,
        "invalid production export membership"
    );
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let mut manifest = Vec::new();
    for relative in files {
        let input = source.join(&relative);
        let metadata = fs::symlink_metadata(&input)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 16 * 1024 * 1024,
            "production export requires bounded regular files"
        );
        let mut bytes = Vec::new();
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&input)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == metadata.len(),
            "production export changed during copy"
        );
        let digest = super::private::digest(&bytes);
        manifest.extend_from_slice(relative.as_bytes());
        manifest.push(0);
        manifest.extend_from_slice(digest.as_bytes());
        manifest.push(0);
        let output = destination.join(&relative);
        fs::create_dir_all(
            output
                .parent()
                .context("production export parent missing")?,
        )?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_NOFOLLOW)
            .open(output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    freeze(destination)?;
    Ok(super::private::digest(&manifest))
}

fn enumerate(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink() && (kind.is_file() || kind.is_dir()),
            "production export links and special files are forbidden"
        );
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_str()
            .context("production export path is not UTF-8")?
            .replace('\\', "/");
        ensure!(
            safe(&relative),
            "unsafe or answer-bearing production export path"
        );
        if kind.is_dir() {
            enumerate(root, &entry.path(), files)?;
        } else {
            files.push(relative);
        }
    }
    files.sort();
    Ok(())
}

fn safe(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
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
        && !path.contains(['\0', '\r', '\n', ':'])
}

pub(super) fn verify_package_source(source: &Path, package: &SourcePackage) -> Result<()> {
    ensure!(source.is_absolute(), "production source must be absolute");
    let mut actual = Vec::new();
    enumerate(source, source, &mut actual)?;
    let expected: std::collections::BTreeMap<_, _> = package
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content_sha256.as_str()))
        .collect();
    ensure!(
        expected.len() == package.files.len(),
        "production source package has duplicate paths across repositories"
    );
    ensure!(
        actual.len() == expected.len()
            && actual
                .iter()
                .all(|path| expected.contains_key(path.as_str())),
        "production source membership differs from declared pinned export"
    );
    for path in actual {
        let bytes = fs::read(source.join(&path))?;
        ensure!(
            expected[&path.as_str()] == super::private::digest(&bytes),
            "production source blob differs from declared pinned export"
        );
    }
    Ok(())
}

fn freeze(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            freeze(&entry.path())?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
    Ok(())
}
