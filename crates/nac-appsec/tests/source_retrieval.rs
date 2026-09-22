#[allow(
    dead_code,
    reason = "shared integration support exposes a broader fixture API"
)]
mod support;
use anyhow::Result;
use nac_appsec::*;
use support::*;

#[test]
fn pinned_retrieval_is_fenced_bounded_and_deduplicated_across_ranges() -> Result<()> {
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest(1)?)?;
    let mut runtime = Worker::default();
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .unwrap();
    let read = SourceRead {
        repository: "nac-test".into(),
        path: "Cargo.toml".into(),
        start_line: 1,
        end_line: 1,
    };
    let first = controller.read_source(&assignment.lease, read.clone())?;
    assert_eq!(first.text, "[workspace]");
    let next = controller.read_source(
        &assignment.lease,
        SourceRead {
            start_line: 2,
            end_line: 3,
            ..read.clone()
        },
    )?;
    assert_eq!(
        first.progress, next.progress,
        "different ranges of the same verified blob cannot manufacture new progress"
    );
    for path in [
        ".git/config",
        "../control.sqlite",
        "Cargo.toml:HEAD",
        "Cargo.toml/../Cargo.toml",
        "/etc/passwd",
    ] {
        assert!(
            controller
                .read_source(
                    &assignment.lease,
                    SourceRead {
                        path: path.into(),
                        ..read.clone()
                    }
                )
                .is_err(),
            "unsafe path must not be retrieved: {path}"
        );
    }
    let status = controller.status(campaign.id)?;
    controller.cancel(campaign.id, status.revision)?;
    assert!(
        controller.read_source(&assignment.lease, read).is_err(),
        "revoked connections cannot retrieve source"
    );
    assert!(
        controller
            .list_source_files(
                &assignment.lease,
                SourceInventory {
                    repository: "nac-test".into(),
                    after: None,
                    limit: 10
                }
            )
            .is_err(),
        "revoked connections cannot enumerate source"
    );
    Ok(())
}

#[test]
fn small_range_of_large_pinned_file_keeps_original_blob_hash_and_response_bound() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::process::Command;
    let directory = Directory::new()?;
    let repository = directory.0.join("repository");
    std::fs::create_dir(&repository)?;
    let content = format!(
        "{}near-end-marker\n",
        "ordinary pinned source line\n".repeat(1200)
    );
    std::fs::write(repository.join("large.txt"), &content)?;
    for args in [
        vec!["init", "-q"],
        vec!["add", "large.txt"],
        vec!["commit", "-qm", "scripted source fixture"],
    ] {
        anyhow::ensure!(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(args)
                .status()?
                .success(),
            "fixture git command failed"
        );
    }
    let commit = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    let mut manifest = manifest(1)?;
    manifest.repositories[0].checkout = repository.clone();
    manifest.repositories[0].commit = String::from_utf8(commit.stdout)?.trim().to_string();
    manifest.tasks[0].operation_limits.output_bytes = 16384;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut Worker::default())?
        .unwrap();
    std::fs::write(
        repository.join("large.txt"),
        "working tree must not replace pinned content",
    )?;
    let request = SourceRead {
        repository: "nac-test".into(),
        path: "large.txt".into(),
        start_line: 1201,
        end_line: 1201,
    };
    let receipt = controller.read_source(&assignment.lease, request.clone())?;
    assert_eq!(receipt.text, "near-end-marker");
    assert_eq!(
        receipt.source.content_sha256,
        format!("{:x}", Sha256::digest(content.as_bytes()))
    );
    assert!(serde_json::to_vec(&receipt)?.len() <= 16384);
    assert!(
        controller
            .read_source(
                &assignment.lease,
                SourceRead {
                    start_line: 1,
                    ..request
                }
            )
            .is_err(),
        "the complete oversized response must still be rejected"
    );
    Ok(())
}

#[test]
fn source_inventory_pages_fit_receipt_limit_without_exposing_undeclared_paths() -> Result<()> {
    let directory = Directory::new()?;
    let mut manifest = manifest(1)?;
    manifest.tasks[0].operation_limits.output_bytes = 512;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let campaign = controller.create(manifest)?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut Worker::default())?
        .unwrap();
    let first = controller.list_source_files(
        &assignment.lease,
        SourceInventory {
            repository: "nac-test".into(),
            after: None,
            limit: 256,
        },
    )?;
    assert!(!first.files.is_empty() && first.files.len() < 256 && first.next_after.is_some());
    assert!(serde_json::to_vec(&first)?.len() <= 512);
    assert!(first.files.iter().all(|path| !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))));
    let second = controller.list_source_files(
        &assignment.lease,
        SourceInventory {
            repository: "nac-test".into(),
            after: first.next_after.clone(),
            limit: 256,
        },
    )?;
    assert!(serde_json::to_vec(&second)?.len() <= 512);
    assert!(second
        .files
        .iter()
        .all(|path| path > first.files.last().unwrap()));
    assert!(controller
        .list_source_files(
            &assignment.lease,
            SourceInventory {
                repository: "undeclared".into(),
                after: None,
                limit: 10
            }
        )
        .is_err());
    assert!(controller
        .list_source_files(
            &assignment.lease,
            SourceInventory {
                repository: "nac-test".into(),
                after: Some("../control.sqlite".into()),
                limit: 10
            }
        )
        .is_err());
    Ok(())
}
