use crate::support::*;
use nac_appsec::*;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn source_identity_commit_path_lines_and_hash_are_verified() -> Result<()> {
    assert!(
        serde_json::from_str::<Submission>("Provider error: request interrupted").is_err(),
        "provider failure prose cannot satisfy the structured completion contract"
    );
    let directory = Directory::new()?;
    let controller = open(&directory.0.join("state"), TestClock::new(), 4)?;
    let input = manifest(1)?;
    let submission = candidate(&input)?;
    let campaign = controller.create(input)?;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut Worker::default())?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    for field in [
        "repository",
        "commit",
        "escape",
        "absolute",
        "missing",
        "line",
        "hash",
        "pathspec",
        "normalized",
    ] {
        let mut invalid = submission.clone();
        if let Payload::Candidate { candidate } = &mut invalid.payload {
            match field {
                "repository" => candidate.source.repository = "another".into(),
                "commit" => candidate.source.commit = "a".repeat(40),
                "escape" => candidate.source.path = "../Cargo.toml".into(),
                "absolute" => candidate.source.path = "/etc/passwd".into(),
                "missing" => candidate.source.path = "nonexistent.rs".into(),
                "line" => candidate.source.end_line = u32::MAX,
                "hash" => candidate.source.content_sha256 = "0".repeat(64),
                "pathspec" => candidate.source.path = ":(glob)*".into(),
                _ => candidate.source.path = "./Cargo.toml".into(),
            }
        }
        assert!(
            controller
                .submit(&assignment.lease, field, invalid)
                .is_err(),
            "invalid {field} must be rejected"
        );
    }
    let mut malformed = serde_json::to_value(&submission)?;
    malformed["payload"]["candidate"]["finding_id"] = "model-assigned".into();
    assert!(
        serde_json::from_value::<Submission>(malformed).is_err(),
        "model cannot assign canonical IDs"
    );
    assert!(serde_json::from_str::<Submission>(r#"{"schema_version":1,"payload":{"kind":"stage_result","result":{"status":"completed","scope":"all","extra":true}},"evidence":[]}"#).is_err(), "nested result fields are strict");
    assert_eq!(controller.status(campaign.id)?.accepted.len(), 0);
    Ok(())
}

#[test]
fn missing_corrupt_and_symlink_evidence_never_becomes_accepted() -> Result<()> {
    let directory = Directory::new()?;
    let path = directory.0.join("state");
    let controller = open(&path, TestClock::new(), 4)?;
    let input = manifest(1)?;
    let submission = candidate(&input)?;
    let campaign = controller.create(input)?;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut Worker::default())?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let mut missing = submission.clone();
    missing.evidence = vec![EvidenceInput::Stored {
        artifact: ArtifactRef {
            sha256: "a".repeat(64),
            bytes: 10,
        },
    }];
    assert!(
        controller
            .submit(&assignment.lease, "missing", missing)
            .is_err(),
        "missing artifacts are rejected"
    );
    let accepted = controller.submit(&assignment.lease, "valid", submission.clone())?;
    let evidence = &accepted.evidence[0];
    let artifact_path = path.join(format!("evidence-{}", evidence.sha256));
    std::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&artifact_path, vec![b'x'; evidence.bytes as usize])?;
    assert!(
        controller.status(campaign.id).is_err(),
        "report cannot silently accept corrupt evidence"
    );
    let mut stored = submission.clone();
    stored.evidence = vec![EvidenceInput::Stored {
        artifact: evidence.clone(),
    }];
    assert!(
        controller
            .submit(&assignment.lease, "corrupt", stored.clone())
            .is_err(),
        "corrupt evidence is rejected"
    );
    std::fs::remove_file(&artifact_path)?;
    let outside = directory.0.join("outside");
    std::fs::write(&outside, b"outside stays untouched")?;
    symlink(&outside, &artifact_path)?;
    assert!(
        controller
            .submit(&assignment.lease, "symlink", stored)
            .is_err(),
        "symlink artifacts are rejected"
    );
    assert!(
        controller
            .submit(&assignment.lease, "valid", submission)
            .is_err(),
        "idempotent replay must still verify evidence"
    );
    assert_eq!(std::fs::read(&outside)?, b"outside stays untouched");
    Ok(())
}

#[test]
fn state_paths_reject_symlink_parents_and_database_symlinks() -> Result<()> {
    let directory = Directory::new()?;
    let real = directory.0.join("real");
    std::fs::create_dir(&real)?;
    let link = directory.0.join("link");
    symlink(&real, &link)?;
    assert!(
        SqliteRepository::open(&link.join("state"), 4).is_err(),
        "parent symlink must fail"
    );
    assert!(
        !real.join("state").exists(),
        "unsafe path must not create state"
    );
    let state = directory.0.join("state");
    ArtifactStore::open(&state)?;
    let outside = directory.0.join("outside.sqlite");
    std::fs::write(&outside, b"unchanged")?;
    symlink(&outside, state.join("control.sqlite"))?;
    assert!(
        SqliteRepository::open(&state, 4).is_err(),
        "database symlink must fail"
    );
    assert_eq!(std::fs::read(outside)?, b"unchanged");
    Ok(())
}
