use crate::support::*;
use nac_appsec::*;
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn git_at(path: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "local Git fixture command failed: {arguments:?}"
    );
    Ok(output.stdout)
}

fn objects(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut directories = vec![path.join(".git/objects")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            } else {
                files.insert(
                    entry.path().strip_prefix(path)?.to_path_buf(),
                    std::fs::read(entry.path())?,
                );
            }
        }
    }
    Ok(files)
}

fn blob_missing(path: &Path, blob: &str) -> Result<bool> {
    Ok(!Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["cat-file", "-e", blob])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .output()?
        .status
        .success())
}

#[test]
#[ignore = "isolated process entry point for traced source validation"]
fn offline_source_entry() -> Result<()> {
    let state = PathBuf::from(std::env::var("APPSEC_TEST_OFFLINE_STATE")?);
    let lease: Lease = serde_json::from_str(&std::env::var("APPSEC_TEST_OFFLINE_LEASE")?)?;
    let controller = open(&state, TestClock::new(), 4)?;
    let campaign = controller.status(lease.run_id)?;
    let result = controller.submit(&lease, "missing-local-blob", candidate(&campaign.manifest)?);
    anyhow::ensure!(
        result.is_err(),
        "source validation unexpectedly fetched a missing blob"
    );
    Ok(())
}

#[test]
fn partial_clone_source_validation_never_fetches_or_materializes_objects() -> Result<()> {
    let directory = Directory::new()?;
    let input = manifest(1)?;
    let remote = directory.0.join("remote.git");
    let remote_url = format!("file://{}", remote.display());
    let root_url = format!("file://{}", input.repositories[0].checkout.display());
    git_at(
        &directory.0,
        &[
            "clone",
            "--bare",
            "--depth=1",
            "--filter=blob:none",
            "--upload-pack=git -c uploadpack.allowFilter=true upload-pack",
            &root_url,
            remote
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid path"))?,
        ],
    )?;
    let bytes = git(&[
        "show",
        &format!("{}:Cargo.toml", input.repositories[0].commit),
    ])?;
    let mut writer = Command::new("git")
        .arg("-C")
        .arg(&remote)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    writer
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing stdin"))?
        .write_all(&bytes)?;
    anyhow::ensure!(
        writer.wait()?.success(),
        "failed to provision the local source blob"
    );
    git_at(&remote, &["config", "uploadpack.allowFilter", "true"])?;
    let subject = directory.0.join("subject");
    let control = directory.0.join("control");
    for clone in [&subject, &control] {
        git_at(
            &directory.0,
            &[
                "clone",
                "--no-checkout",
                "--filter=blob:none",
                &remote_url,
                clone
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid path"))?,
            ],
        )?;
        assert_eq!(
            String::from_utf8(git_at(clone, &["config", "remote.origin.promisor"])?)?.trim(),
            "true"
        );
    }
    let commit = &input.repositories[0].commit;
    let source = format!("{commit}:Cargo.toml");
    let blob = String::from_utf8(git_at(&subject, &["rev-parse", &source])?)?
        .trim()
        .to_string();
    assert!(
        blob_missing(&subject, &blob)?,
        "subject must begin without the source blob"
    );
    assert!(
        blob_missing(&control, &blob)?,
        "control must begin without the source blob"
    );
    let control_trace = directory.0.join("control.trace");
    let fetched = Command::new("git")
        .arg("-C")
        .arg(&control)
        .args(["show", &source])
        .env("GIT_TRACE", &control_trace)
        .output()?;
    assert!(
        fetched.status.success(),
        "the local promisor remote can serve the missing object"
    );
    assert!(
        !blob_missing(&control, &blob)?,
        "unrestricted control materializes the blob"
    );
    assert!(
        std::fs::read_to_string(control_trace)?.contains("git fetch"),
        "control trace proves implicit fetching"
    );
    let before = objects(&subject)?;
    let state = directory.0.join("state");
    let controller = open(&state, TestClock::new(), 4)?;
    let mut input = input;
    input.repositories[0].checkout = subject.clone();
    let campaign = controller.create(input)?;
    let assignment = controller
        .dispatch_next(campaign.id, 0, &mut Worker::default())?
        .ok_or_else(|| anyhow::anyhow!("not admitted"))?;
    let trace = directory.0.join("subject.trace");
    let result = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "offline_source::offline_source_entry",
            "--ignored",
            "--nocapture",
        ])
        .env("APPSEC_TEST_OFFLINE_STATE", &state)
        .env(
            "APPSEC_TEST_OFFLINE_LEASE",
            serde_json::to_string(&assignment.lease)?,
        )
        .env("GIT_TRACE", &trace)
        .output()?;
    assert!(
        result.status.success(),
        "isolated validation must reject the missing local blob: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    let trace = std::fs::read_to_string(trace)?;
    assert!(
        !trace.contains("git fetch") && !trace.contains("git-upload-pack"),
        "validation cannot launch a transport"
    );
    assert!(
        blob_missing(&subject, &blob)?,
        "validation leaves the missing blob missing"
    );
    assert_eq!(
        objects(&subject)?,
        before,
        "validation must not change the object store"
    );
    assert!(
        controller.status(campaign.id)?.accepted.is_empty(),
        "missing source cannot support accepted evidence"
    );
    Ok(())
}
