use super::{
    docker::inspect, private, process, BuildDiagnosticProjection, BuildOutputStream, FrozenPilot,
};
use anyhow::{ensure, Context, Result};
use nac_appsec::ExperimentCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{ffi::OsString, path::Path};

const BUILD_OUTPUT_CAP: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildOutputRecord {
    stdout_total: u64,
    stderr_total: u64,
    stdout_complete: bool,
    stderr_complete: bool,
    projection: Vec<BuildDiagnosticProjection>,
}

struct CapturedStream<'a> {
    kind: BuildOutputStream,
    full: &'a [u8],
    head: &'a [u8],
    tail: &'a [u8],
    total: u64,
    complete: bool,
}

pub(super) fn verify_build(recipe: &FrozenPilot, source: &Path, root: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let expected_receipt = serde_json::json!({"schema_version":1,"source":recipe.source_export_sha256,"builder":recipe.builder_image,"build":recipe.build_receipt_sha256,"image":recipe.image});
    let receipt_path = root.join(format!(
        "receipt-{}.json",
        private::digest(&serde_json::to_vec(&expected_receipt)?)
    ));
    if receipt_path.exists() {
        let receipt: Value = private::read(&receipt_path)?;
        ensure!(
            receipt == expected_receipt,
            "controlled build receipt drift"
        );
        return Ok(());
    }
    let suffix = &private::digest(recipe.id.as_bytes())[..20];
    let name = format!("nac-appsec-build-{suffix}");
    let inspect_name = format!("nac-appsec-image-{suffix}");
    remove_owned(&name, "nac.appsec.build", &recipe.id)?;
    remove_owned(&inspect_name, "nac.appsec.build", &recipe.id)?;
    let output = root.join(&recipe.id);
    if output.exists() {
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
        std::fs::remove_dir_all(&output)?;
    }
    std::fs::DirBuilder::new().mode(0o777).create(&output)?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o777))?;
    let source_mount = format!("{}:/src:ro", source.display());
    let output_mount = format!("{}:/out:rw", output.display());
    let arguments = [
        "create",
        "--pull=never",
        "--name",
        &name,
        "--label",
        &format!("nac.appsec.build={}", recipe.id),
        "--network",
        "none",
        "--user",
        "65534:65534",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=536870912,uid=65534,gid=65534,mode=0700",
        "--volume",
        &source_mount,
        "--volume",
        &output_mount,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "seccomp=builtin",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        "128",
        "--memory",
        "1073741824",
        "--memory-swap",
        "1073741824",
        "--cpus",
        "1",
        "--log-driver",
        "none",
        "--workdir",
        "/src",
        "--env",
        "PATH=/usr/local/go/bin:/usr/bin:/bin",
        "--env",
        "HOME=/tmp",
        "--env",
        "GOCACHE=/tmp/go-cache",
        "--env",
        "GOPROXY=off",
        "--env",
        "GOSUMDB=off",
        "--env",
        "CGO_ENABLED=0",
        "--env",
        "GOOS=linux",
        "--env",
        "GOARCH=amd64",
        "--entrypoint",
        "/usr/local/go/bin/go",
        &recipe.builder_image,
        "build",
        "-trimpath",
        "-ldflags=-s -w -buildid=",
        "-o",
        "/out/target",
        "main.go",
    ];
    let result = (|| {
        process::docker(&arguments)?;
        let inspected = inspect(&name)?;
        verify_builder(&inspected, recipe, &name, &source_mount, &output_mount)?;
        let build_output = process::execute(
            "/usr/bin/docker",
            &[
                OsString::from("start"),
                OsString::from("--attach"),
                OsString::from(&name),
            ],
            vec![],
            180_000,
            BUILD_OUTPUT_CAP,
        )?;
        let projection = retain_output(root, &recipe.id, source, &build_output)?;
        let inspected = inspect(&name)?;
        verify_builder(&inspected, recipe, &name, &source_mount, &output_mount)?;
        ensure!(
            inspected["State"]["Running"] == false,
            "controlled build termination uncertain"
        );
        ensure!(
            build_output.success && inspected["State"]["ExitCode"] == 0,
            "controlled target build failed: {}",
            serde_json::to_string(&projection)?
        );
        let binary = std::fs::read(output.join("target"))?;
        ensure!(
            private::digest(&binary) == recipe.build_receipt_sha256,
            "controlled build receipt drift"
        );
        process::docker(&[
            "create",
            "--pull=never",
            "--name",
            &inspect_name,
            "--label",
            &format!("nac.appsec.build={}", recipe.id),
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "seccomp=builtin",
            "--security-opt",
            "no-new-privileges=true",
            "--entrypoint",
            "/target",
            &recipe.image,
            "echo",
        ])?;
        let image_binary = output.join("image-target");
        let arguments = [
            OsString::from("cp"),
            OsString::from(format!("{inspect_name}:/target")),
            image_binary.as_os_str().to_owned(),
        ];
        let copied = process::execute("/usr/bin/docker", &arguments, vec![], 30_000, 4096)?;
        ensure!(
            copied.success && copied.complete,
            "target image inspection failed"
        );
        ensure!(
            private::digest(&std::fs::read(image_binary)?) == recipe.build_receipt_sha256,
            "target image differs from controlled build"
        );
        Ok(())
    })();
    let cleanup = remove_owned(&name, "nac.appsec.build", &recipe.id)
        .and_then(|_| remove_owned(&inspect_name, "nac.appsec.build", &recipe.id));
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
    std::fs::remove_dir_all(output)?;
    result.and(cleanup)?;
    private::write(&receipt_path, &expected_receipt)
}

pub(super) fn read_projection(
    root: &Path,
    pilot_id: &str,
) -> Result<Vec<BuildDiagnosticProjection>> {
    ensure!(
        !pilot_id.is_empty()
            && pilot_id.len() <= 128
            && pilot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid private pilot identity"
    );
    let key = private::digest(pilot_id.as_bytes());
    let record: BuildOutputRecord = private::read(&root.join(format!("{key}.json")))?;
    Ok(record.projection)
}

fn retain_output(
    root: &Path,
    pilot_id: &str,
    source: &Path,
    output: &process::Output,
) -> Result<Vec<BuildDiagnosticProjection>> {
    private::directory(root)?;
    let key = private::digest(pilot_id.as_bytes());
    let stdout = retained(
        &output.full,
        &output.bytes,
        &output.tail,
        output.stdout_complete,
    );
    let stderr = retained(
        &output.stderr_full,
        &output.stderr_bytes,
        &output.stderr_tail,
        output.stderr_complete,
    );
    private::write_bytes(&root.join(format!("{key}.stdout.bin")), &stdout)?;
    private::write_bytes(&root.join(format!("{key}.stderr.bin")), &stderr)?;
    let mut projection = Vec::new();
    project_stream(
        source,
        CapturedStream {
            kind: BuildOutputStream::Stdout,
            full: &output.full,
            head: &output.bytes,
            tail: &output.tail,
            total: output.total,
            complete: output.stdout_complete,
        },
        &mut projection,
    )?;
    project_stream(
        source,
        CapturedStream {
            kind: BuildOutputStream::Stderr,
            full: &output.stderr_full,
            head: &output.stderr_bytes,
            tail: &output.stderr_tail,
            total: output.stderr_total,
            complete: output.stderr_complete,
        },
        &mut projection,
    )?;
    if !output.stdout_complete || !output.stderr_complete {
        projection.insert(
            0,
            BuildDiagnosticProjection {
                code: ExperimentCode::CaptureIncomplete,
                stream: None,
                source_path: None,
                line: None,
                column: None,
                byte_offset: None,
                truncated: true,
            },
        );
    }
    if !projection
        .iter()
        .any(|item| item.code == ExperimentCode::RecognizedTargetError)
    {
        projection.push(BuildDiagnosticProjection {
            code: ExperimentCode::UnknownOutputWithheld,
            stream: None,
            source_path: None,
            line: None,
            column: None,
            byte_offset: None,
            truncated: true,
        });
    }
    private::write(
        &root.join(format!("{key}.json")),
        &BuildOutputRecord {
            stdout_total: output.total,
            stderr_total: output.stderr_total,
            stdout_complete: output.stdout_complete,
            stderr_complete: output.stderr_complete,
            projection: projection.clone(),
        },
    )?;
    Ok(projection)
}

fn retained(full: &[u8], head: &[u8], tail: &[u8], complete: bool) -> Vec<u8> {
    if complete {
        return full.to_vec();
    }
    let mut retained = Vec::with_capacity(head.len() + tail.len());
    retained.extend_from_slice(head);
    retained.extend_from_slice(tail);
    retained
}

fn project_stream(
    source: &Path,
    stream: CapturedStream<'_>,
    projection: &mut Vec<BuildDiagnosticProjection>,
) -> Result<()> {
    if stream.complete {
        project_region(source, stream.kind, stream.full, 0, false, projection)?;
    } else {
        project_region(source, stream.kind, stream.head, 0, true, projection)?;
        project_region(
            source,
            stream.kind,
            stream.tail,
            stream.total.saturating_sub(stream.tail.len() as u64),
            true,
            projection,
        )?;
    }
    Ok(())
}

fn project_region(
    source: &Path,
    stream: BuildOutputStream,
    bytes: &[u8],
    base: u64,
    truncated: bool,
    projection: &mut Vec<BuildDiagnosticProjection>,
) -> Result<()> {
    if projection.len() >= 32 {
        return Ok(());
    }
    let source_bytes = std::fs::read(source.join("main.go"))?;
    ensure!(
        std::fs::symlink_metadata(source.join("main.go"))?
            .file_type()
            .is_file(),
        "controlled build source is not regular"
    );
    let mut offset = 0usize;
    for line_bytes in bytes.split_inclusive(|byte| *byte == b'\n') {
        if projection.len() >= 32 {
            break;
        }
        let line = line_bytes.strip_suffix(b"\n").unwrap_or(line_bytes);
        if let Some((line_number, column)) = parse_location(line) {
            if valid_position(&source_bytes, line_number, column) {
                projection.push(BuildDiagnosticProjection {
                    code: ExperimentCode::RecognizedTargetError,
                    stream: Some(stream),
                    source_path: Some("main.go".into()),
                    line: Some(line_number),
                    column,
                    byte_offset: Some(base.saturating_add(offset as u64)),
                    truncated,
                });
            }
        }
        offset = offset.saturating_add(line_bytes.len());
    }
    Ok(())
}

fn parse_location(bytes: &[u8]) -> Option<(u32, Option<u32>)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let rest = text
        .strip_prefix("./main.go:")
        .or_else(|| text.strip_prefix("main.go:"))?;
    let mut parts = rest.split(':');
    let line = parts.next()?.parse().ok()?;
    let column = parts.next().and_then(|value| value.parse().ok());
    Some((line, column))
}

fn valid_position(source: &[u8], line: u32, column: Option<u32>) -> bool {
    if line == 0 {
        return false;
    }
    let Some(bytes) = source.split(|byte| *byte == b'\n').nth(line as usize - 1) else {
        return false;
    };
    column.is_none_or(|column| column > 0 && column as usize <= bytes.len().saturating_add(1))
}

fn verify_builder(
    value: &Value,
    recipe: &FrozenPilot,
    name: &str,
    source: &str,
    output: &str,
) -> Result<()> {
    let host = &value["HostConfig"];
    let config = &value["Config"];
    ensure!(
        value["Image"] == recipe.builder_image
            && config["Image"] == recipe.builder_image
            && config["User"] == "65534:65534"
            && config["WorkingDir"] == "/src"
            && config["Entrypoint"] == serde_json::json!(["/usr/local/go/bin/go"]),
        "builder identity drift"
    );
    ensure!(
        config["Cmd"]
            == serde_json::json!([
                "build",
                "-trimpath",
                "-ldflags=-s -w -buildid=",
                "-o",
                "/out/target",
                "main.go"
            ]),
        "builder command drift"
    );
    let environment: std::collections::BTreeSet<_> = config["Env"]
        .as_array()
        .context("builder environment missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: std::collections::BTreeSet<_> = [
        "PATH=/usr/local/go/bin:/usr/bin:/bin",
        "HOME=/tmp",
        "GOCACHE=/tmp/go-cache",
        "GOPROXY=off",
        "GOSUMDB=off",
        "CGO_ENABLED=0",
        "GOOS=linux",
        "GOARCH=amd64",
    ]
    .into_iter()
    .collect();
    ensure!(
        environment == expected
            && config["Env"]
                .as_array()
                .is_some_and(|values| values.len() == expected.len()),
        "builder environment drift"
    );
    ensure!(
        host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host["CapDrop"] == serde_json::json!(["ALL"])
            && host["CapAdd"].is_null()
            && host["NetworkMode"] == "none"
            && host["LogConfig"]["Type"] == "none",
        "builder isolation drift"
    );
    ensure!(
        host["SecurityOpt"] == serde_json::json!(["seccomp=builtin", "no-new-privileges=true"])
            && host["PidsLimit"] == 128
            && host["Memory"] == 1073741824u64
            && host["MemorySwap"] == 1073741824u64
            && host["NanoCpus"] == 1_000_000_000u64,
        "builder resource policy drift"
    );
    let binds: std::collections::BTreeSet<_> = host["Binds"]
        .as_array()
        .context("builder binds missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected_binds = std::collections::BTreeSet::from([source, output]);
    ensure!(
        binds == expected_binds
            && host["Binds"]
                .as_array()
                .is_some_and(|values| values.len() == 2),
        "builder bind policy drift: {}",
        host["Binds"]
    );
    ensure!(
        host["Tmpfs"]
            == serde_json::json!({"/tmp":"rw,noexec,nosuid,nodev,size=536870912,uid=65534,gid=65534,mode=0700"}),
        "builder writable-path policy drift"
    );
    ensure!(
        host["PidMode"] == ""
            && host["IpcMode"] == "private"
            && host["Devices"] == serde_json::json!([]),
        "builder namespace policy drift"
    );
    ensure!(
        config["Labels"]["nac.appsec.build"] == recipe.id && value["Name"] == format!("/{name}"),
        "builder ownership drift"
    );
    Ok(())
}

fn remove_owned(name: &str, label: &str, value: &str) -> Result<()> {
    let listed = process::docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("name=^/{name}$"),
        "--format",
        "{{.Names}}",
    ])?;
    if listed.is_empty() {
        return Ok(());
    }
    let inspected = inspect(name)?;
    ensure!(
        inspected["Config"]["Labels"][label] == value,
        "build cleanup ownership uncertain"
    );
    process::docker(&["rm", "--force", name])?;
    ensure!(
        process::docker(&[
            "ps",
            "-a",
            "--filter",
            &format!("name=^/{name}$"),
            "--format",
            "{{.Names}}"
        ])?
        .is_empty(),
        "build cleanup uncertain"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_large_private_builder_output_and_projects_only_valid_location() -> Result<()> {
        let parent =
            std::env::temp_dir().join(format!("nac-appsec-build-output-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&parent)?;
        let source = parent.join("source");
        std::fs::create_dir(&source)?;
        std::fs::write(
            source.join("main.go"),
            b"package main\nfunc main() {\n missing\n}\n",
        )?;
        let secret = "private-build-secret";
        let mut stderr = vec![b'x'; 128 * 1024];
        stderr.extend_from_slice(b"\n./main.go:3:2: undefined: ");
        stderr.extend_from_slice(secret.as_bytes());
        stderr.push(b'\n');
        let output = process::Output {
            bytes: vec![],
            tail: vec![],
            total: 0,
            stdout_complete: true,
            stderr_bytes: stderr.clone(),
            stderr_tail: vec![],
            stderr_total: stderr.len() as u64,
            stderr_complete: true,
            complete: true,
            success: false,
            full: vec![],
            stderr_full: stderr.clone(),
        };
        let root = parent.join("diagnostics");
        let projection = retain_output(&root, "failed-pilot", &source, &output)?;
        assert_eq!(
            projection,
            vec![BuildDiagnosticProjection {
                code: ExperimentCode::RecognizedTargetError,
                stream: Some(BuildOutputStream::Stderr),
                source_path: Some("main.go".into()),
                line: Some(3),
                column: Some(2),
                byte_offset: Some(128 * 1024 + 1),
                truncated: false,
            }]
        );
        let public = serde_json::to_vec(&projection)?;
        assert!(!String::from_utf8(public)?.contains(secret));
        assert_eq!(read_projection(&root, "failed-pilot")?, projection);
        let key = private::digest(b"failed-pilot");
        assert_eq!(
            private::bytes(
                &root.join(format!("{key}.stderr.bin")),
                BUILD_OUTPUT_CAP as u64
            )?,
            stderr
        );
        std::fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn marks_overflow_incomplete_and_finds_a_late_retained_location() -> Result<()> {
        let parent = std::env::temp_dir().join(format!(
            "nac-appsec-build-overflow-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&parent)?;
        let source = parent.join("source");
        std::fs::create_dir(&source)?;
        std::fs::write(source.join("main.go"), b"package main\nmissing\n")?;
        let tail = b"adversarial private text\n./main.go:2:1: undefined: missing\n".to_vec();
        let output = process::Output {
            bytes: b"head without a location\n".to_vec(),
            tail: vec![],
            total: 24,
            stdout_complete: true,
            stderr_bytes: b"private head\n".to_vec(),
            stderr_tail: tail.clone(),
            stderr_total: 1_000_000,
            stderr_complete: false,
            complete: false,
            success: false,
            full: b"head without a location\n".to_vec(),
            stderr_full: b"private head\n".to_vec(),
        };
        let root = parent.join("diagnostics");
        let projection = retain_output(&root, "overflow-pilot", &source, &output)?;
        assert_eq!(projection[0].code, ExperimentCode::CaptureIncomplete);
        let recognized = projection
            .iter()
            .find(|item| item.code == ExperimentCode::RecognizedTargetError)
            .context("late compiler location was not projected")?;
        assert!(recognized.truncated);
        assert!(recognized
            .byte_offset
            .is_some_and(|offset| offset > 900_000));
        assert!(!serde_json::to_string(&projection)?.contains("adversarial"));
        std::fs::remove_dir_all(parent)?;
        Ok(())
    }
}
