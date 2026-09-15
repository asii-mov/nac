#![allow(
    clippy::missing_assert_message,
    clippy::unwrap_used,
    reason = "integration-test setup and assertions should fail immediately"
)]

use std::{fs, path::PathBuf, process::Command};

use serde_json::{json, Value};

const BINARY: &str = env!("CARGO_BIN_EXE_nac-web");
const EXAMPLE: &str = include_str!("../../../docs/security/appsec-doctor.example.json");

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("nac-doctor-cli-{}", uuid::Uuid::new_v4()));
        for directory in ["home", "config", "bin", "evaluation"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        Self(root)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BINARY);
        command
            .env_clear()
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("PATH", self.0.join("bin"))
            .current_dir(&self.0);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn appsec_doctor_real_invocation_is_offline_and_exits_blocked_with_reports() {
    let fixture = Fixture::new();
    let mut config: Value = serde_json::from_str(EXAMPLE).unwrap();
    config["evaluation_source"] = json!("evaluation");
    config["tools"] = json!(["doctor-sentinel-tool"]);
    fs::write(fixture.0.join("doctor.json"), config.to_string()).unwrap();
    fs::write(
        fixture.0.join("evaluation/answer-key"),
        "external-answer-sentinel",
    )
    .unwrap();
    let tool = fixture.0.join("bin/doctor-sentinel-tool");
    fs::write(&tool, "#!/bin/sh\necho invoked > tool-was-executed\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let result = fixture
        .command()
        .args([
            "appsec",
            "doctor",
            "--config",
            "doctor.json",
            "--output",
            "result",
        ])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(fixture.0.join("result/doctor.json")).unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["ready"], false);
    assert_eq!(report["offline"], true);
    assert_eq!(report["model_execution"], false);
    assert_eq!(report["requested"], config);
    let markdown = fs::read_to_string(fixture.0.join("result/doctor.md")).unwrap();
    assert!(markdown.contains("Readiness: blocked"));
    assert!(markdown.contains("No credentials or headers are loaded"));
    assert!(!markdown.contains("external-answer-sentinel"));
    assert!(!fixture.0.join("tool-was-executed").exists());
    assert_eq!(fs::read_dir(fixture.0.join("home")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(fixture.0.join("config")).unwrap().count(), 0);
    assert!(!fixture.0.join(".nac").exists());
    let repeat = fixture
        .command()
        .args([
            "appsec",
            "doctor",
            "--config",
            "doctor.json",
            "--output",
            "result",
        ])
        .output()
        .unwrap();
    assert_eq!(repeat.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.0.join("result/doctor.json")).unwrap(),
        bytes
    );
}

#[test]
fn appsec_doctor_distinguishes_bad_config_and_io_without_echoing_secrets() {
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("doctor.json"),
        "{\"api_key\":\"secret-sentinel\"}",
    )
    .unwrap();
    let result = fixture
        .command()
        .args([
            "appsec",
            "doctor",
            "--config",
            "doctor.json",
            "--output",
            "result",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-sentinel"));
    assert!(!fixture.0.join("result").exists());
    let result = fixture
        .command()
        .args([
            "appsec",
            "doctor",
            "--config",
            "missing.json",
            "--output",
            "result",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!fixture.0.join("result").exists());
}
