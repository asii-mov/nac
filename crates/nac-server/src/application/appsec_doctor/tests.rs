#![allow(
    clippy::missing_assert_message,
    clippy::unwrap_used,
    reason = "tests fail immediately on unexpected results"
)]

use super::*;
use report::Status;
use serde_json::{json, Value};

const EXAMPLE: &str = include_str!("../../../../../docs/security/appsec-doctor.example.json");

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nac-doctor-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn parse(value: &Value) -> Result<DoctorConfig, DoctorError> {
    DoctorConfig::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn strict_schema_rejects_unknown_missing_duplicate_and_unsupported_fields() {
    let original: Value = serde_json::from_str(EXAMPLE).unwrap();
    for pointer in [
        "/schema_version",
        "/backend",
        "/model",
        "/reasoning",
        "/monetary_policy",
        "/limits",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(&pointer[1..]);
        assert!(parse(&value).is_err(), "missing {pointer}");
    }
    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/backend", json!("openai-responses")),
        ("/backend", json!("daybreak")),
        ("/backend", json!({"chatgpt-codex-responses": null})),
        ("/reasoning", json!("auto")),
        ("/reasoning", json!({"high": null})),
        ("/monetary_policy", json!(0)),
        ("/monetary_policy", json!({"uncapped": null})),
        ("/monetary_policy", Value::Null),
        ("/model", json!("")),
        ("/model", json!(" gpt-5.6-sol")),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(parse(&value).is_err(), "{pointer}");
    }
    for key in [
        "api_key",
        "headers",
        "account_id",
        "provider",
        "runtime_profile",
    ] {
        let mut value = original.clone();
        value[key] = json!("sensitive-sentinel");
        let error = parse(&value).unwrap_err().to_string();
        assert!(!error.contains("sensitive-sentinel"));
    }
    let mut value = original;
    value["limits"]["unbounded"] = json!(true);
    assert!(parse(&value).is_err());
    let duplicate = EXAMPLE.replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    assert!(DoctorConfig::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn operational_limits_reject_zero_unbounded_and_contradictory_values() {
    let original: Value = serde_json::from_str(EXAMPLE).unwrap();
    for key in original["limits"].as_object().unwrap().keys() {
        for invalid in [
            json!(-1),
            json!(1.5),
            json!("unbounded"),
            Value::Null,
            json!(1e100),
        ] {
            let mut value = original.clone();
            value["limits"][key] = invalid;
            assert!(parse(&value).is_err(), "{key}");
        }
        let mut value = original.clone();
        value["limits"].as_object_mut().unwrap().remove(key);
        assert!(parse(&value).is_err(), "missing {key}");
    }
    for key in [
        "active_agents",
        "task_tokens",
        "task_seconds",
        "tool_output_bytes_per_response",
        "tool_output_bytes_total",
    ] {
        let mut value = original.clone();
        value["limits"][key] = json!(0);
        assert!(parse(&value).is_err(), "zero {key}");
    }
    let mut value = original.clone();
    value["limits"]["active_agents"] = json!(5);
    assert!(parse(&value).is_err());
    value = original;
    value["limits"]["tool_output_bytes_total"] = json!(1);
    assert!(parse(&value).is_err());
    value["limits"]["tool_output_bytes_per_response"] = json!(1);
    assert!(parse(&value).is_ok());
}

#[test]
fn zero_transient_retries_requests_no_retries_without_implying_enforcement() {
    let mut value: Value = serde_json::from_str(EXAMPLE).unwrap();
    value["limits"]["transient_retries"] = json!(0);
    let config = parse(&value).unwrap();
    let report = DoctorReport::inspect(config, Path::new("doctor.json"), None);
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(report["requested"]["limits"]["transient_retries"], 0);
    assert_eq!(report["limits_enforced"], false);
    assert_eq!(report["ready"], false);
}

#[test]
fn subscription_only_config_preserves_requested_settings_and_blocks_runtime_readiness() {
    let config = DoctorConfig::parse(EXAMPLE.as_bytes()).unwrap();
    let report = DoctorReport::inspect(config, Path::new("doctor.json"), None);
    assert!(!report.ready);
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["requested"]["model"], "gpt-5.6-sol");
    assert_eq!(value["requested"]["reasoning"], "high");
    assert_eq!(value["requested"]["backend"], "chatgpt-codex-responses");
    assert_eq!(value["requested"]["monetary_policy"], "uncapped");
    assert_eq!(
        value["requested"]["limits"],
        serde_json::from_str::<Value>(EXAMPLE).unwrap()["limits"]
    );
    assert_eq!(value["model_execution"], false);
    assert_eq!(value["offline"], true);
    assert_eq!(value["limits_enforced"], false);
    assert!(report
        .checks
        .iter()
        .any(|c| c.required && c.status == Status::Unsupported));
    assert!(report
        .checks
        .iter()
        .any(|c| c.required && c.status == Status::NotTested));
    assert_eq!(
        report.ready,
        report
            .checks
            .iter()
            .all(|c| !c.required || c.status == Status::Verified)
    );
    let evaluation = report
        .checks
        .iter()
        .find(|c| c.id == "evaluation_source")
        .unwrap();
    assert!(!evaluation.required);
    assert_eq!(evaluation.status, Status::NotTested);
    assert!(!report.checks.iter().any(|c| c.id.starts_with("tool:")));
}

#[test]
fn evaluation_availability_is_relative_to_config_without_reading_contents() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("source")).unwrap();
    fs::write(
        fixture.0.join("source/answer-key"),
        "must-not-read-sentinel",
    )
    .unwrap();
    let mut value: Value = serde_json::from_str(EXAMPLE).unwrap();
    for (source, expected) in [
        ("source", Status::Verified),
        ("missing", Status::NotTested),
        ("source/answer-key", Status::NotTested),
    ] {
        value["evaluation_source"] = json!(source);
        let report =
            DoctorReport::inspect(parse(&value).unwrap(), &fixture.0.join("config.json"), None);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "evaluation_source")
            .unwrap();
        assert!(check.required);
        assert_eq!(check.status, expected);
        assert!(!report.ready);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("must-not-read-sentinel"));
    }
}

#[cfg(unix)]
#[test]
fn requested_tools_check_mode_bits_without_execution() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let tool = fixture.0.join("sentinel-tool");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\ntouch '{}'\n",
            fixture.0.join("executed").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    let mut value: Value = serde_json::from_str(EXAMPLE).unwrap();
    value["tools"] = json!(["sentinel-tool", "missing-tool"]);
    let report = DoctorReport::inspect(
        parse(&value).unwrap(),
        Path::new("config.json"),
        Some(fixture.0.as_os_str()),
    );
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.id == "tool:sentinel-tool")
            .unwrap()
            .status,
        Status::Verified
    );
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.id == "tool:missing-tool")
            .unwrap()
            .status,
        Status::NotTested
    );
    assert!(!fixture.0.join("executed").exists());
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!executable_available(
        "sentinel-tool",
        Some(fixture.0.as_os_str())
    ));
    for tools in [
        json!(["../tool"]),
        json!(["/bin/sh"]),
        json!(["tool --version"]),
        json!(["tool", "tool"]),
        json!([""]),
    ] {
        value["tools"] = tools;
        assert!(parse(&value).is_err());
    }
}

#[test]
fn reports_escape_untrusted_paths_and_embed_exact_json() {
    let fixture = Fixture::new();
    let mut value: Value = serde_json::from_str(EXAMPLE).unwrap();
    value["evaluation_source"] = json!("</pre><script>alert(1)</script>&|```\n# fake");
    fs::write(fixture.0.join("config.json"), value.to_string()).unwrap();
    assert!(!run_appsec_doctor(&fixture.0.join("config.json"), &fixture.0.join("out")).unwrap());
    let json = fs::read_to_string(fixture.0.join("out/doctor.json")).unwrap();
    let markdown = fs::read_to_string(fixture.0.join("out/doctor.md")).unwrap();
    let report: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        report["requested"]["evaluation_source"],
        value["evaluation_source"]
    );
    assert!(!markdown.contains("<script>"));
    let embedded = markdown
        .split("<pre>\n")
        .nth(1)
        .unwrap()
        .strip_suffix("\n</pre>\n")
        .unwrap();
    let decoded = embedded
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    assert_eq!(decoded, json);
}

#[test]
fn never_overwrites_existing_outputs_and_invalid_config_writes_nothing() {
    let fixture = Fixture::new();
    let config = fixture.0.join("config.json");
    let output = fixture.0.join("out");
    fs::write(&config, EXAMPLE).unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("doctor.json"), "user file").unwrap();
    assert!(matches!(
        run_appsec_doctor(&config, &output),
        Err(DoctorError::Io(_))
    ));
    assert_eq!(
        fs::read_to_string(output.join("doctor.json")).unwrap(),
        "user file"
    );
    assert!(!output.join("doctor.md").exists());
    assert!(write_new(&output.join("doctor.json"), b"replacement").is_err());
    assert!(matches!(
        run_appsec_doctor(&config, &config),
        Err(DoctorError::Io(_))
    ));
    assert_eq!(fs::read_to_string(&config).unwrap(), EXAMPLE);
    #[cfg(unix)]
    {
        let link = fixture.0.join("output-link");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(matches!(
            run_appsec_doctor(&config, &link),
            Err(DoctorError::Io(_))
        ));
        assert_eq!(
            fs::read_to_string(output.join("doctor.json")).unwrap(),
            "user file"
        );
    }
    fs::write(&config, "{}").unwrap();
    assert!(matches!(
        run_appsec_doctor(&config, &fixture.0.join("new")),
        Err(DoctorError::InvalidConfig(_))
    ));
    assert!(!fixture.0.join("new").exists());
    let message = DoctorError::Io(io::Error::from(io::ErrorKind::WriteZero)).to_string();
    assert!(message.contains("partial diagnostic files"));
}
