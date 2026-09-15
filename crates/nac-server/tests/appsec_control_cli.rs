use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Command, Output},
};

struct Directory(std::path::PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn invoke(arguments: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_nac-web"))
        .arg("appsec")
        .args(arguments)
        .output()?)
}

#[test]
fn appsec_cli_persists_reports_cancels_and_resumes_without_model_execution() -> Result<()> {
    let directory =
        Directory(std::env::temp_dir().join(format!("nac-appsec-cli-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir(&directory.0)?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let revision = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(revision.status.success(), "fixture revision lookup failed");
    let commit = String::from_utf8(revision.stdout)?.trim().to_string();
    let operation_limits = json!({"wall_ms":100000,"output_bytes":10000});
    let manifest = json!({
        "schema_version":1,
        "repositories":[{"identity":"fixture","checkout":repository,"commit":commit}],
        "declared_inputs":{"environment":null,"dependencies":null,"fixtures":null,"deployment":null,"harness_commit":null,"runtime_version":null,"model_configuration":null,"skill_bundle":null},
        "monetary_policy":"uncapped",
        "token_policy":"observe_only",
        "watchdog":{"warn_after_ms":10000,"stall_after_ms":20000,"diagnostic_grace_ms":5000,"lease_ms":100000,"max_failed_recoveries":3},
        "max_concurrency":1,
        "tasks":[{"key":"manifest","scope":"inspect pinned manifest","dependencies":[],"operation_limits":operation_limits}]
    });
    let manifest_path = directory.0.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let state_path = directory.0.join("state");
    let state = state_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    let input = manifest_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    let run = invoke(&["run", "--manifest", input, "--state", state])?;
    assert_eq!(run.status.code(), Some(3));
    let blocked: Value = serde_json::from_slice(&run.stdout)?;
    assert_eq!(blocked["execution_state"], "blocked");
    assert_eq!(blocked["security_assurance"], "not_established");
    assert_eq!(blocked["campaign"]["tasks"][0]["attempts"], json!([]));
    assert!(
        String::from_utf8(run.stderr)?.contains("No model executed"),
        "run explicitly refuses live dispatch"
    );
    let run_id = blocked["campaign"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing run ID"))?;
    let task_id = blocked["campaign"]["tasks"][0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing task ID"))?;
    let status = invoke(&["status", "--state", state, "--run-id", run_id])?;
    assert!(status.status.success(), "real CLI can reopen SQLite state");
    assert_eq!(serde_json::from_slice::<Value>(&status.stdout)?, blocked);
    let cancelled = invoke(&[
        "cancel",
        "--state",
        state,
        "--run-id",
        run_id,
        "--revision",
        "1",
    ])?;
    assert!(cancelled.status.success(), "matching revision can cancel");
    let cancelled: Value = serde_json::from_slice(&cancelled.stdout)?;
    assert_eq!(cancelled["execution_state"], "cancelled");
    let stale = invoke(&[
        "cancel",
        "--state",
        state,
        "--run-id",
        run_id,
        "--revision",
        "1",
    ])?;
    assert!(
        !stale.status.success(),
        "stale CLI mutation cannot overwrite state"
    );
    let resumed = invoke(&[
        "resume",
        "--state",
        state,
        "--run-id",
        run_id,
        "--task-id",
        task_id,
        "--revision",
        "2",
        "--handoff",
        "operator cleared cancellation",
    ])?;
    assert!(
        resumed.status.success(),
        "cancelled unstarted scope can be resumed"
    );
    let resumed: Value = serde_json::from_slice(&resumed.stdout)?;
    assert_eq!(resumed["execution_state"], "queued");
    assert_eq!(resumed["campaign"]["tasks"][0]["attempts"], json!([]));
    let report_path = directory.0.join("report");
    let report = report_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    let rendered = invoke(&[
        "report", "--state", state, "--run-id", run_id, "--output", report,
    ])?;
    assert!(
        rendered.status.success(),
        "JSON and Markdown reporting works"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(report_path.join("report.json"))?)?,
        resumed
    );
    let markdown = std::fs::read_to_string(report_path.join("report.md"))?;
    assert!(
        markdown.contains("Completed scope: 0/1"),
        "incomplete coverage is explicit"
    );
    assert!(
        markdown.contains("environment: unknown"),
        "unknown inputs remain visible"
    );
    assert!(
        markdown.contains("does not establish security assurance"),
        "zero findings is not assurance"
    );
    assert!(
        !invoke(&["report", "--state", state, "--run-id", run_id, "--output", report])?
            .status
            .success(),
        "report never overwrites an existing package"
    );
    Ok(())
}
