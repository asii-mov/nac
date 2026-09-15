use anyhow::{ensure, Result};
use serde_json::json;
use std::{path::Path, process::Command};

#[test]
fn appsec_cli_freezes_exact_skill_and_assurance_inputs_without_a_model() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let directory = std::env::temp_dir().join(format!("nac-freeze-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let manifest = json!({"schema_version":1,"repositories":[],"declared_inputs":{},"monetary_policy":"uncapped","token_policy":"observe_only","watchdog":{"warn_after_ms":1000,"stall_after_ms":2000,"diagnostic_grace_ms":500,"lease_ms":5000,"max_failed_recoveries":2},"max_concurrency":1,"tasks":[{"key":"fixture","scope":"scripted freeze-only scope","dependencies":[],"operation_limits":{"wall_ms":10000,"output_bytes":65536}}]});
    let brief = json!({"schema_version":1,"assurance":{"mode":"open_ended"},"source_root":"fixture/","attacker_model":"scripted fixture","deployment_profile":"offline fixture","impact_goal":"exercise frozen input loading","success_property":"typed exact input hashes","minimum_active_research_ms":null,"max_investigative_agents":1});
    let input = directory.join("manifest.json");
    let brief_path = directory.join("brief.json");
    let output = directory.join("frozen.json");
    std::fs::write(&input, serde_json::to_vec(&manifest)?)?;
    std::fs::write(&brief_path, serde_json::to_vec(&brief)?)?;
    let result = Command::new(env!("CARGO_BIN_EXE_nac-web"))
        .args(["appsec", "freeze", "--manifest"])
        .arg(&input)
        .arg("--brief")
        .arg(&brief_path)
        .arg("--skills")
        .arg(root.join("skills/appsec"))
        .arg("--output")
        .arg(&output)
        .output()?;
    ensure!(
        result.status.success(),
        "freeze CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let frozen: nac_appsec::Manifest = serde_json::from_slice(&std::fs::read(output)?)?;
    let research = frozen
        .research
        .ok_or_else(|| anyhow::anyhow!("CLI omitted frozen inputs"))?;
    let prepared = research.prepare("fixture")?;
    ensure!(
        prepared.prompt.contains("Source discovery 1.0.0")
            && prepared
                .prompt
                .contains("may or may not contain a vulnerability"),
        "CLI lost the selected stage or assurance statement"
    );
    ensure!(
        !prepared
            .prompt
            .contains("has established that at least one"),
        "open-ended CLI brief asserted existence"
    );
    ensure!(
        prepared.skills.len() == 2 && prepared.prompt_sha256.len() == 64,
        "CLI omitted transitive helper or effective hash"
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
