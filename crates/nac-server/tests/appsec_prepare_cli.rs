use anyhow::{ensure, Context, Result};
use nac_appsec::{
    ArtifactRef, ArtifactStore, Controller, ExperimentPlan, HttpMethod, HttpRequest, Id, Manifest,
    Runtime, RuntimeObservation, SourceRef, SqliteRepository, SystemClock, Usage,
};
use nac_server::{AppsecTargetRunner, FrozenPilot, LocalPilotArtifacts};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    root: PathBuf,
    images: Vec<String>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for image in &self.images {
            let _ = Command::new("/usr/bin/docker")
                .args(["image", "rm", "--force", image])
                .output();
        }
        let _ = Command::new("/usr/bin/chmod")
            .args(["-R", "u+rwx"])
            .arg(&self.root)
            .status();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct AdmitRuntime {
    live: BTreeSet<Id>,
}

impl Runtime for AdmitRuntime {
    fn check_capabilities(&self) -> Result<()> {
        Ok(())
    }

    fn start(&mut self, assignment: &nac_appsec::Assignment) -> Result<()> {
        self.live.insert(assignment.lease.attempt_id);
        Ok(())
    }

    fn observe(&mut self, attempt: Id) -> Result<RuntimeObservation> {
        ensure!(self.live.contains(&attempt), "unknown test attempt");
        Ok(RuntimeObservation::Live {
            usage: Usage::default(),
            progress: None,
            oldest_active_operation: None,
        })
    }

    fn cancel(&mut self, attempt: Id) -> Result<()> {
        self.live.remove(&attempt);
        Ok(())
    }

    fn diagnose(&mut self, _attempt: Id) -> Result<ArtifactRef> {
        anyhow::bail!("diagnosis is not part of local pilot admission")
    }
}

fn invoke(arguments: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_nac-web"))
        .arg("appsec")
        .args(arguments)
        .output()?)
}

fn run_git(repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()?;
    ensure!(
        output.status.success(),
        "fixture Git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().into())
}

#[test]
fn clean_local_prepare_freeze_reconcile_read_cancel_and_report() -> Result<()> {
    let root =
        std::env::temp_dir().join(format!("nac-appsec-prepare-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    let mut fixture = Fixture {
        root: root.clone(),
        images: vec![],
    };
    let repository = root.join("repository");
    std::fs::create_dir(&repository)?;
    run_git(&repository, &["init", "-q"])?;
    std::fs::write(
        repository.join("main.go"),
        include_bytes!("fixtures/appsec-pilot/main.go"),
    )?;
    run_git(&repository, &["add", "main.go"])?;
    run_git(&repository, &["commit", "-qm", "local pilot fixture"])?;
    let commit = run_git(&repository, &["rev-parse", "HEAD"])?;
    let interface = root.join("interface.json");
    std::fs::write(
        &interface,
        serde_json::to_vec(&json!({
            "max_requests":4,
            "routes":[
                {"actor":"attacker","method":"get","path_prefix":"/object/owner","max_body_bytes":0},
                {"actor":"attacker","method":"post","path_prefix":"/state","max_body_bytes":8192}
            ]
        }))?,
    )?;
    let prepared = root.join("prepared");
    let prepare = invoke(&[
        "prepare-local-pilot",
        "--repository",
        repository
            .to_str()
            .context("repository path is not UTF-8")?,
        "--commit",
        &commit,
        "--repository-id",
        "local-pilot",
        "--include",
        "main.go",
        "--interface",
        interface.to_str().context("interface path is not UTF-8")?,
        "--oracle",
        "authorization",
        "--output",
        prepared.to_str().context("prepared path is not UTF-8")?,
    ])?;
    ensure!(
        prepare.status.success(),
        "prepare CLI failed: {}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    let artifacts: LocalPilotArtifacts = serde_json::from_slice(&prepare.stdout)?;
    fixture.images = vec![
        artifacts.builder_image.clone(),
        artifacts.vulnerable_image.clone(),
        artifacts.protected_image.clone(),
    ];
    let registry_mode = std::fs::metadata(&artifacts.registry)?.permissions().mode() & 0o777;
    assert_eq!(registry_mode, 0o600);
    assert_eq!(
        std::fs::metadata(&artifacts.profile)?.permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::metadata(&prepared)?.permissions().mode() & 0o777,
        0o755
    );
    let manifest_path = root.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&json!({
            "schema_version":1,
            "repositories":[{"identity":"local-pilot","checkout":repository,"commit":commit}],
            "declared_inputs":{"environment":null,"dependencies":null,"fixtures":null,"deployment":null,"harness_commit":null,"runtime_version":null,"model_configuration":null,"skill_bundle":null},
            "monetary_policy":"uncapped",
            "token_policy":"observe_only",
            "watchdog":{"warn_after_ms":10000,"stall_after_ms":20000,"diagnostic_grace_ms":5000,"lease_ms":300000,"max_failed_recoveries":3},
            "max_concurrency":1,
            "tasks":[{"key":"discovery","scope":"local controlled experiment demonstration","dependencies":[],"operation_limits":{"wall_ms":300000,"output_bytes":65536}}]
        }))?,
    )?;
    let brief_path = root.join("brief.json");
    std::fs::write(
        &brief_path,
        serde_json::to_vec(&json!({
            "schema_version":1,
            "assurance":{"mode":"open_ended"},
            "source_root":"local-pilot/main.go",
            "attacker_model":"local deterministic fixture attacker",
            "deployment_profile":"isolated local Docker pilot",
            "impact_goal":"exercise class-appropriate authorization controls",
            "success_property":"forbidden object delivery or state change",
            "minimum_active_research_ms":null,
            "max_investigative_agents":1
        }))?,
    )?;
    let frozen_path = root.join("frozen-manifest.json");
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let freeze = invoke(&[
        "freeze",
        "--manifest",
        manifest_path
            .to_str()
            .context("manifest path is not UTF-8")?,
        "--skills",
        repository_root
            .join("skills/appsec")
            .to_str()
            .context("skills path is not UTF-8")?,
        "--brief",
        brief_path.to_str().context("brief path is not UTF-8")?,
        "--experiment-profile",
        artifacts
            .profile
            .to_str()
            .context("profile path is not UTF-8")?,
        "--output",
        frozen_path.to_str().context("frozen path is not UTF-8")?,
    ])?;
    ensure!(
        freeze.status.success(),
        "freeze CLI failed: {}",
        String::from_utf8_lossy(&freeze.stderr)
    );
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&frozen_path)?)?;
    let profile = manifest
        .experiments
        .clone()
        .context("frozen manifest omitted experiments")?;
    let pilots: Vec<FrozenPilot> = serde_json::from_slice(&std::fs::read(&artifacts.registry)?)?;
    let state = root.join("state");
    AppsecTargetRunner::freeze_registry(&state, &profile.recipes, pilots)?;
    let controller = Controller::new(
        SqliteRepository::open_with_target_capacity(&state, 4, 1)?,
        ArtifactStore::open(&state)?,
        SystemClock,
    );
    let campaign = controller.create(manifest)?;
    let mut runtime = AdmitRuntime::default();
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .context("controller-only local admission did not start")?;
    ensure!(
        assignment.experiment_tools,
        "frozen local campaign omitted experiment tools"
    );
    let package_file = &profile.package.files[0];
    let source = SourceRef {
        repository: package_file.repository.clone(),
        commit: package_file.commit.clone(),
        path: package_file.path.clone(),
        start_line: 1,
        end_line: 1,
        content_sha256: package_file.content_sha256.clone(),
    };
    let attack = vec![
        HttpRequest {
            actor: "attacker".into(),
            method: HttpMethod::Get,
            path: "/object/owner".into(),
            body: String::new(),
        },
        HttpRequest {
            actor: "attacker".into(),
            method: HttpMethod::Post,
            path: "/state".into(),
            body: "attacker-change".into(),
        },
    ];
    let completed = controller.run_experiment(
        &assignment.lease,
        ExperimentPlan {
            schema_version: 1,
            key: "complete-local-pilot".into(),
            recipe_id: "local-authz-vulnerable".into(),
            hypothesis: "the local vulnerable fixture permits forbidden access".into(),
            sources: vec![source.clone()],
            requests: attack.clone(),
        },
    )?;
    let state_text = state.to_str().context("state path is not UTF-8")?;
    let run_text = campaign.id.to_string();
    let demo = invoke(&[
        "experiment-demo",
        "--state",
        state_text,
        "--run-id",
        &run_text,
    ])?;
    ensure!(
        demo.status.success(),
        "experiment demo failed: {}",
        String::from_utf8_lossy(&demo.stderr)
    );
    let completed_id = completed.id.to_string();
    let read = invoke(&[
        "experiment-read",
        "--state",
        state_text,
        "--run-id",
        &run_text,
        "--experiment-id",
        &completed_id,
    ])?;
    ensure!(read.status.success(), "completed experiment read failed");
    let completed: Value = serde_json::from_slice(&read.stdout)?;
    assert_eq!(completed["trials"][0]["phase"], "cleaned");
    assert_eq!(completed["trials"][0]["verdict"]["assessment"], "confirmed");
    let cancelled = controller.run_experiment(
        &assignment.lease,
        ExperimentPlan {
            schema_version: 1,
            key: "cancel-local-pilot".into(),
            recipe_id: "local-authz-protected".into(),
            hypothesis: "the protected local fixture remains isolated during cancellation".into(),
            sources: vec![source],
            requests: attack,
        },
    )?;
    let reconcile = invoke(&[
        "experiment-reconcile",
        "--state",
        state_text,
        "--run-id",
        &run_text,
    ])?;
    ensure!(reconcile.status.success(), "experiment reconcile failed");
    let cancelled_id = cancelled.id.to_string();
    let cancel = invoke(&[
        "experiment-cancel",
        "--state",
        state_text,
        "--run-id",
        &run_text,
        "--experiment-id",
        &cancelled_id,
    ])?;
    ensure!(cancel.status.success(), "experiment cancel failed");
    let cleanup = invoke(&[
        "experiment-demo",
        "--state",
        state_text,
        "--run-id",
        &run_text,
    ])?;
    ensure!(
        cleanup.status.success(),
        "cancelled experiment cleanup failed"
    );
    let report = root.join("report");
    let report_result = invoke(&[
        "report",
        "--state",
        state_text,
        "--run-id",
        &run_text,
        "--output",
        report.to_str().context("report path is not UTF-8")?,
    ])?;
    ensure!(report_result.status.success(), "campaign report failed");
    let report_json: Value = serde_json::from_slice(&std::fs::read(report.join("report.json"))?)?;
    assert_eq!(
        report_json["campaign"]["experiments"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        report_json["security_assurance"], "not_established",
        "local pilot reports must not claim scanner assurance"
    );
    Ok(())
}
