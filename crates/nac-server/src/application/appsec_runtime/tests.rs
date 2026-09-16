use super::*;
use nac_appsec::{
    Assurance, Controller, ExecutionState, FrozenResearch, Manifest, ResearchBrief,
    SqliteRepository, StopIntent,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[path = "discovery_tests.rs"]
mod discovery;
#[path = "operator_tests.rs"]
mod operator;
#[path = "ownership_tests.rs"]
mod ownership;
#[path = "workflow_tests.rs"]
mod workflow;

#[test]
fn process_helper() {
    let Ok(role) = std::env::var("NAC_APPSEC_TEST_ROLE") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("NAC_APPSEC_TEST_DIRECTORY").unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        match role.as_str() {
            "supervisor" => supervise_appsec_worker(&directory).await,
            "worker" => {
                let _descendant = if let Some(path) = std::env::var_os("NAC_APPSEC_TEST_DESCENDANT_PID") {
                    let child = Command::new("/bin/sleep").arg("60").spawn()?;
                    std::fs::write(path, child.id().to_string())?;
                    Some(child)
                } else { None };
                eprintln!("__NAC_CANCEL_ACK__");
                eprintln!("__NAC_EVENT__{{\"type\":\"token_usage_updated\",\"usage\":{{\"input_tokens\":999999999}}}}");
                run_appsec_worker(&directory).await
            },
            _ => panic!("unknown test helper role"),
        }
    });
    if let Err(error) = result {
        eprintln!("SCRIPTED WORKER FIXTURE ERROR: {error:#}");
        std::process::exit(1);
    }
}

struct Fixture {
    directory: PathBuf,
    state: PathBuf,
    manifest: Manifest,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("nac-appsec-runtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = directory.join("state");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let commit = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["rev-parse", "HEAD"])
            .output()?;
        ensure!(commit.status.success(), "fixture git revision failed");
        let mut manifest: Manifest = serde_json::from_value(json!({
            "schema_version":1,
            "repositories":[{"identity":"fixture", "checkout":repo, "commit":String::from_utf8(commit.stdout)?.trim()}],
            "declared_inputs":{"environment":null,"dependencies":null,"fixtures":null,"deployment":null,"harness_commit":null,"runtime_version":null,"model_configuration":null,"skill_bundle":null},
            "monetary_policy":"uncapped", "token_policy":"observe_only",
            "watchdog":{"warn_after_ms":10000,"stall_after_ms":20000,"diagnostic_grace_ms":5000,"lease_ms":30000,"max_failed_recoveries":3},
            "max_concurrency":1,
            "tasks":[{"key":"discovery", "scope":"inspect pinned Cargo.toml", "dependencies":[],"operation_limits":{"wall_ms":10000,"output_bytes":65536}}]
        }))?;
        let brief = ResearchBrief {
            schema_version: 1,
            assurance: Assurance::OpenEnded,
            source_root: "fixture/Cargo.toml".into(),
            attacker_model: "scripted test attacker, not an actual finding".into(),
            deployment_profile: "offline scripted fixture".into(),
            impact_goal: "exercise the typed receipt path".into(),
            success_property: "receive source and selected skill markers".into(),
            minimum_active_research_ms: Some(21600000),
            max_investigative_agents: 1,
        };
        manifest.research = Some(FrozenResearch::resolve(
            &repo.join("skills/appsec"),
            brief,
            BTreeMap::from([("discovery".into(), "discovery".into())]),
        )?);
        Ok(Self {
            directory,
            state,
            manifest,
        })
    }

    fn controller(&self) -> Result<Controller<SqliteRepository>> {
        Ok(Controller::new(
            SqliteRepository::open(&self.state, 4)?,
            ArtifactStore::open(&self.state)?,
            SystemClock,
        ))
    }

    fn runtime(&self, endpoint: String) -> Result<NacWorkerRuntime> {
        let mut runtime = NacWorkerRuntime::new(
            &self.state,
            std::env::current_exe()?,
            NativeResearchModel {
                fixture_endpoint: Some(endpoint),
                model: "gpt-4.1".into(),
                ..NativeResearchModel::default()
            },
        )?;
        runtime.test_helper = true;
        Ok(runtime)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn response(output: Vec<Value>) -> Value {
    json!({"id":"scripted-fixture", "status":"completed", "output":output, "usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}})
}

fn call(id: &str, name: &str, arguments: Value) -> Value {
    json!({"type":"function_call","id":id,"call_id":id,"name":name,"arguments":arguments.to_string(),"status":"completed"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_process_mcp_sqlite_receipts_and_restart_cleanup() -> Result<()> {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new()?;
    let repository = &fixture.manifest.repositories[0];
    let blob = Command::new("git")
        .arg("-C")
        .arg(&repository.checkout)
        .args(["show", &format!("{}:Cargo.toml", repository.commit)])
        .output()?;
    ensure!(blob.status.success(), "fixture pinned blob lookup failed");
    let source = json!({"repository":"fixture","commit":repository.commit,"path":"Cargo.toml","start_line":1,"end_line":3,"content_sha256":format!("{:x}", Sha256::digest(&blob.stdout))});
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let received = Arc::clone(&requests);
    let sentinel = fixture.directory.join("native-command-must-not-run");
    let canary = fixture.directory.join("ambient-history");
    std::fs::write(&canary, "DO-NOT-EXPOSE-AMBIENT-FILE")?;
    let canary_arg = canary.display().to_string();
    let sentinel_arg = sentinel.display().to_string();
    let app = axum::Router::new().route("/responses", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
        let received = Arc::clone(&received);
        let sentinel_arg = sentinel_arg.clone();
        let canary_arg = canary_arg.clone();
        let source = source.clone();
        async move {
            let mut requests = received.lock().unwrap();
            requests.push(request);
            axum::Json(match requests.len() {
                1 => response(vec![
                    call("native-denied", "exec_command", json!({"command":format!("touch {sentinel_arg}")})),
                    call("read-denied", "read", json!({"path":canary_arg})),
                    call("web-denied", "web_fetch", json!({"url":"http://127.0.0.1:1"})),
                    call("child-denied", "subagent", json!({"prompt":"must not launch"})),
                    call("source", "mcp__controller__read_source", json!({"repository":"fixture","path":"Cargo.toml","start_line":1,"end_line":3})),
                ]),
                2 => response(vec![call("candidate", "mcp__controller__submit_candidate", json!({"key":"scripted-candidate","candidate":{"claim":"scripted source observation, not a real vulnerability", "prerequisites":[],"unresolved_assumptions":["scripted fixture only"],"source":source},"evidence":[{"kind":"upload","bytes":b"scripted candidate evidence".to_vec()}]}))]),
                3 => response(vec![call("artifact", "mcp__controller__read_artifact_range", json!({"artifact":{"sha256":format!("{:x}", Sha256::digest(b"scripted candidate evidence")),"bytes":b"scripted candidate evidence".len()},"offset":0,"length":b"scripted candidate evidence".len()}))]),
                4 => response(vec![call("stage", "mcp__controller__submit_stage_result", json!({"key":"scripted-checkpoint","result":{"status":"partial","reason":"scripted fixture, not a security conclusion"},"evidence":[{"kind":"upload","bytes":b"scripted receipt: [workspace]; Source discovery 1.0.0".to_vec()}]}))]),
                _ => response(vec![json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"Scripted fixture complete."}]})]),
            })
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let mut runtime = fixture.runtime(endpoint.clone())?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .context("no admitted task")?;
    drop(runtime);
    drop(controller);
    let controller = fixture.controller()?;
    let mut runtime = fixture.runtime(endpoint)?;
    let mut settled = None;
    for _ in 0..300 {
        let _ = controller.reconcile(campaign.id, &mut runtime);
        let status = controller.status(campaign.id)?;
        if !status.tasks[0].attempts[0].runtime_slot_held {
            settled = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let directory = runtime.directory(assignment.lease.attempt_id);
    if settled.is_none() {
        eprintln!(
            "diagnostics: {:?}; supervisor: {:?}",
            std::fs::read_to_string(directory.join("stderr.log")),
            std::fs::read_to_string(directory.join("supervisor.log"))
        );
    }
    let settled = settled.context("scripted process did not settle")?;
    let requests = requests.lock().unwrap();
    assert!(
        requests.len() >= 2,
        "scripted fixture must exercise a second real provider request: {requests:?}; stderr {:?}",
        std::fs::read_to_string(directory.join("stderr.log"))
    );
    let first = requests[0].to_string();
    assert!(
        first.contains("Source discovery 1.0.0"),
        "selected frozen skill reached provider"
    );
    assert!(
        first.contains("Evidence discipline 1.0.0"),
        "transitive helper reached provider"
    );
    assert!(
        !first.contains("exec_command\""),
        "native command definition is not exposed"
    );
    assert!(
        !first.contains(&fixture.state.display().to_string()),
        "controller state paths are not model inputs"
    );
    assert!(
        !first.contains("NAC repository guide"),
        "ambient repository instructions were not loaded"
    );
    let second = requests[1].to_string();
    assert!(
        second.contains("[workspace]"),
        "pinned source marker reached the model through MCP"
    );
    assert!(
        second.contains("not available to this agent"),
        "forged native invocation was denied"
    );
    assert!(
        !second.contains("DO-NOT-EXPOSE-AMBIENT-FILE"),
        "forged native read cannot access ambient history"
    );
    assert!(!sentinel.exists(), "native invocation never executed");
    assert_eq!(settled.tasks[0].state, ExecutionState::Partial);
    assert_eq!(
        settled.tasks[0].attempts[0].stop_intent,
        Some(StopIntent::AcceptedResultCleanup)
    );
    assert_eq!(settled.tasks[0].failed_recoveries, 0);
    assert_eq!(settled.accepted.len(), 2);
    let observation = runtime.observation(assignment.lease.attempt_id)?;
    eprintln!(
        "SCRIPTED_LOCAL_CONFORMANCE {}",
        serde_json::to_string(
            &json!({"loaded":observation.loaded,"lock_sha256":fixture.manifest.research.as_ref().map(|research| &research.lock_sha256),"observed_tokens":observation.control.observed_tokens,"usage_complete":false,"accepted_records":settled.accepted.len(),"physical_exit":observation.exit,"stop_intent":settled.tasks[0].attempts[0].stop_intent})
        )?
    );
    assert!(
        observation.loaded.is_some(),
        "trusted loaded inventory was recorded"
    );
    assert!(
        observation.control.observed_tokens.unwrap_or(0) < 1000,
        "stderr token spoof must not enter trusted accounting"
    );
    assert!(
        std::fs::read_to_string(directory.join("stderr.log"))?.contains("__NAC_CANCEL_ACK__"),
        "spoofed log retained only as diagnostics"
    );
    let evidence = ArtifactStore::open(&fixture.state)?.read_range(
        &settled.accepted[1].evidence[0],
        0,
        settled.accepted[1].evidence[0].bytes,
    )?;
    assert_eq!(
        evidence,
        b"scripted receipt: [workspace]; Source discovery 1.0.0"
    );
    runtime.cancel(assignment.lease.attempt_id)?;
    assert!(
        runtime.start(&assignment).is_err(),
        "durable cancellation tombstone prevents relaunch after restart"
    );
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_interrupts_pending_model_and_late_launch() -> Result<()> {
    let fixture = Fixture::new()?;
    let hit = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&hit);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let app = axum::Router::new().route(
        "/responses",
        axum::routing::post(move || {
            let notify = Arc::clone(&notify);
            async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_secs(30)).await;
                axum::Json(response(vec![]))
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let mut runtime = fixture.runtime(endpoint)?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .context("no admitted task")?;
    if tokio::time::timeout(Duration::from_secs(10), hit.notified())
        .await
        .is_err()
    {
        anyhow::bail!(
            "model fixture never called: {:?}",
            std::fs::read_to_string(
                runtime
                    .directory(assignment.lease.attempt_id)
                    .join("stderr.log")
            )
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let operation = match runtime.observe(assignment.lease.attempt_id)? {
        RuntimeObservation::Live {
            oldest_active_operation,
            ..
        } => oldest_active_operation.context("model operation missing")?,
        _ => anyhow::bail!("model terminated before cancellation"),
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    match runtime.observe(assignment.lease.attempt_id)? {
        RuntimeObservation::Live {
            oldest_active_operation,
            ..
        } => assert_eq!(oldest_active_operation, Some(operation)),
        _ => anyhow::bail!("model terminated before cancellation"),
    }
    let status = controller.status(campaign.id)?;
    controller.cancel(campaign.id, status.revision)?;
    for _ in 0..200 {
        let _ = controller.reconcile(campaign.id, &mut runtime);
        if !controller.status(campaign.id)?.tasks[0].attempts[0].runtime_slot_held {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let status = controller.status(campaign.id)?;
    assert!(
        !status.tasks[0].attempts[0].runtime_slot_held,
        "actual worker cleanup releases slot"
    );
    assert_eq!(
        status.tasks[0].attempts[0].runtime_exit,
        Some(RuntimeExit::Cancelled)
    );
    assert!(
        !status.tasks[0].attempts[0].usage.complete,
        "interrupted request usage remains incomplete"
    );
    assert!(
        runtime.start(&assignment).is_err(),
        "late launch is rejected by durable key tombstone"
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cancelled_pending_launch_cannot_acquire_a_slot_after_restart() -> Result<()> {
    let fixture = Fixture::new()?;
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let mut runtime = fixture.runtime("http://127.0.0.1:1".into())?;
    runtime.test_helper = false;
    runtime.executable = fixture.directory.join("not-an-executable");
    std::fs::write(
        &runtime.executable,
        "intentionally invalid scripted launch fixture",
    )?;
    assert!(
        controller
            .dispatch_next(campaign.id, campaign.revision, &mut runtime)
            .is_err(),
        "the deliberately failed spawn must be reported"
    );
    let recorded = controller.status(campaign.id)?;
    let attempt_id = recorded.tasks[0].attempts[0].lease.attempt_id;
    let launch: Launch = read_json(&runtime.directory(attempt_id).join("launch.json"))?;
    let assignment = launch.assignment;
    let attempt = assignment.lease.attempt_id;
    assert!(
        runtime.observe(attempt).is_err(),
        "a pending launch without supervisor ownership is unavailable, not terminated"
    );
    let status = controller.status(campaign.id)?;
    assert!(
        status.tasks[0].attempts[0].runtime_slot_held,
        "failed spawn retains its uncertain reservation"
    );
    assert!(
        controller
            .resume(
                campaign.id,
                status.revision,
                assignment.lease.task_id,
                "retry"
            )
            .is_err(),
        "restart cannot admit replacement over an uncertain launch"
    );
    runtime.cancel(attempt)?;
    drop(runtime);
    let mut late = Command::new(std::env::current_exe()?);
    let directory = fixture.state.join("workers").join(attempt.to_string());
    configure_test_command(&mut late, &directory, "supervisor");
    let result = late.status()?;
    assert!(
        result.success(),
        "late real supervisor reconciles the tombstone without launching worker"
    );
    let mut runtime = fixture.runtime("http://127.0.0.1:1".into())?;
    assert!(matches!(
        runtime.observe(attempt)?,
        RuntimeObservation::Terminated {
            exit: RuntimeExit::Cancelled,
            ..
        }
    ));
    assert!(
        runtime.start(&assignment).is_err(),
        "tombstone is durable across runtime reconstruction"
    );
    let status = controller.reconcile(campaign.id, &mut runtime)?;
    assert!(
        !status.tasks[0].attempts[0].runtime_slot_held,
        "only confirmed late-launch reconciliation releases reservation"
    );
    assert!(
        !directory.join("context").exists(),
        "cancelled launch never constructed a model context"
    );
    Ok(())
}
