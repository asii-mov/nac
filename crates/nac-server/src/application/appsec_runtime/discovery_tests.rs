use super::*;

fn output(request: &Value, id: &str) -> Value {
    request["input"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["type"] == "function_call_output" && item["call_id"] == id)
        })
        .and_then(|item| item["output"].as_str())
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neutral_brief_discovers_pinned_paths_before_reading_unknown_file() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let repository = fixture.directory.join("pinned-repository");
    std::fs::create_dir(&repository)?;
    let filename = format!("unannounced-{}.rs", uuid::Uuid::new_v4());
    std::fs::write(
        repository.join(&filename),
        "inventory-discovered-source-marker\n",
    )?;
    std::os::unix::fs::symlink("/etc/passwd", repository.join("forbidden-link.rs"))?;
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec!["commit", "-qm", "scripted discovery fixture"],
    ] {
        ensure!(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(args)
                .status()?
                .success(),
            "fixture Git failed"
        );
    }
    let commit = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    fixture.manifest.repositories[0].identity = "neutral-source".into();
    fixture.manifest.repositories[0].checkout = repository.clone();
    fixture.manifest.repositories[0].commit = String::from_utf8(commit.stdout)?.trim().to_string();
    fixture.manifest.tasks[0].scope = "Investigate the declared source".into();
    fixture
        .manifest
        .research
        .as_mut()
        .unwrap()
        .brief
        .source_root = "declared source".into();
    std::fs::write(
        repository.join("future-uncommitted.rs"),
        "must not be listed",
    )?;
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = Arc::clone(&requests);
    let app = axum::Router::new().route("/responses", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
        let captured = Arc::clone(&captured);
        async move {
            let mut requests = captured.lock().unwrap();
            requests.push(request.clone());
            let result = match requests.len() {
                1 => response(vec![call("inventory", "mcp__controller__list_source_files", json!({"repository":"neutral-source","after":null,"limit":10}))]),
                2 => match output(&request,"inventory")["files"].as_array().and_then(|files| files.first()).and_then(Value::as_str) {
                    Some(path) => response(vec![call("source", "mcp__controller__read_source", json!({"repository":"neutral-source","path":path,"start_line":1,"end_line":1}))]),
                    None => response(vec![json!({"type":"message","content":[{"type":"output_text","text":"inventory unavailable"}]})]),
                },
                3 => response(vec![call("stage", "mcp__controller__submit_stage_result", json!({"key":"inventory-checkpoint","result":{"status":"partial","reason":"source discovered through inventory"},"evidence":[{"kind":"upload","bytes":output(&request,"source")["text"].as_str().unwrap_or("").as_bytes()}]}))]),
                _ => response(vec![json!({"type":"message","content":[{"type":"output_text","text":"discovery fixture complete"}]})]),
            };
            axum::Json(result)
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let mut runtime = fixture.runtime(endpoint)?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .unwrap();
    let mut settled = None;
    for _ in 0..400 {
        let _ = controller.reconcile(campaign.id, &mut runtime);
        let status = controller.status(campaign.id)?;
        if !status.tasks[0].attempts[0].runtime_slot_held {
            settled = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    runtime.cancel(assignment.lease.attempt_id)?;
    server.abort();
    let requests = requests.lock().unwrap();
    let first = requests[0].to_string();
    assert!(
        !first.contains(&filename),
        "the prompt must not disclose the fixture filename"
    );
    assert!(
        first.contains("neutral-source"),
        "the worker needs declared repository identity context"
    );
    assert!(
        !first.contains(&repository.display().to_string()),
        "host checkout paths are not model context"
    );
    assert_eq!(
        output(&requests[1], "inventory")["files"],
        json!([filename]),
        "inventory excludes symlinks, Git internals and unpinned paths"
    );
    assert_eq!(
        output(&requests[2], "source")["text"],
        "inventory-discovered-source-marker"
    );
    let settled = settled.context("discovery fixture did not settle")?;
    assert_eq!(settled.tasks[0].state, ExecutionState::Partial);
    let artifact = &settled.accepted[0].evidence[0];
    assert_eq!(
        ArtifactStore::open(&fixture.state)?.read_range(artifact, 0, artifact.bytes)?,
        b"inventory-discovered-source-marker"
    );
    Ok(())
}
