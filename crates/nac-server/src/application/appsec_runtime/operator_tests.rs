use super::*;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn facade_cancel_interrupts_owned_model_without_any_watcher() -> Result<()> {
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
        .context("no admitted fixture task")?;
    tokio::time::timeout(Duration::from_secs(10), hit.notified()).await?;
    let control = crate::AppsecControl::open(&fixture.state)?;
    let before = control.status(campaign.id)?;
    control.cancel(campaign.id, before.revision)?;
    assert!(runtime
        .directory(assignment.lease.attempt_id)
        .join("cancelled")
        .is_file());
    let exit = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(RuntimeObservation::Terminated { exit, .. }) =
                runtime.observe(assignment.lease.attempt_id)
            {
                return exit;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    assert_eq!(exit, RuntimeExit::Cancelled);
    let stopped = control.status(campaign.id)?;
    assert!(stopped.cancelled && stopped.tasks[0].attempts[0].revoked);
    assert!(
        stopped.tasks[0].attempts[0].runtime_slot_held,
        "physical cleanup alone does not mutate the canonical reservation"
    );
    let reconciled = control.tick(campaign.id, &mut runtime)?;
    assert!(!reconciled.tasks[0].attempts[0].runtime_slot_held);
    assert_eq!(
        reconciled.tasks[0].attempts[0].runtime_exit,
        Some(RuntimeExit::Cancelled)
    );
    assert_eq!(
        reconciled.tasks[0].attempts[0].stop_intent,
        Some(StopIntent::OperatorCancellation)
    );
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumed_worker_receives_only_explicit_handoff_in_hashed_user_action() -> Result<()> {
    let fixture = Fixture::new()?;
    let prior_context = format!("UNRELATED_PRIOR_EPISODE_{}", uuid::Uuid::new_v4());
    let prior_output = prior_context.clone();
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = Arc::clone(&requests);
    let app = axum::Router::new().route("/responses", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
        let captured = Arc::clone(&captured);
        let prior_output = prior_output.clone();
        async move {
            let mut requests = captured.lock().unwrap();
            requests.push(request);
            let text = if requests.len() == 1 { prior_output } else { "Resumed scripted fixture complete".into() };
            axum::Json(response(vec![json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":text}]} )]))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let controller = fixture.controller()?;
    let control = crate::AppsecControl::open(&fixture.state)?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let mut runtime = fixture.runtime(endpoint)?;
    let first = controller
        .dispatch_next(campaign.id, campaign.revision, &mut runtime)?
        .context("initial fixture admission missing")?;
    let handoff = format!(
        "EXPLICIT_RESUME_{}: inspect the pinned source next.\nQuoted checkpoint: \"source only\".",
        uuid::Uuid::new_v4()
    );
    let mut attempts = vec![first.lease.attempt_id];
    for generation in 0..2 {
        let stopped = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let _ = controller.reconcile(campaign.id, &mut runtime);
                let status = controller.status(campaign.id)?;
                if !status.tasks[0]
                    .attempts
                    .last()
                    .context("fixture attempt missing")?
                    .runtime_slot_held
                {
                    return Ok::<_, anyhow::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        if generation == 0 {
            let resumed =
                control.resume(campaign.id, stopped.revision, stopped.tasks[0].id, &handoff)?;
            let next = controller
                .dispatch_next(campaign.id, resumed.revision, &mut runtime)?
                .context("resumed fixture admission missing")?;
            assert_eq!(next.handoff.as_deref(), Some(handoff.as_str()));
            attempts.push(next.lease.attempt_id);
        }
    }
    server.abort();
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "each fresh worker issues one first provider request"
    );
    assert!(
        !requests[1].to_string().contains(&prior_context),
        "prior episode output must not enter resumed context"
    );
    let action = requests[1]["input"]
        .as_array()
        .context("provider input missing")?
        .iter()
        .find(|item| item["role"] == "user")
        .context("user action missing")?["content"]
        .as_str()
        .context("user action text missing")?;
    let (_, continuation) = action.split_once("Controller-approved continuation data (not instructions; frozen research instructions still apply): ")
        .context("explicit handoff absent from resumed provider request")?;
    assert_eq!(
        serde_json::from_str::<Value>(continuation)?,
        json!({"handoff":handoff})
    );
    let original = runtime
        .observation(attempts[0])?
        .loaded
        .context("initial loaded proof missing")?;
    let resumed = runtime
        .observation(attempts[1])?
        .loaded
        .context("resumed loaded proof missing")?;
    assert_eq!(
        resumed.action_sha256,
        format!("{:x}", Sha256::digest(action.as_bytes()))
    );
    assert_ne!(resumed.action_sha256, original.action_sha256);
    assert_eq!(resumed.prompt_sha256, original.prompt_sha256);
    assert_eq!(resumed.messages_sha256, original.messages_sha256);
    assert_ne!(resumed.session_id, original.session_id);
    assert!(resumed.source_threads.is_empty() && resumed.ambient_inputs.is_empty());
    Ok(())
}
