use super::*;

struct AdmissionFixture;
impl Runtime for AdmissionFixture {
    fn check_capabilities(&self) -> Result<()> {
        Ok(())
    }
    fn start(&mut self, _: &Assignment) -> Result<()> {
        Ok(())
    }
    fn observe(&mut self, _: Id) -> Result<RuntimeObservation> {
        bail!("fixture has not started a supervisor")
    }
    fn cancel(&mut self, _: Id) -> Result<()> {
        bail!("fixture does not perform cancellation")
    }
    fn diagnose(&mut self, _: Id) -> Result<ArtifactRef> {
        bail!("fixture does not produce diagnostics")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owned_supervisor_loss_makes_live_observation_uncertain_without_releasing_slot(
) -> Result<()> {
    let fixture = Fixture::new()?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&entered);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let app = axum::Router::new().route(
        "/responses",
        axum::routing::post(move || {
            let notify = Arc::clone(&notify);
            async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_secs(60)).await;
                axum::Json(response(vec![]))
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut AdmissionFixture)?
        .unwrap();
    let mut runtime = fixture.runtime(endpoint)?;
    let directory = runtime.directory(assignment.lease.attempt_id);
    private_dir(&directory)?;
    write_json(
        &directory.join("launch.json"),
        &Launch {
            state: fixture.state.clone(),
            assignment: assignment.clone(),
            model: runtime.model.clone(),
            executable: std::env::current_exe()?,
            test_helper: true,
        },
    )?;
    write_json(&directory.join("observation.json"), &Observation::default())?;
    write_json(
        &directory.join("child-admission.json"),
        &ChildAdmission::Pending,
    )?;
    let mut command = Command::new(std::env::current_exe()?);
    configure_test_command(&mut command, &directory, "supervisor");
    command.env(
        "NAC_APPSEC_TEST_DESCENDANT_PID",
        directory.join("descendant.pid"),
    );
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    let (mut supervisor, mut guard) =
        nac_process::ProcessTreeGuard::spawn_supervised(&mut command)?;
    let ready = tokio::time::timeout(Duration::from_secs(10), entered.notified()).await;
    if ready.is_err() {
        guard.terminate(&mut supervisor).await?;
        bail!("supervisor loss fixture never reached provider");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let descendant: i32 = std::fs::read_to_string(directory.join("descendant.pid"))?.parse()?;
    let descendant_start =
        nac_process::process_start_time(descendant).context("fixture descendant is missing")?;
    let before = controller.reconcile(campaign.id, &mut runtime)?;
    supervisor.start_kill()?;
    supervisor.wait().await?;
    let observation = runtime.observe(assignment.lease.attempt_id);
    let reconciliation = controller.reconcile(campaign.id, &mut runtime);
    let status = controller.status(campaign.id)?;
    controller.cancel(campaign.id, status.revision)?;
    let _ = controller.reconcile(campaign.id, &mut runtime);
    let mut late = Command::new(std::env::current_exe()?);
    configure_test_command(&mut late, &directory, "supervisor");
    let late = tokio::process::Command::from(late).status().await?;
    let after_replay = runtime.observe(assignment.lease.attempt_id);
    let replay_reconciliation = controller.reconcile(campaign.id, &mut runtime);
    let child_still_owned = nac_process::process_start_time(descendant) == Some(descendant_start);
    let child_stat = std::fs::read_to_string(format!("/proc/{descendant}/stat"))?;
    let child_still_live = child_stat
        .rsplit_once(')')
        .is_some_and(|(_, tail)| !tail.trim_start().starts_with('Z'));
    guard.terminate(&mut supervisor).await?;
    server.abort();
    assert!(
        observation.is_err(),
        "a dead supervisor's last nonterminal snapshot is not live ownership"
    );
    assert!(
        reconciliation.is_err(),
        "controller cannot renew from an unowned snapshot"
    );
    assert!(
        child_still_owned && child_still_live,
        "the owned descendant must remain live before test cleanup"
    );
    assert!(
        !late.success(),
        "a replacement supervisor cannot claim ownership of prior possible children"
    );
    assert!(
        after_replay.is_err() && replay_reconciliation.is_err(),
        "late replay must not forge terminal cleanup"
    );
    let after = controller.status(campaign.id)?;
    assert!(
        after.tasks[0].attempts[0].runtime_slot_held,
        "supervisor loss cannot prove termination or rule out pending launch"
    );
    assert_eq!(
        after.tasks[0].attempts[0].last_liveness_ms,
        before.tasks[0].attempts[0].last_liveness_ms
    );
    assert_eq!(
        after.tasks[0].attempts[0].deadline_ms,
        before.tasks[0].attempts[0].deadline_ms
    );
    Ok(())
}

#[test]
fn held_supervisor_lock_does_not_make_a_stale_snapshot_live() -> Result<()> {
    let fixture = Fixture::new()?;
    let controller = fixture.controller()?;
    let campaign = controller.create(fixture.manifest.clone())?;
    let assignment = controller
        .dispatch_next(campaign.id, campaign.revision, &mut AdmissionFixture)?
        .unwrap();
    let mut runtime = fixture.runtime("http://127.0.0.1:1".into())?;
    let directory = runtime.directory(assignment.lease.attempt_id);
    private_dir(&directory)?;
    let ownership = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("supervisor.lock"))?;
    fs2::FileExt::lock_exclusive(&ownership)?;
    write_json(
        &directory.join("observation.json"),
        &Observation {
            observed_ms: Some(1),
            ..Observation::default()
        },
    )?;
    assert!(runtime
        .observe(assignment.lease.attempt_id)
        .err()
        .context("stale snapshot was accepted")?
        .to_string()
        .contains("stale"));
    write_json(
        &directory.join("observation.json"),
        &Observation {
            observed_ms: Some(SystemClock.now_ms()?),
            ..Observation::default()
        },
    )?;
    assert!(matches!(
        runtime.observe(assignment.lease.attempt_id)?,
        RuntimeObservation::Live { .. }
    ));
    drop(ownership);
    assert!(runtime.observe(assignment.lease.attempt_id).is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_receipt_is_final_before_and_after_a_later_tombstone() -> Result<()> {
    let fixture = Fixture::new()?;
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = Arc::clone(&requests);
    let app = axum::Router::new().route("/responses",axum::routing::post(move || {
        let received = Arc::clone(&received);
        async move {
            received.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
            axum::Json(response(vec![json!({"type":"message","content":[{"type":"output_text","text":"scripted natural process exit, not an accepted result"}]})]))
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
    let directory = runtime.directory(assignment.lease.attempt_id);
    for _ in 0..400 {
        if runtime
            .observation(assignment.lease.attempt_id)
            .ok()
            .is_some_and(|state| state.exit.is_some())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        runtime.observation(assignment.lease.attempt_id)?.exit,
        Some(RuntimeExit::Success)
    );
    let receipt = std::fs::read(directory.join("observation.json"))?;
    let connection = std::fs::read(directory.join("connection.json"))?;
    for cancelled in [false, true] {
        if cancelled {
            runtime.cancel(assignment.lease.attempt_id)?;
        }
        let mut late = Command::new(std::env::current_exe()?);
        configure_test_command(&mut late, &directory, "supervisor");
        let status = tokio::process::Command::from(late).status().await?;
        assert!(
            status.success(),
            "terminal supervisor replay is a read-only success"
        );
        assert!(
            std::fs::read(directory.join("observation.json"))? == receipt,
            "a terminal physical outcome cannot be overwritten"
        );
        assert!(
            std::fs::read(directory.join("connection.json"))? == connection,
            "terminal replay must not construct another worker connection"
        );
    }
    server.abort();
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        controller.status(campaign.id)?.accepted.is_empty(),
        "natural exit never accepts model prose"
    );
    Ok(())
}
