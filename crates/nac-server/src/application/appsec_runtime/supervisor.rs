use super::*;
use nac_process::ProcessTreeGuard;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

#[derive(Serialize, Deserialize)]
pub(super) enum WorkerFrame {
    Loaded(Box<LoadedWorkerInputs>),
    Snapshot(WorkerControlSnapshot),
    Finished(WorkerControlSnapshot),
}

#[derive(Serialize, Deserialize)]
pub(super) enum InputAdmission {
    Accepted,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Connection {
    pub supervisor_pid: u32,
    pub url: String,
    pub token: String,
}

pub async fn supervise_appsec_worker(directory: &Path) -> Result<()> {
    nac_core::runtime::restrict_same_uid_inspection()?;
    let launch: Launch = read_json(&directory.join("launch.json"))?;
    let ownership = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("supervisor.lock"))?;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match fs2::FileExt::try_lock_exclusive(&ownership) {
                Ok(()) => return Ok::<(), std::io::Error>(()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    let mut observation: Observation = read_json(&directory.join("observation.json"))?;
    {
        let _gate = launch_gate(directory)?;
        if observation.exit.is_some() {
            return Ok(());
        }
        let admission: ChildAdmission = read_json(&directory.join("child-admission.json"))?;
        ensure!(
            admission == ChildAdmission::Pending,
            "a prior guardian admitted possible children; cleanup remains uncertain"
        );
        if directory.join("cancelled").exists() {
            observation.control.active.clear();
            observation.exit = Some(RuntimeExit::Cancelled);
            write_json(&directory.join("observation.json"), &observation)?;
            return Ok(());
        }
    }
    let listener = event_listener(launch.assignment.lease.attempt_id)?;
    let tools = tools::ResearchTools::new(&launch.state, launch.assignment.lease.clone())?;
    let token = uuid::Uuid::new_v4().to_string();
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/mcp", http.local_addr()?);
    let router = crate::delivery::appsec_mcp::router(
        tools.clone(),
        token.clone(),
        launch.assignment.limits.output_bytes as usize,
    );
    let service = tokio::spawn(async move { axum::serve(http, router).await });
    write_json(
        &directory.join("connection.json"),
        &Connection {
            supervisor_pid: std::process::id(),
            url,
            token,
        },
    )?;
    let mut command = Command::new(&launch.executable);
    configure_command(&mut command, directory, "worker");
    #[cfg(test)]
    if launch.test_helper {
        configure_test_command(&mut command, directory, "worker");
    }
    let mut command = tokio::process::Command::from(command);
    command
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (mut child, mut guard) = {
        let _gate = launch_gate(directory)?;
        if directory.join("cancelled").exists() {
            service.abort();
            observation.control.active.clear();
            observation.exit = Some(RuntimeExit::Cancelled);
            write_json(&directory.join("observation.json"), &observation)?;
            return Ok(());
        }
        write_json(
            &directory.join("child-admission.json"),
            &ChildAdmission::ChildMayExist,
        )?;
        ProcessTreeGuard::spawn_supervised(&mut command)?
    };
    let pid = child.id().context("worker has no process ID")?;
    let stderr = child
        .stderr
        .take()
        .context("worker diagnostic pipe missing")?;
    let stdout = child.stdout.take().context("worker output pipe missing")?;
    let diagnostic_limit = launch.assignment.limits.output_bytes.min(1024 * 1024) as usize;
    let stderr_task = tokio::spawn(capture(
        stderr,
        directory.join("stderr.log"),
        diagnostic_limit,
    ));
    let stdout_task = tokio::spawn(capture(
        stdout,
        directory.join("stdout.log"),
        diagnostic_limit,
    ));
    let current = Arc::new(Mutex::new(observation));
    let incoming = Arc::clone(&current);
    let expected_prompt = launch
        .assignment
        .research
        .as_ref()
        .context("missing frozen research")?
        .prompt_sha256
        .clone();
    let expected_model = launch.model.model.clone();
    let expected_reasoning = launch.model.reasoning.clone();
    let expected_backend = "chatgpt-codex-responses";
    #[cfg(test)]
    let expected_backend = if launch.model.fixture_endpoint.is_some() {
        "openai-responses"
    } else {
        expected_backend
    };
    let loaded_tools = tools.clone();
    let connection_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        ensure!(
            stream.peer_cred()?.pid() == Some(pid as i32),
            "worker control peer PID mismatch"
        );
        loop {
            let frame: WorkerFrame = receive(&mut stream).await?;
            match frame {
                WorkerFrame::Loaded(proof) => {
                    ensure!(
                        proof.model == expected_model
                            && proof.reasoning.as_deref() == Some(expected_reasoning.as_str())
                            && proof.backend == expected_backend,
                        "worker loaded an unexpected model route"
                    );
                    let expected_tools: std::collections::BTreeSet<_> =
                        tools::tool_names(launch.assignment.experiment_tools)
                            .iter()
                            .map(|name| format!("mcp__controller__{name}"))
                            .collect();
                    ensure!(
                        proof
                            .tools
                            .iter()
                            .cloned()
                            .collect::<std::collections::BTreeSet<_>>()
                            == expected_tools,
                        "worker loaded an unexpected tool inventory"
                    );
                    ensure!(
                        proof.prompt_sha256 == expected_prompt
                            && proof.ambient_inputs.is_empty()
                            && proof.source_threads.is_empty(),
                        "worker loaded unexpected inputs"
                    );
                    loaded_tools.record_loaded(&proof)?;
                    incoming
                        .lock()
                        .map_err(|_| anyhow::anyhow!("worker observation lock poisoned"))?
                        .loaded = Some(*proof);
                    send(&mut stream, &InputAdmission::Accepted).await?;
                }
                WorkerFrame::Snapshot(snapshot) => {
                    incoming
                        .lock()
                        .map_err(|_| anyhow::anyhow!("worker observation lock poisoned"))?
                        .control = snapshot;
                }
                WorkerFrame::Finished(snapshot) => {
                    incoming
                        .lock()
                        .map_err(|_| anyhow::anyhow!("worker observation lock poisoned"))?
                        .control = snapshot;
                    return Ok::<(), anyhow::Error>(());
                }
            }
        }
    });
    let mut cancelled = false;
    let status = loop {
        if directory.join("cancelled").exists() {
            cancelled = true;
            tokio::time::sleep(Duration::from_millis(150)).await;
            guard.terminate(&mut child).await?;
            break child.wait().await?;
        }
        if let Some(status) = child.try_wait()? {
            guard.terminate(&mut child).await?;
            break status;
        }
        {
            let mut state = current
                .lock()
                .map_err(|_| anyhow::anyhow!("worker observation lock poisoned"))?;
            state.progress = tools
                .progress
                .lock()
                .map_err(|_| anyhow::anyhow!("progress lock poisoned"))?
                .clone();
            state.observed_ms = Some(SystemClock.now_ms()?);
            write_json(&directory.join("observation.json"), &*state)?;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let transport = tokio::time::timeout(Duration::from_secs(1), connection_task).await;
    let channel_ok = matches!(transport, Ok(Ok(Ok(()))));
    let _ = tokio::time::timeout(Duration::from_secs(1), stderr_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), stdout_task).await;
    service.abort();
    let mut state = current
        .lock()
        .map_err(|_| anyhow::anyhow!("worker observation lock poisoned"))?;
    state.progress = tools
        .progress
        .lock()
        .map_err(|_| anyhow::anyhow!("progress lock poisoned"))?
        .clone();
    state.control.active.clear();
    state.exit = Some(if cancelled {
        RuntimeExit::Cancelled
    } else if status.success() && channel_ok && state.loaded.is_some() {
        RuntimeExit::Success
    } else {
        RuntimeExit::ProviderFailure
    });
    write_json(&directory.join("observation.json"), &*state)?;
    Ok(())
}

async fn capture(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    path: PathBuf,
    limit: usize,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut retained = 0;
    let mut buffer = [0; 4096];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            break;
        }
        let keep = length.min(limit.saturating_sub(retained));
        file.write_all(&buffer[..keep])?;
        retained += keep;
    }
    file.sync_all()?;
    Ok(())
}

pub(super) async fn send(stream: &mut UnixStream, value: &(impl Serialize + Sync)) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "worker control frame exceeds bound"
    );
    stream.write_u32(bytes.len().try_into()?).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub(super) async fn receive<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    ensure!(length <= 1024 * 1024, "worker control frame exceeds bound");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "linux")]
fn event_listener(attempt: Id) -> Result<UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(format!("nac-appsec-{attempt}"))?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
    listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(listener)?)
}

#[cfg(not(target_os = "linux"))]
fn event_listener(_: Id) -> Result<UnixListener> {
    bail!("controlled worker requires Linux peer authentication")
}

#[cfg(target_os = "linux")]
pub(super) fn event_connection(attempt: Id) -> Result<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(format!("nac-appsec-{attempt}"))?;
    let stream = std::os::unix::net::UnixStream::connect_addr(&address)?;
    stream.set_nonblocking(true)?;
    Ok(UnixStream::from_std(stream)?)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn event_connection(_: Id) -> Result<UnixStream> {
    bail!("controlled worker requires Linux peer authentication")
}
