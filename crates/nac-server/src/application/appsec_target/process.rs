use anyhow::{ensure, Context, Result};
use nac_process::ProcessTreeGuard;
use std::{ffi::OsString, process::Stdio, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub(super) struct Output {
    pub bytes: Vec<u8>,
    pub tail: Vec<u8>,
    pub total: u64,
    pub stdout_complete: bool,
    pub stderr_bytes: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub stderr_total: u64,
    pub stderr_complete: bool,
    pub complete: bool,
    pub success: bool,
    pub full: Vec<u8>,
    pub stderr_full: Vec<u8>,
}

pub(super) fn execute(
    program: &str,
    arguments: &[OsString],
    input: Vec<u8>,
    milliseconds: u64,
    cap: usize,
) -> Result<Output> {
    let program = program.to_string();
    let arguments = arguments.to_vec();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let mut command = tokio::process::Command::new(program);
                command
                    .args(arguments)
                    .env_clear()
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .env("HOME", "/nonexistent")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                let (mut child, mut guard) = ProcessTreeGuard::spawn_supervised(&mut command)?;
                let mut stdin = child
                    .stdin
                    .take()
                    .context("private process stdin unavailable")?;
                let writer = tokio::spawn(async move { stdin.write_all(&input).await });
                let stdout = child
                    .stdout
                    .take()
                    .context("private process stdout unavailable")?;
                let stderr = child
                    .stderr
                    .take()
                    .context("private process stderr unavailable")?;
                let out = tokio::spawn(capture(stdout, cap));
                let err = tokio::spawn(capture(stderr, cap));
                let waited =
                    tokio::time::timeout(Duration::from_millis(milliseconds), child.wait()).await;
                let status = match waited {
                    Ok(status) => status?,
                    Err(_) => {
                        guard.terminate(&mut child).await?;
                        writer.abort();
                        out.abort();
                        err.abort();
                        anyhow::bail!("private operation uncertain");
                    }
                };
                guard.mark_leader_reaped();
                guard.finish().await;
                let _ = writer.await?;
                let stdout = out.await??;
                let stderr = err.await??;
                Ok(Output {
                    bytes: stdout.bytes,
                    tail: stdout.tail,
                    total: stdout.total,
                    stdout_complete: stdout.complete,
                    stderr_bytes: stderr.bytes,
                    stderr_tail: stderr.tail,
                    stderr_total: stderr.total,
                    stderr_complete: stderr.complete,
                    complete: stdout.complete && stderr.complete,
                    success: status.success(),
                    full: stdout.full,
                    stderr_full: stderr.full,
                })
            })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("private operation failed"))?
}

struct Capture {
    bytes: Vec<u8>,
    tail: Vec<u8>,
    total: u64,
    complete: bool,
    full: Vec<u8>,
}

async fn capture(mut stream: impl AsyncRead + Unpin, cap: usize) -> Result<Capture> {
    let head_cap = cap.div_ceil(2);
    let tail_cap = cap / 2;
    let mut bytes = Vec::new();
    let mut tail = Vec::new();
    let mut total = 0u64;
    let mut full = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let length = stream.read(&mut buffer).await?;
        if length == 0 {
            if total <= cap as u64 {
                bytes.extend_from_slice(&tail);
                tail.clear();
            }
            return Ok(Capture {
                complete: total <= cap as u64,
                bytes,
                tail,
                total,
                full,
            });
        }
        total = total
            .checked_add(length.try_into()?)
            .context("private output size overflow")?;
        if full.len() < cap {
            full.extend_from_slice(&buffer[..length.min(cap - full.len())]);
        }
        let retained = length.min(head_cap.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        if retained < length && tail_cap > 0 {
            tail.extend_from_slice(&buffer[retained..length]);
            if tail.len() > tail_cap {
                tail.drain(..tail.len() - tail_cap);
            }
        }
    }
}

pub(super) fn docker(arguments: &[&str]) -> Result<Vec<u8>> {
    docker_bounded(arguments, 30_000)
}

pub(super) fn docker_bounded(arguments: &[&str], milliseconds: u64) -> Result<Vec<u8>> {
    let output = execute(
        "/usr/bin/docker",
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
        vec![],
        milliseconds,
        1024 * 1024,
    )?;
    ensure!(
        output.success && output.complete,
        "private engine operation failed"
    );
    Ok(output.bytes)
}

pub(super) fn capabilities(milliseconds: u64) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "controlled Docker targets require Linux"
    );
    docker_bounded(
        &["version", "--format", "{{.Server.Version}}"],
        milliseconds,
    )?;
    let arguments = [
        OsString::from("-n"),
        OsString::from("/usr/bin/python3"),
        OsString::from("-I"),
        OsString::from("-c"),
        OsString::from("import os,sys;sys.exit(0 if hasattr(os,'setns') else 1)"),
    ];
    let output = execute("/usr/bin/sudo", &arguments, vec![], milliseconds, 1_024)?;
    ensure!(output.success, "private namespace broker unavailable");
    Ok(())
}
