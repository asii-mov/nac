use super::process;
use anyhow::{ensure, Result};
use nac_appsec::{HttpMethod, HttpRequest};
use std::ffi::OsString;

pub(super) struct Exchange {
    pub raw: Vec<u8>,
    pub tail: Vec<u8>,
    pub total: u64,
    pub complete: bool,
    pub body: Vec<u8>,
}

pub(super) fn send(
    pid: u64,
    request: &HttpRequest,
    owner: &str,
    cap: usize,
    timeout_ms: u64,
) -> Result<Exchange> {
    ensure!(pid > 1, "invalid target namespace");
    ensure!(
        request.path.starts_with('/')
            && !request.path.starts_with("//")
            && !request.path.contains(['\r', '\n', '\\', '"', '\0', '#'])
            && request.path.len() <= 1024
            && request.body.len() <= 8192,
        "invalid registered HTTP request"
    );
    let actor = match request.actor.as_str() {
        "owner" => owner,
        "attacker" => "unprivileged-pilot",
        "anonymous" => "",
        _ => anyhow::bail!("unregistered actor"),
    };
    ensure!(
        actor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid private actor credential"
    );
    let method = match request.method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
    };
    let start_time = nac_process::process_start_time(pid.try_into()?)
        .ok_or_else(|| anyhow::anyhow!("target process identity unavailable"))?;
    let configuration = serde_json::to_vec(
        &serde_json::json!({"pid":pid,"start_time":start_time,"method":method,"path":request.path,"body":request.body,"actor":actor,"cap":cap}),
    )?;
    let arguments: Vec<OsString> = [
        "-n",
        "/usr/bin/python3",
        "-I",
        "-c",
        include_str!("http_broker.py"),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let output = process::execute("/usr/bin/sudo", &arguments, configuration, timeout_ms, cap)?;
    ensure!(output.success, "private HTTP delivery failed");
    let separator = output
        .bytes
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n");
    let body = separator.map_or_else(Vec::new, |offset| output.bytes[offset + 4..].to_vec());
    Ok(Exchange {
        complete: output.complete && separator.is_some(),
        raw: output.bytes,
        tail: output.tail,
        total: output.total,
        body,
    })
}
