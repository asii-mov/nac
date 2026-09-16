use super::{private, process, FrozenPilot, Resource};
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::{ffi::OsString, path::Path};

pub(super) fn inspect(id: &str) -> Result<Value> {
    inspect_bounded(id, 30_000)
}

pub(super) fn inspect_bounded(id: &str, timeout_ms: u64) -> Result<Value> {
    let value: Value =
        serde_json::from_slice(&process::docker_bounded(&["inspect", id], timeout_ms)?)?;
    value
        .as_array()
        .and_then(|array| array.first())
        .cloned()
        .context("private engine inspection unavailable")
}

pub(super) fn prepare(
    resource: &mut Resource,
    recipe: &FrozenPilot,
    journal: &Path,
    timeout_ms: u64,
) -> Result<()> {
    if !resource.network_ack {
        if resource.network_pending {
            let network = network_bounded(&resource.name, timeout_ms)?;
            verify_network(&network, &resource.name)?;
        } else {
            resource.network_pending = true;
            private::write(journal, resource)?;
            process::docker_bounded(
                &[
                    "network",
                    "create",
                    "--internal",
                    "--ipv6=false",
                    "--opt",
                    "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                    "--label",
                    &format!("nac.appsec.target={}", resource.name),
                    &resource.name,
                ],
                timeout_ms,
            )?;
            verify_network(
                &network_bounded(&resource.name, timeout_ms)?,
                &resource.name,
            )?;
        }
        resource.network_ack = true;
        resource.network_pending = false;
        private::write(journal, resource)?;
    }
    if resource.container.is_none() {
        if !resource.create_pending {
            resource.create_pending = true;
            private::write(journal, resource)?;
            let arguments = [
                "create",
                "--pull=never",
                "--name",
                &resource.name,
                "--label",
                &format!("nac.appsec.target={}", resource.name),
                "--network",
                &resource.name,
                "--user",
                "65534:65534",
                "--read-only",
                "--tmpfs",
                "/run/nac:rw,noexec,nosuid,nodev,size=65536,uid=65534,gid=65534,mode=0700",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "seccomp=builtin",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "32",
                "--memory",
                "67108864",
                "--memory-swap",
                "67108864",
                "--cpus",
                "0.5",
                "--log-driver",
                "none",
                "--workdir",
                "/",
                "--env",
                if resource.protected {
                    "PILOT_PROTECTED=1"
                } else {
                    "PILOT_PROTECTED=0"
                },
                "--entrypoint",
                "/target",
                &recipe.image,
                "wait",
            ];
            process::docker_bounded(&arguments, timeout_ms)?;
        }
        let inspected = inspect_bounded(&resource.name, timeout_ms)?;
        verify_target(&inspected, resource, recipe, timeout_ms).context("identity_drift")?;
        resource.container = Some(
            inspected["Id"]
                .as_str()
                .context("missing effective engine identity")?
                .into(),
        );
        resource.create_pending = false;
        private::write(journal, resource)?;
    }
    Ok(())
}

pub(super) fn start(
    resource: &mut Resource,
    recipe: &FrozenPilot,
    journal: &Path,
    timeout_ms: u64,
) -> Result<u64> {
    let container = resource.container.clone().context("target missing")?;
    if !resource.start_pending {
        resource.start_pending = true;
        private::write(journal, resource)?;
        process::docker_bounded(&["start", &container], timeout_ms)?;
    }
    let value = inspect_bounded(&container, timeout_ms)?;
    verify_target(&value, resource, recipe, timeout_ms).context("identity_drift")?;
    ensure!(
        value["State"]["Running"] == true,
        "target start remains uncertain"
    );
    let pid = value["State"]["Pid"]
        .as_u64()
        .context("target process missing")?;
    if !resource.injected {
        let arguments = [
            OsString::from("exec"),
            OsString::from("-i"),
            OsString::from(&container),
            OsString::from("/target"),
            OsString::from("inject"),
        ];
        let output = process::execute(
            "/usr/bin/docker",
            &arguments,
            format!("{}\n{}", resource.nonce, resource.owner).into_bytes(),
            timeout_ms,
            4096,
        )?;
        ensure!(
            output.success && output.complete,
            "private injection failed"
        );
        resource.injected = true;
    }
    resource.started = true;
    resource.start_pending = false;
    private::write(journal, resource)?;
    Ok(pid)
}

pub(super) fn verify_target(
    value: &Value,
    resource: &Resource,
    recipe: &FrozenPilot,
    timeout_ms: u64,
) -> Result<()> {
    let host = &value["HostConfig"];
    let config = &value["Config"];
    ensure!(
        value["Image"] == recipe.image
            && config["Image"] == recipe.image
            && config["User"] == "65534:65534"
            && config["WorkingDir"] == "/"
            && config["Entrypoint"] == serde_json::json!(["/target"])
            && config["Cmd"] == serde_json::json!(["wait"]),
        "target identity drift"
    );
    ensure!(
        config["Env"]
            == serde_json::json!([
                if resource.protected {
                    "PILOT_PROTECTED=1"
                } else {
                    "PILOT_PROTECTED=0"
                },
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ]),
        "target environment drift"
    );
    ensure!(
        host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host["CapDrop"] == serde_json::json!(["ALL"])
            && host["CapAdd"].is_null(),
        "target capability policy drift"
    );
    ensure!(
        host["SecurityOpt"] == serde_json::json!(["seccomp=builtin", "no-new-privileges=true"])
            && host["PidsLimit"] == 32
            && host["Memory"] == 67108864u64
            && host["MemorySwap"] == 67108864u64
            && host["NanoCpus"] == 500000000u64,
        "target resource policy drift"
    );
    ensure!(
        host["LogConfig"]["Type"] == "none"
            && host["NetworkMode"] == resource.name
            && host["PortBindings"] == serde_json::json!({})
            && host["PublishAllPorts"] == false
            && value["NetworkSettings"]["Networks"]
                .as_object()
                .is_some_and(|networks| {
                    networks.len() == 1 && networks.contains_key(&resource.name)
                }),
        "target network or log policy drift"
    );
    ensure!(
        value["Mounts"] == serde_json::json!([])
            && host["Binds"].is_null()
            && host["Devices"] == serde_json::json!([])
            && host["PidMode"] == ""
            && host["IpcMode"] == "private"
            && host["Tmpfs"]
                == serde_json::json!({"/run/nac":"rw,noexec,nosuid,nodev,size=65536,uid=65534,gid=65534,mode=0700"}),
        "target host exposure drift"
    );
    ensure!(
        config["Labels"]["nac.appsec.target"] == resource.name,
        "target ownership drift"
    );
    let diff = process::docker_bounded(
        &[
            "diff",
            value["Id"].as_str().context("target identity missing")?,
        ],
        timeout_ms,
    )?;
    let changes: std::collections::BTreeSet<_> = String::from_utf8(diff)?
        .lines()
        .map(str::to_string)
        .collect();
    let allowed =
        std::collections::BTreeSet::from(["A /run".to_string(), "A /run/nac".to_string()]);
    ensure!(
        (value["State"]["Running"] == false && changes.is_empty())
            || (value["State"]["Running"] == true && changes == allowed),
        "target writable-path drift"
    );
    verify_network(
        &network_bounded(&resource.name, timeout_ms)?,
        &resource.name,
    )?;
    let info: Value = serde_json::from_slice(&process::docker_bounded(
        &["info", "--format", "{{json .}}"],
        timeout_ms,
    )?)?;
    ensure!(
        info["SecurityOptions"]
            .as_array()
            .is_some_and(|options| options
                .iter()
                .any(|option| option.as_str() == Some("name=seccomp,profile=builtin"))),
        "engine seccomp unavailable"
    );
    Ok(())
}

pub(super) fn deny_checks(resource: &Resource, timeout_ms: u64) -> Result<()> {
    let current = resource.container.as_deref().context("target missing")?;
    let listed = String::from_utf8(process::docker_bounded(
        &[
            "ps",
            "--no-trunc",
            "--filter",
            "label=nac.appsec.target",
            "--format",
            "{{.ID}}",
        ],
        timeout_ms,
    )?)?;
    let mut addresses = vec![
        "169.254.169.254".to_string(),
        "1.1.1.1".to_string(),
        "192.0.2.1".to_string(),
        "2001:db8::1".to_string(),
    ];
    for container in listed.lines().filter(|container| *container != current) {
        let value = inspect_bounded(container, timeout_ms)?;
        let networks = value["NetworkSettings"]["Networks"]
            .as_object()
            .context("target network addresses missing")?;
        for network in networks.values() {
            for key in ["IPAddress", "GlobalIPv6Address"] {
                if let Some(address) = network[key].as_str().filter(|address| !address.is_empty()) {
                    addresses.push(address.into());
                }
            }
        }
    }
    addresses.sort();
    addresses.dedup();
    let addresses: Vec<_> = addresses.iter().map(String::as_str).collect();
    adapter_network_probe(resource, &addresses, timeout_ms)
}

#[cfg(test)]
pub(super) fn address(resource: &Resource) -> Result<String> {
    let value = inspect(resource.container.as_ref().context("target missing")?)?;
    value["NetworkSettings"]["Networks"][&resource.name]["IPAddress"]
        .as_str()
        .map(str::to_string)
        .context("target network address missing")
}

#[cfg(test)]
pub(super) fn deny_address(resource: &Resource, address: &str) -> Result<()> {
    adapter_network_probe(resource, &[address], 15_000)
}

fn adapter_network_probe(resource: &Resource, addresses: &[&str], timeout_ms: u64) -> Result<()> {
    let container = resource.container.as_ref().context("target missing")?;
    let value = inspect_bounded(container, timeout_ms)?;
    let pid = value["State"]["Pid"]
        .as_u64()
        .context("target process missing")?;
    let start_time = nac_process::process_start_time(pid.try_into()?)
        .context("target process identity unavailable")?;
    let input = serde_json::to_vec(&serde_json::json!({
        "pid": pid,
        "start_time": start_time,
        "addresses": addresses,
    }))?;
    let arguments = [
        OsString::from("-n"),
        OsString::from("/usr/bin/python3"),
        OsString::from("-I"),
        OsString::from("-c"),
        OsString::from(include_str!("network_probe.py")),
    ];
    let output = process::execute("/usr/bin/sudo", &arguments, input, timeout_ms, 4096)?;
    ensure!(
        output.success && output.complete && output.bytes == b"adapter-network-denied",
        "adapter-owned network isolation probe failed"
    );
    Ok(())
}

pub(super) fn cleanup(resource: &mut Resource, journal: &Path, timeout_ms: u64) -> Result<()> {
    resource.stopped = true;
    private::write(journal, resource)?;
    if resource.create_pending && resource.container.is_none() {
        let listed = process::docker_bounded(
            &[
                "ps",
                "-a",
                "--filter",
                &format!("name=^/{}$", resource.name),
                "--format",
                "{{.Names}}",
            ],
            timeout_ms,
        )?;
        if listed.is_empty() {
            resource.create_pending = false;
        } else {
            let found = inspect_bounded(&resource.name, timeout_ms)?;
            ensure!(
                found["Config"]["Labels"]["nac.appsec.target"] == resource.name,
                "target ownership uncertain"
            );
            resource.container = Some(
                found["Id"]
                    .as_str()
                    .context("missing engine identity")?
                    .into(),
            );
            resource.create_pending = false;
        }
        private::write(journal, resource)?;
    }
    if let Some(container) = &resource.container {
        let listed = process::docker_bounded(
            &[
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                &format!("id={container}"),
                "--format",
                "{{.ID}}",
            ],
            timeout_ms,
        )?;
        if !listed.is_empty() {
            process::docker_bounded(&["rm", "--force", container], timeout_ms)?;
        }
        let remaining = process::docker_bounded(
            &[
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                &format!("id={container}"),
                "--format",
                "{{.ID}}",
            ],
            timeout_ms,
        )?;
        ensure!(remaining.is_empty(), "target cleanup uncertain");
    }
    if resource.network_pending && !resource.network_ack {
        let listed = process::docker_bounded(
            &[
                "network",
                "ls",
                "--filter",
                &format!("name=^{}$", resource.name),
                "--format",
                "{{.Name}}",
            ],
            timeout_ms,
        )?;
        if listed.is_empty() {
            resource.network_pending = false;
        } else {
            verify_network(
                &network_bounded(&resource.name, timeout_ms)?,
                &resource.name,
            )?;
            resource.network_ack = true;
            resource.network_pending = false;
        }
        private::write(journal, resource)?;
    }
    if resource.network_ack {
        let listed = process::docker_bounded(
            &[
                "network",
                "ls",
                "--filter",
                &format!("name=^{}$", resource.name),
                "--format",
                "{{.Name}}",
            ],
            timeout_ms,
        )?;
        if !listed.is_empty() {
            verify_network(
                &network_bounded(&resource.name, timeout_ms)?,
                &resource.name,
            )?;
            process::docker_bounded(&["network", "rm", &resource.name], timeout_ms)?;
        }
        ensure!(
            process::docker_bounded(
                &[
                    "network",
                    "ls",
                    "--filter",
                    &format!("name=^{}$", resource.name),
                    "--format",
                    "{{.Name}}"
                ],
                timeout_ms,
            )?
            .is_empty(),
            "network cleanup uncertain"
        );
    }
    ensure!(
        !resource.create_pending && !resource.network_pending,
        "pending creation retains capacity"
    );
    resource.cleaned = true;
    private::write(journal, resource)?;
    Ok(())
}

fn network_bounded(name: &str, timeout_ms: u64) -> Result<Value> {
    let value: Value = serde_json::from_slice(&process::docker_bounded(
        &["network", "inspect", name],
        timeout_ms,
    )?)?;
    value
        .as_array()
        .and_then(|array| array.first())
        .cloned()
        .context("private network inspection unavailable")
}

fn verify_network(network: &Value, name: &str) -> Result<()> {
    ensure!(
        network["Name"] == name
            && network["Driver"] == "bridge"
            && network["Internal"] == true
            && network["EnableIPv6"] == false
            && network["Options"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
            && network["Labels"]["nac.appsec.target"] == name,
        "target network drift"
    );
    Ok(())
}
