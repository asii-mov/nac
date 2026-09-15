use anyhow::{bail, ensure, Context, Result};
use nac_appsec::{
    ArtifactRef, ArtifactStore, Assignment, Clock, Id, Runtime, RuntimeExit, RuntimeObservation,
    SystemClock, Usage,
};
use nac_core::runtime::{LoadedWorkerInputs, WorkerControlSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

mod supervisor;
#[cfg(test)]
mod tests;
pub(crate) mod tools;
mod worker;

pub use supervisor::supervise_appsec_worker;
pub use worker::run_appsec_worker;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResearchModel {
    pub model: String,
    pub reasoning: String,
    #[cfg(test)]
    pub fixture_endpoint: Option<String>,
}

impl Default for NativeResearchModel {
    fn default() -> Self {
        Self {
            model: "gpt-5.6-sol".into(),
            reasoning: "high".into(),
            #[cfg(test)]
            fixture_endpoint: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Launch {
    state: PathBuf,
    assignment: Assignment,
    model: NativeResearchModel,
    executable: PathBuf,
    #[cfg(test)]
    test_helper: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChildAdmission {
    Pending,
    ChildMayExist,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Observation {
    #[serde(default)]
    observed_ms: Option<u64>,
    control: WorkerControlSnapshot,
    loaded: Option<LoadedWorkerInputs>,
    progress: Option<ArtifactRef>,
    exit: Option<RuntimeExit>,
}

pub struct NacWorkerRuntime {
    state: PathBuf,
    executable: PathBuf,
    model: NativeResearchModel,
    pub(crate) inputs_ready: bool,
    #[cfg(test)]
    test_helper: bool,
}

impl NacWorkerRuntime {
    pub fn new(state: &Path, executable: PathBuf, model: NativeResearchModel) -> Result<Self> {
        ensure!(
            executable.is_absolute(),
            "runtime executable must be absolute"
        );
        let state = if state.is_absolute() {
            state.to_path_buf()
        } else {
            std::env::current_dir()?.join(state)
        };
        ArtifactStore::open(&state)?;
        private_dir(&state.join("workers"))?;
        Ok(Self {
            state,
            executable,
            model,
            inputs_ready: true,
            #[cfg(test)]
            test_helper: false,
        })
    }

    fn directory(&self, attempt: Id) -> PathBuf {
        self.state.join("workers").join(attempt.to_string())
    }

    fn observation(&self, attempt: Id) -> Result<Observation> {
        read_json(&self.directory(attempt).join("observation.json"))
            .context("worker launch or cleanup is uncertain; slot remains held")
    }
}

impl Runtime for NacWorkerRuntime {
    fn check_capabilities(&self) -> Result<()> {
        ensure!(
            self.inputs_ready,
            "source-only runtime requires frozen skills and a typed brief; No model executed"
        );
        ensure!(
            cfg!(target_os = "linux"),
            "authenticated source-only worker control currently requires Linux"
        );
        ensure!(self.executable.is_file(), "worker executable is missing");
        ensure!(
            !self.model.model.trim().is_empty(),
            "native model is required"
        );
        serde_json::from_value::<nac_core::model::ReasoningEffort>(serde_json::Value::String(
            self.model.reasoning.clone(),
        ))?;
        Ok(())
    }

    fn start(&mut self, assignment: &Assignment) -> Result<()> {
        self.check_capabilities()?;
        ensure!(
            assignment.research.is_some(),
            "source-only dispatch requires frozen research inputs"
        );
        let directory = self.directory(assignment.lease.attempt_id);
        private_dir(&directory)?;
        let _gate = launch_gate(&directory)?;
        ensure!(
            !directory.join("cancelled").exists(),
            "attempt launch key is tombstoned"
        );
        if directory.join("launch.json").exists() {
            let existing: Launch = read_json(&directory.join("launch.json"))?;
            ensure!(
                serde_json::to_vec(&existing.assignment)? == serde_json::to_vec(assignment)?,
                "attempt launch key was reused with different inputs"
            );
            return Ok(());
        }
        let launch = Launch {
            state: self.state.clone(),
            assignment: assignment.clone(),
            model: self.model.clone(),
            executable: self.executable.clone(),
            #[cfg(test)]
            test_helper: self.test_helper,
        };
        write_json(&directory.join("launch.json"), &launch)?;
        write_json(
            &directory.join("child-admission.json"),
            &ChildAdmission::Pending,
        )?;
        let mut observation = Observation::default();
        let startup_id = format!("startup-{}", assignment.lease.attempt_id);
        observation.control.active.insert(
            startup_id.clone(),
            nac_core::runtime::WorkerOperation {
                id: startup_id,
                kind: "startup".into(),
                started_ms: SystemClock.now_ms()?,
            },
        );
        write_json(&directory.join("observation.json"), &observation)?;
        let mut command = Command::new(&self.executable);
        configure_command(&mut command, &directory, "supervisor");
        #[cfg(test)]
        if self.test_helper {
            configure_test_command(&mut command, &directory, "supervisor");
        }
        command.stderr(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(directory.join("supervisor.log"))?,
        );
        let mut child = command.spawn()?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }

    fn observe(&mut self, attempt: Id) -> Result<RuntimeObservation> {
        let observation = self.observation(attempt)?;
        if observation.exit.is_none() {
            let ownership = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.directory(attempt).join("supervisor.lock"))?;
            ensure!(
                ownership.metadata()?.is_file(),
                "supervisor ownership record is not a regular file"
            );
            match fs2::FileExt::try_lock_exclusive(&ownership) {
                Ok(()) => {
                    bail!("supervisor ownership is absent; launch and cleanup remain uncertain")
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            let observed_ms = observation
                .observed_ms
                .context("supervisor has not reported a live observation")?;
            ensure!(
                SystemClock
                    .now_ms()?
                    .checked_sub(observed_ms)
                    .is_some_and(|age| age <= 5000),
                "supervisor observation is stale; liveness remains uncertain"
            );
        }
        let usage = Usage {
            tokens: observation.control.observed_tokens,
            output_bytes: observation.control.observed_output_bytes,
            complete: false,
        };
        if let Some(exit) = observation.exit {
            return Ok(RuntimeObservation::Terminated {
                usage,
                exit,
                progress: observation.progress,
            });
        }
        let oldest_active_operation = observation
            .control
            .active
            .values()
            .min_by_key(|operation| (operation.started_ms, &operation.id))
            .map(|operation| nac_appsec::RuntimeOperation {
                id: operation.id.clone(),
                started_ms: operation.started_ms,
            });
        Ok(RuntimeObservation::Live {
            usage,
            progress: observation.progress,
            oldest_active_operation,
        })
    }

    fn cancel(&mut self, attempt: Id) -> Result<()> {
        let directory = self.directory(attempt);
        private_dir(&directory)?;
        let _gate = launch_gate(&directory)?;
        write_json(&directory.join("cancelled"), &SystemClock.now_ms()?)?;
        if !directory.join("launch.json").exists()
            && !directory.join("child-admission.json").exists()
        {
            write_json(
                &directory.join("observation.json"),
                &Observation {
                    exit: Some(RuntimeExit::Cancelled),
                    ..Observation::default()
                },
            )?;
        }
        Ok(())
    }

    fn diagnose(&mut self, attempt: Id) -> Result<ArtifactRef> {
        let observation = self.observation(attempt)?;
        ArtifactStore::open(&self.state)?.write(&serde_json::to_vec(&observation)?, 1024 * 1024)
    }
}

fn configure_command(command: &mut Command, directory: &Path, role: &str) {
    command
        .args(["appsec", "__process", "--role", role, "--directory"])
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

#[cfg(test)]
fn configure_test_command(command: &mut Command, directory: &Path, role: &str) {
    let executable = command.get_program().to_owned();
    *command = Command::new(executable);
    command
        .args([
            "--exact",
            "application::appsec_runtime::tests::process_helper",
            "--nocapture",
        ])
        .env("NAC_APPSEC_TEST_ROLE", role)
        .env("NAC_APPSEC_TEST_DIRECTORY", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().context("directory has no parent")?)?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "worker state must be an owner-only real directory"
    );
    Ok(())
}

fn launch_gate(directory: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("launch.lock"))?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 4 * 1024 * 1024,
        "runtime record is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "runtime record grew beyond bound"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(path.parent().context("record has no parent")?)?.sync_all()?;
    Ok(())
}
