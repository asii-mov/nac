use std::{path::PathBuf, process};

use clap::{Args, Subcommand};
use nac_appsec::{Campaign, ExperimentProfile, HttpInterface, Id, Manifest, OracleClass};
use nac_server::{
    run_appsec_doctor, AppsecControl, AppsecTargetRunner, DoctorError, FrozenPilot,
    LocalPilotPreparation,
};

#[derive(Args)]
pub(super) struct AppsecCli {
    #[command(subcommand)]
    command: AppsecCommand,
}

#[derive(Subcommand)]
enum AppsecCommand {
    #[command(name = "__process", hide = true)]
    Process {
        #[arg(long)]
        role: String,
        #[arg(long)]
        directory: PathBuf,
    },
    /// Freeze the selected bootstrap skills and typed brief into a manifest
    Freeze {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        skills: PathBuf,
        #[arg(long)]
        brief: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        workflow: bool,
        #[arg(long)]
        experiment_profile: Option<PathBuf>,
    },
    /// Reconcile and drive admitted source-only workers until stopped
    Watch {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
    },
    /// Write an offline JSON and Markdown prerequisite diagnostic; never execute a model
    Doctor {
        #[arg(long, value_name = "JSON")]
        config: PathBuf,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        output: PathBuf,
    },
    /// Build reviewed local pilot images and emit a public profile plus private registry
    PrepareLocalPilot {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        commit: String,
        #[arg(long, default_value = "local-pilot")]
        repository_id: String,
        #[arg(long = "include", required = true)]
        includes: Vec<String>,
        #[arg(long)]
        interface: PathBuf,
        #[arg(long, value_parser = ["authorization", "rce-nonce"])]
        oracle: String,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        output: PathBuf,
    },
    /// Persist a frozen campaign and admit a native worker
    Run {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        experiment_registry: Option<PathBuf>,
        #[arg(long)]
        target_capacity: Option<u32>,
    },
    /// Inspect canonical controller state and verified evidence
    Status {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
    },
    /// Revoke submission rights and signal runtime cleanup without requiring a watcher
    Cancel {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        revision: u64,
    },
    /// Revoke a diagnosed suspected stall and request cleanup; never automatically resume
    Recover {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        task_id: Id,
        #[arg(long)]
        revision: u64,
    },
    /// Queue a resumable task with a bounded handoff, without dispatching a model
    Resume {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        task_id: Id,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        handoff: String,
    },
    /// Write JSON and Markdown reports to a new directory
    Report {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read one task-safe experiment projection from canonical state
    ExperimentRead {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        experiment_id: Id,
    },
    /// Commit an experiment stop tombstone using the owning task lease
    ExperimentCancel {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        experiment_id: Id,
    },
    /// Clear bounded experiment adapter recovery state after reviewing diagnostics
    ExperimentRecover {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
        #[arg(long)]
        experiment_id: Id,
    },
    /// Reconcile frozen experiment desired state with the private Docker adapter once
    ExperimentReconcile {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
    },
    /// Drive only locally authored pilot experiments until cleanup is confirmed
    ExperimentDemo {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
    },
}

pub(super) async fn run(cli: AppsecCli) -> anyhow::Result<()> {
    match cli.command {
        AppsecCommand::Process { role, directory } => match role.as_str() {
            "supervisor" => nac_server::supervise_appsec_worker(&directory).await?,
            "worker" => nac_server::run_appsec_worker(&directory).await?,
            _ => anyhow::bail!("unknown internal process role"),
        },
        AppsecCommand::Freeze {
            manifest,
            skills,
            brief,
            output,
            workflow,
            experiment_profile,
        } => {
            let mut manifest: Manifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
            let brief = serde_json::from_slice(&std::fs::read(brief)?)?;
            let stages = manifest
                .tasks
                .iter()
                .map(|task| {
                    (
                        task.key.clone(),
                        if workflow {
                            "recon".into()
                        } else {
                            "discovery".into()
                        },
                    )
                })
                .collect();
            let profile = match experiment_profile {
                Some(path) => Some(serde_json::from_slice::<ExperimentProfile>(
                    &std::fs::read(path)?,
                )?),
                None => None,
            };
            let mut research = nac_appsec::FrozenResearch::resolve(&skills, brief, stages)?;
            research.workflow = workflow;
            if profile.is_some() {
                research.enable_controlled_experiments()?;
            }
            research.verify()?;
            manifest.research = Some(research);
            manifest.experiments = profile;
            write_report(&output, &serde_json::to_vec_pretty(&manifest)?)?;
        }
        AppsecCommand::Watch { state, run_id } => {
            watch(state, run_id).await?;
        }
        AppsecCommand::Doctor { config, output } => match run_appsec_doctor(&config, &output) {
            Ok(true) => println!("Offline doctor reports written; readiness: ready."),
            Ok(false) => {
                eprintln!("Offline doctor reports written; readiness: blocked. No model executed.");
                process::exit(3);
            }
            Err(error @ DoctorError::InvalidConfig(_)) => {
                eprintln!("Error: {error}");
                process::exit(2);
            }
            Err(error) => return Err(error.into()),
        },
        AppsecCommand::PrepareLocalPilot {
            repository,
            commit,
            repository_id,
            includes,
            interface,
            oracle,
            output,
        } => {
            let repository = std::fs::canonicalize(repository)?;
            let interface: HttpInterface = serde_json::from_slice(&std::fs::read(interface)?)?;
            let oracle_class = match oracle.as_str() {
                "authorization" => OracleClass::Authorization,
                "rce-nonce" => OracleClass::RceNonce,
                _ => unreachable!("clap validates local pilot oracle"),
            };
            let output = if output.is_absolute() {
                output
            } else {
                std::env::current_dir()?.join(output)
            };
            let artifacts = AppsecTargetRunner::prepare_local_pilot(LocalPilotPreparation {
                repository,
                commit,
                repository_id,
                includes,
                interface,
                oracle_class,
                output,
            })?;
            println!("{}", serde_json::to_string_pretty(&artifacts)?);
        }
        AppsecCommand::Run {
            manifest,
            state,
            experiment_registry,
            target_capacity,
        } => {
            let manifest: Manifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
            let control = match (&manifest.experiments, experiment_registry, target_capacity) {
                (Some(profile), Some(registry), Some(capacity)) => {
                    let pilots: Vec<FrozenPilot> =
                        serde_json::from_slice(&std::fs::read(registry)?)?;
                    AppsecTargetRunner::freeze_registry(&state, &profile.recipes, pilots)?;
                    AppsecControl::open_with_target_capacity(&state, capacity)?
                }
                (None, None, None) => AppsecControl::open(&state)?,
                (Some(_), _, _) => anyhow::bail!(
                    "experiment campaigns require a private registry and finite target capacity"
                ),
                (None, _, _) => {
                    anyhow::bail!("source-only campaigns do not accept experiment adapter options")
                }
            };
            let campaign = control.run(manifest)?;
            print_status(&campaign)?;
            if campaign.dispatch_blocker.is_some() {
                eprintln!("Campaign persisted; freeze the selected skills and typed brief before dispatch. No model executed.");
                process::exit(3);
            }
            watch(state, campaign.id).await?;
        }
        AppsecCommand::Status { state, run_id } => {
            print_status(&AppsecControl::open(&state)?.status(run_id)?)?;
        }
        AppsecCommand::Cancel {
            state,
            run_id,
            revision,
        } => {
            print_status(&AppsecControl::open(&state)?.cancel(run_id, revision)?)?;
        }
        AppsecCommand::Resume {
            state,
            run_id,
            task_id,
            revision,
            handoff,
        } => {
            print_status(
                &AppsecControl::open(&state)?.resume(run_id, revision, task_id, &handoff)?,
            )?;
        }
        AppsecCommand::Recover {
            state,
            run_id,
            task_id,
            revision,
        } => {
            let control = AppsecControl::open(&state)?;
            let mut runtime = nac_server::NacWorkerRuntime::new(
                &state,
                std::env::current_exe()?,
                nac_server::NativeResearchModel::default(),
            )?;
            print_status(&control.recover(run_id, revision, task_id, &mut runtime)?)?;
        }
        AppsecCommand::Report {
            state,
            run_id,
            output,
        } => {
            let campaign = AppsecControl::open(&state)?.status(run_id)?;
            std::fs::create_dir(&output)?;
            write_report(
                &output.join("report.json"),
                &serde_json::to_vec_pretty(&status_json(&campaign))?,
            )?;
            write_report(&output.join("report.md"), campaign.markdown().as_bytes())?;
        }
        AppsecCommand::ExperimentRead {
            state,
            run_id,
            experiment_id,
        } => {
            let campaign = AppsecControl::open(&state)?.status(run_id)?;
            let experiment = campaign
                .experiments
                .iter()
                .find(|experiment| experiment.id == experiment_id)
                .ok_or_else(|| anyhow::anyhow!("experiment unavailable"))?;
            println!("{}", serde_json::to_string_pretty(experiment)?);
        }
        AppsecCommand::ExperimentCancel {
            state,
            run_id,
            experiment_id,
        } => {
            let control = AppsecControl::open(&state)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&control.cancel_experiment(run_id, experiment_id)?)?
            );
        }
        AppsecCommand::ExperimentRecover {
            state,
            run_id,
            experiment_id,
        } => {
            let control = AppsecControl::open(&state)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&control.recover_experiment(run_id, experiment_id)?)?
            );
        }
        AppsecCommand::ExperimentReconcile { state, run_id } => {
            print_status(&AppsecControl::open(&state)?.reconcile_experiments(run_id)?)?;
        }
        AppsecCommand::ExperimentDemo { state, run_id } => {
            let control = AppsecControl::open(&state)?;
            loop {
                let campaign = control.reconcile_experiments(run_id)?;
                if campaign.occupied_targets() == 0
                    || campaign.experiments.iter().all(|experiment| {
                        experiment
                            .trials
                            .iter()
                            .all(|trial| !trial.holds_target() || trial.operator_recovery_required)
                    })
                {
                    print_status(&campaign)?;
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn watch(state: PathBuf, run_id: Id) -> anyhow::Result<()> {
    let control = AppsecControl::open(&state)?;
    let mut runtime = nac_server::NacWorkerRuntime::new(
        &state,
        std::env::current_exe()?,
        nac_server::NativeResearchModel::default(),
    )?;
    let mut last_error = None;
    let mut watchdog_states = std::collections::BTreeMap::new();
    loop {
        let campaign = match control.tick(run_id, &mut runtime).and_then(|campaign| {
            if campaign.experiments.iter().any(|experiment| {
                experiment
                    .trials
                    .iter()
                    .any(nac_appsec::ExperimentTrial::holds_target)
            }) {
                control.reconcile_experiments(run_id)
            } else {
                Ok(campaign)
            }
        }) {
            Ok(campaign) => {
                last_error = None;
                campaign
            }
            Err(error) => {
                let message = error.to_string();
                if last_error.as_ref() != Some(&message) {
                    eprintln!("Reconciliation remains uncertain: {message}");
                }
                last_error = Some(message);
                control.status(run_id)?
            }
        };
        for task in &campaign.tasks {
            for attempt in task
                .attempts
                .iter()
                .filter(|attempt| attempt.runtime_slot_held && !attempt.revoked)
            {
                let previous =
                    watchdog_states.insert(attempt.lease.attempt_id, attempt.watchdog_state);
                if previous == Some(attempt.watchdog_state) {
                    continue;
                }
                let notice = match attempt.watchdog_state {
                    nac_appsec::WatchdogState::Warning => {
                        "warning: meaningful progress is overdue; diagnosis requested"
                    }
                    nac_appsec::WatchdogState::SuspectedStall => {
                        "suspected stall: diagnostic grace elapsed; explicit recovery is available"
                    }
                    nac_appsec::WatchdogState::Healthy if previous.is_some() => {
                        "healthy: verified meaningful progress resumed"
                    }
                    nac_appsec::WatchdogState::Healthy => continue,
                };
                eprintln!(
                    "Watchdog run={} task={} attempt={}: {notice}",
                    campaign.id, task.id, attempt.lease.attempt_id
                );
            }
        }
        let occupied = campaign.occupied_attempts() > 0;
        let queued = campaign.tasks.iter().any(|task| {
            task.state == nac_appsec::ExecutionState::Queued
                && task.plan.dependencies.iter().all(|key| {
                    campaign.tasks.iter().any(|dependency| {
                        dependency.plan.key == *key
                            && dependency.state == nac_appsec::ExecutionState::Completed
                    })
                })
        });
        if !occupied && (!queued || campaign.dispatch_blocker.is_some() || campaign.cancelled) {
            print_status(&campaign)?;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    Ok(())
}

fn status_json(campaign: &Campaign) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "execution_state": campaign.state(),
        "security_assurance": "not_established",
        "campaign": campaign,
    })
}

fn print_status(campaign: &Campaign) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(&status_json(campaign))?);
    Ok(())
}

fn write_report(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn doctor_requires_both_paths_and_rejects_server_options() {
        for arguments in [
            vec!["nac-web", "appsec"],
            vec!["nac-web", "appsec", "doctor"],
            vec!["nac-web", "appsec", "doctor", "--config", "config.json"],
            vec!["nac-web", "appsec", "doctor", "--output", "new"],
            vec![
                "nac-web",
                "--port",
                "3211",
                "appsec",
                "doctor",
                "--config",
                "config.json",
                "--output",
                "new",
            ],
        ] {
            assert!(
                crate::Cli::try_parse_from(arguments).is_err(),
                "invalid doctor arguments must fail before dispatch"
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "nac-web",
                "appsec",
                "doctor",
                "--config",
                "config.json",
                "--output",
                "new"
            ])
            .is_ok(),
            "doctor accepts explicit input and output paths"
        );
    }
}
