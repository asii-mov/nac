use std::{path::PathBuf, process};

use clap::{Args, Subcommand};
use nac_appsec::{Campaign, Id, Manifest};
use nac_server::{run_appsec_doctor, AppsecControl, DoctorError};

#[derive(Args)]
pub(super) struct AppsecCli {
    #[command(subcommand)]
    command: AppsecCommand,
}

#[derive(Subcommand)]
enum AppsecCommand {
    /// Write an offline JSON and Markdown prerequisite diagnostic; never execute a model
    Doctor {
        #[arg(long, value_name = "JSON")]
        config: PathBuf,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        output: PathBuf,
    },
    /// Persist a pinned campaign; live dispatch remains explicitly unsupported
    Run {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    /// Inspect canonical controller state and verified evidence
    Status {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
    },
    /// Revoke submission rights; live runtime slots still require reconciliation
    Cancel {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        run_id: Id,
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
}

pub(super) fn run(cli: AppsecCli) -> anyhow::Result<()> {
    match cli.command {
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
        AppsecCommand::Run { manifest, state } => {
            let manifest: Manifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
            let campaign = AppsecControl::open(&state)?.run(manifest)?;
            print_status(&campaign)?;
            eprintln!("Campaign persisted; live dispatch unsupported. No model executed.");
            process::exit(3);
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
