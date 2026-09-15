use std::{path::PathBuf, process};

use clap::{Args, Subcommand};
use nac_server::{run_appsec_doctor, DoctorError};

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
    }
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
