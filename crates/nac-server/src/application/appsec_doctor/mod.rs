mod config;
mod report;

#[cfg(test)]
mod tests;

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use config::DoctorConfig;
use report::DoctorReport;

#[derive(Debug)]
pub enum DoctorError {
    InvalidConfig(String),
    Io(io::Error),
}

impl std::fmt::Display for DoctorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "{reason}"),
            Self::Io(error) => write!(formatter, "doctor I/O failure: {:?}; a newly created output directory may contain partial diagnostic files; use a new directory to retry", error.kind()),
        }
    }
}

impl std::error::Error for DoctorError {}

impl From<io::Error> for DoctorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn run_appsec_doctor(config: &Path, output: &Path) -> Result<bool, DoctorError> {
    let requested = DoctorConfig::parse(&fs::read(config)?)?;
    let path = std::env::var_os("PATH");
    let report = DoctorReport::inspect(requested, config, path.as_deref());
    let json = serde_json::to_string_pretty(&report).map_err(io::Error::other)?;
    let markdown = report.markdown(&json);
    fs::create_dir(output)?;
    write_new(&output.join("doctor.json"), json.as_bytes())?;
    write_new(&output.join("doctor.md"), markdown.as_bytes())?;
    Ok(report.ready)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn executable_available(name: &str, path: Option<&OsStr>) -> bool {
    path.is_some_and(|path| {
        std::env::split_paths(path).any(|directory| {
            let candidate = directory.join(name);
            let Ok(metadata) = fs::metadata(candidate) else {
                return false;
            };
            if !metadata.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                false
            }
        })
    })
}
