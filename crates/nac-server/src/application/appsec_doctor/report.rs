use std::{ffi::OsStr, path::Path};

use serde::Serialize;

use super::{config::DoctorConfig, executable_available};

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Verified,
    Unsupported,
    NotTested,
}

#[derive(Serialize)]
pub(super) struct Check {
    pub id: String,
    pub status: Status,
    pub required: bool,
    pub scope: &'static str,
    pub reason: &'static str,
}

#[derive(Serialize)]
struct Provenance {
    product_version: &'static str,
    build_id: &'static str,
    track: &'static str,
    source_revision: &'static str,
}

#[derive(Serialize)]
pub(super) struct DoctorReport {
    schema_version: u32,
    kind: &'static str,
    offline: bool,
    model_execution: bool,
    diagnostic_only: bool,
    limits_enforced: bool,
    provenance: Provenance,
    pub requested: DoctorConfig,
    pub checks: Vec<Check>,
    pub ready: bool,
}

impl DoctorReport {
    pub(super) fn inspect(requested: DoctorConfig, config: &Path, path: Option<&OsStr>) -> Self {
        let mut checks = vec![Check {
            id: "doctor_config".into(),
            status: Status::Verified,
            required: true,
            scope: "parsing",
            reason: "Strict doctor schema, subscription backend and consistent finite requested limits parsed. Requested active_agents includes the root and all investigative agents. This does not configure or enforce runtime limits.",
        }];
        let (status, reason) = match &requested.evaluation_source {
            None => (
                Status::NotTested,
                "No evaluation source requested; no source contents or answer keys read.",
            ),
            Some(source) => {
                let source = config.parent().unwrap_or(Path::new(".")).join(source);
                if source.is_dir() {
                    (Status::Verified, "Requested directory exists relative to the config file. Contents, readability, provenance and evaluator suitability were not tested.")
                } else {
                    (Status::NotTested, "Requested evaluation source is missing, inaccessible or not a directory. No contents read.")
                }
            }
        };
        checks.push(Check {
            id: "evaluation_source".into(),
            status,
            required: requested.evaluation_source.is_some(),
            scope: "path_availability",
            reason,
        });
        for tool in &requested.tools {
            let available = executable_available(tool, path);
            checks.push(Check {
                id: format!("tool:{tool}"),
                status: if available { Status::Verified } else { Status::NotTested },
                required: true,
                scope: "executable_availability",
                reason: if available {
                    "A regular file with executable mode bits was found on PATH. It was not launched; version, effective permissions and campaign suitability were not tested."
                } else {
                    "No regular file with executable mode bits found on PATH, or platform availability check unsupported. No executable launched."
                },
            });
        }
        for (id, status, scope, reason) in [
            ("controller_mcp_binding", Status::Unsupported, "runtime_tool_binding", "Direct primaries and resume do not bind controller MCP tools."),
            ("task_tree_budget", Status::Unsupported, "runtime_budget", "No shared full-task-tree budget, admission and cancellation contract."),
            ("hard_admission", Status::Unsupported, "runtime_admission", "No controller hard-admission implementation hook for these requested limits."),
            ("source_only_containment", Status::Unsupported, "runtime_containment", "Effective source-only containment has not been proved."),
            ("skills_lock", Status::Unsupported, "runtime_skills", "Skills lock is not implemented."),
            ("evaluation_equivalence", Status::NotTested, "evaluation", "Original evaluation equivalence was not tested; no evaluator launched or external answer key read."),
            ("model_execution", Status::NotTested, "provider_execution", "Offline doctor does not execute a model or validate subscription authentication or model availability."),
            ("skill_load", Status::NotTested, "runtime_skills", "Actual skill loading was not tested."),
            ("provider_generation_bound", Status::NotTested, "provider_limits", "Provider generation bounds were not tested. Context-window metadata is not a generation hard cap."),
        ] {
            checks.push(Check { id: id.into(), status, required: true, scope, reason });
        }
        let identity = crate::build_identity::current();
        let ready = checks
            .iter()
            .all(|check| !check.required || check.status == Status::Verified);
        Self {
            schema_version: 1,
            kind: "appsec_doctor_diagnostic",
            offline: true,
            model_execution: false,
            diagnostic_only: true,
            limits_enforced: false,
            provenance: Provenance {
                product_version: identity.product_version,
                build_id: identity.build_id,
                track: identity.track,
                source_revision: identity.source_revision,
            },
            requested,
            checks,
            ready,
        }
    }

    pub(super) fn markdown(&self, json: &str) -> String {
        let mut markdown = format!(
            "# Appsec doctor\n\nReadiness: {}. Offline diagnostic only; no model execution.\n\nRequested limits are not proof of enforcement. This diagnostic does not implement campaigns or prove runtime or security controls. It is not canonical security state or a campaign manifest.\n\n## Checks\n\n| Check | Status | Required | Scope | Reason |\n| --- | --- | --- | --- | --- |\n",
            if self.ready { "ready" } else { "blocked" }
        );
        for check in &self.checks {
            let status = match check.status {
                Status::Verified => "verified",
                Status::Unsupported => "unsupported",
                Status::NotTested => "not_tested",
            };
            markdown.push_str(&format!(
                "| {} | {status} | {} | {} | {} |\n",
                check.id, check.required, check.scope, check.reason
            ));
        }
        let escaped = json
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        markdown.push_str(&format!("\n## Exact diagnostic JSON\n\nIncludes build provenance and effective requested model, settings and limits. No credentials or headers are loaded.\n\n<pre>\n{escaped}\n</pre>\n"));
        markdown
    }
}
