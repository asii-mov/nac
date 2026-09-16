use super::*;
use nac_appsec::{
    Candidate, Controller, EvidenceInput, Lease, Payload, SourceRead, SqliteRepository,
    StageResult, Submission,
};
use std::sync::{Arc, Mutex};

pub(crate) const TOOL_NAMES: [&str; 10] = [
    "list_source_files",
    "read_source",
    "search_source",
    "submit_candidate",
    "submit_stage_result",
    "record_blocker",
    "read_artifact_range",
    "query_work",
    "submit_workflow",
    "read_work_record",
];

#[derive(Clone)]
pub(crate) struct ResearchTools {
    controller: Arc<Controller<SqliteRepository>>,
    lease: Lease,
    pub progress: Arc<Mutex<Option<ArtifactRef>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    source: SourceRead,
    literal: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateInput {
    key: String,
    candidate: Candidate,
    evidence: Vec<EvidenceInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageInput {
    key: String,
    result: StageResult,
    evidence: Vec<EvidenceInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockerInput {
    key: String,
    reason: String,
    evidence: Vec<EvidenceInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRange {
    artifact: ArtifactRef,
    offset: u64,
    length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkQuery {
    offset: usize,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRead {
    record_id: Id,
    offset: usize,
    length: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowInput {
    key: String,
    revision: u64,
    action: nac_appsec::WorkflowAction,
    evidence: Vec<EvidenceInput>,
}

impl ResearchTools {
    pub fn record_loaded(&self, proof: &LoadedWorkerInputs) -> Result<()> {
        use sha2::{Digest, Sha256};
        let campaign = self.controller.status(self.lease.run_id)?;
        if let Some(workflow) = campaign.workflow {
            let job = workflow
                .jobs
                .get(&self.lease.task_id)
                .context("missing workflow job")?;
            let mut executable = std::fs::File::open(std::env::current_exe()?)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                let length = std::io::Read::read(&mut executable, &mut buffer)?;
                if length == 0 {
                    break;
                }
                hasher.update(&buffer[..length]);
            }
            let binary_hash = format!("{:x}", hasher.finalize());
            self.controller.record_effective_inputs(
                &self.lease,
                nac_appsec::EffectiveInputs {
                    model: proof.model.clone(),
                    backend: proof.backend.clone(),
                    reasoning: proof.reasoning.clone(),
                    runtime: format!(
                        "nac-server/{} executable-sha256:{binary_hash}",
                        env!("CARGO_PKG_VERSION")
                    ),
                    extractor: format!("nac-appsec/pinned-git-v1 executable-sha256:{binary_hash}"),
                    prompt_sha256: proof.prompt_sha256.clone(),
                    context_sha256: job.input_sha256.clone(),
                    session_id: proof.session_id.clone(),
                    thread_name: proof.thread_name.clone(),
                    dispatch_id: proof.dispatch_id.clone(),
                    action_sha256: proof.action_sha256.clone(),
                    messages_sha256: proof.messages_sha256.clone(),
                },
            )?;
        }
        Ok(())
    }

    pub fn new(state: &Path, lease: Lease) -> Result<Self> {
        Ok(Self {
            controller: Arc::new(Controller::new(
                SqliteRepository::open(state, 4)?,
                ArtifactStore::open(state)?,
                SystemClock,
            )),
            lease,
            progress: Arc::default(),
        })
    }

    pub fn call(&self, name: &str, arguments: serde_json::Value) -> Result<serde_json::Value> {
        let submission = match name {
            "read_work_record" => {
                let request: WorkRead = serde_json::from_value(arguments)?;
                return self.controller.read_work_record(
                    &self.lease,
                    request.record_id,
                    request.offset,
                    request.length,
                );
            }
            "query_work" => {
                let query: WorkQuery = serde_json::from_value(arguments)?;
                return self
                    .controller
                    .query_work(&self.lease, query.offset, query.limit);
            }
            "submit_workflow" => {
                let input: WorkflowInput = serde_json::from_value(arguments)?;
                (
                    input.key,
                    Payload::Workflow {
                        revision: input.revision,
                        action: input.action,
                    },
                    input.evidence,
                )
            }
            "list_source_files" => {
                return Ok(serde_json::to_value(self.controller.list_source_files(
                    &self.lease,
                    serde_json::from_value(arguments)?,
                )?)?)
            }
            "read_source" => {
                let receipt = self
                    .controller
                    .read_source(&self.lease, serde_json::from_value(arguments)?)?;
                *self
                    .progress
                    .lock()
                    .map_err(|_| anyhow::anyhow!("progress lock poisoned"))? =
                    Some(receipt.progress.clone());
                return Ok(serde_json::to_value(receipt)?);
            }
            "search_source" => {
                let search: Search = serde_json::from_value(arguments)?;
                ensure!(
                    !search.literal.is_empty() && search.literal.len() <= 1024,
                    "search needs a bounded literal"
                );
                let receipt = self.controller.read_source(&self.lease, search.source)?;
                *self
                    .progress
                    .lock()
                    .map_err(|_| anyhow::anyhow!("progress lock poisoned"))? =
                    Some(receipt.progress.clone());
                let matches: Vec<_> = receipt.text.lines().enumerate().filter(|(_, line)| line.contains(&search.literal)).map(|(index, line)| serde_json::json!({"line": index + receipt.source.start_line as usize, "text": line})).collect();
                return Ok(
                    serde_json::json!({"source": receipt.source, "matches":matches, "progress":receipt.progress}),
                );
            }
            "read_artifact_range" => {
                let input: ArtifactRange = serde_json::from_value(arguments)?;
                return Ok(serde_json::to_value(self.controller.read_evidence_range(
                    &self.lease,
                    &input.artifact,
                    input.offset,
                    input.length,
                )?)?);
            }
            "submit_candidate" => {
                let input: CandidateInput = serde_json::from_value(arguments)?;
                (
                    input.key,
                    Payload::Candidate {
                        candidate: input.candidate,
                    },
                    input.evidence,
                )
            }
            "submit_stage_result" => {
                let input: StageInput = serde_json::from_value(arguments)?;
                (
                    input.key,
                    Payload::StageResult {
                        result: input.result,
                    },
                    input.evidence,
                )
            }
            "record_blocker" => {
                let input: BlockerInput = serde_json::from_value(arguments)?;
                (
                    input.key,
                    Payload::StageResult {
                        result: StageResult::Blocked {
                            reason: input.reason,
                        },
                    },
                    input.evidence,
                )
            }
            _ => bail!("tool is not in the source-only profile"),
        };
        Ok(serde_json::to_value(self.controller.submit(
            &self.lease,
            &submission.0,
            Submission {
                schema_version: 1,
                payload: submission.1,
                evidence: submission.2,
            },
        )?)?)
    }
}
