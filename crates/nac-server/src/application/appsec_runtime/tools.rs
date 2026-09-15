use super::*;
use nac_appsec::{
    Candidate, Controller, EvidenceInput, Lease, Payload, SourceRead, SqliteRepository,
    StageResult, Submission,
};
use std::sync::{Arc, Mutex};

pub(crate) const TOOL_NAMES: [&str; 7] = [
    "list_source_files",
    "read_source",
    "search_source",
    "submit_candidate",
    "submit_stage_result",
    "record_blocker",
    "read_artifact_range",
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

impl ResearchTools {
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
