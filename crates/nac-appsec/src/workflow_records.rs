use crate::{Id, SourceRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BASELINE_CLASSES: [&str; 6] = [
    "authentication",
    "authorization",
    "injection",
    "data_exposure",
    "resource_exhaustion",
    "business_logic",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRole {
    Recon,
    Discovery,
    Validation,
    Synthesis,
}

impl ResearchRole {
    pub fn stage(self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Discovery => "discovery",
            Self::Validation => "validation",
            Self::Synthesis => "synthesis",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Area {
    pub key: String,
    pub description: String,
    pub sources: Vec<SourceRef>,
    pub trust_boundaries: Vec<String>,
    pub unknowns: Vec<String>,
    pub applicability: Vec<Applicability>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub attack_class: String,
    pub proposed_exclusion: bool,
    pub reason: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub id: String,
    pub area: String,
    pub attack_class: String,
    pub scenario_sha256: String,
    pub baseline: bool,
    pub family: Option<String>,
    pub task: Id,
    pub round: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchJob {
    pub role: ResearchRole,
    pub parent: Option<Id>,
    pub purpose: String,
    pub round: u32,
    pub cell: Option<String>,
    pub candidate: Option<Id>,
    pub input: serde_json::Value,
    pub input_sha256: String,
    pub effective_inputs: BTreeMap<Id, EffectiveInputs>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveInputs {
    pub model: String,
    pub backend: String,
    pub reasoning: Option<String>,
    pub runtime: String,
    pub extractor: String,
    pub prompt_sha256: String,
    pub context_sha256: String,
    pub session_id: String,
    pub thread_name: String,
    pub dispatch_id: String,
    pub action_sha256: String,
    pub messages_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyStatus {
    Exploring,
    Blocked,
    Exhausted,
    Supported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approach {
    pub mechanism: SourceRef,
    pub attack_class: String,
    pub idea: String,
    pub status: FamilyStatus,
    pub rationale: String,
    pub evidence: Vec<SourceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub id: String,
    pub history: Vec<Approach>,
    pub tasks: Vec<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Followup {
    pub area: String,
    pub attack_class: String,
    pub family: String,
    pub rationale: String,
    pub evidence: Vec<SourceRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    Supported,
    Disproved,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validation {
    pub outcome: ValidationOutcome,
    pub prerequisites: String,
    pub reachability: String,
    pub security_violation: String,
    pub sources: Vec<SourceRef>,
    pub counterevidence: Vec<SourceRef>,
    pub unknowns: Vec<String>,
    pub next_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub experiments: Vec<Id>,
}

impl Validation {
    pub fn is_resolved(&self) -> bool {
        self.outcome != ValidationOutcome::Inconclusive && self.unknowns.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Synthesis {
    pub assumptions: Vec<String>,
    pub counterevidence: Vec<SourceRef>,
    pub gaps: Vec<String>,
    pub next: Vec<Followup>,
    pub finish: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQuestion {
    pub key: String,
    pub question: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceResolution {
    pub key: String,
    pub answer: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowAction {
    AskSource {
        question: SourceQuestion,
    },
    ResolveSource {
        resolution: SourceResolution,
    },
    Map {
        areas: Vec<Area>,
        unknowns: Vec<String>,
    },
    Approach {
        approach: Approach,
    },
    Followup {
        request: Followup,
    },
    Validate {
        validation: Validation,
    },
    Synthesize {
        synthesis: Synthesis,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchEffort {
    pub intervals: Vec<(u64, u64)>,
    pub source_fingerprints: Vec<String>,
}

impl ResearchEffort {
    pub fn credited_ms(&self) -> u64 {
        self.intervals.iter().map(|(start, end)| end - start).sum()
    }

    pub(crate) fn record(&mut self, fingerprint: String, start: u64, end: u64) {
        if self.source_fingerprints.contains(&fingerprint) {
            return;
        }
        self.source_fingerprints.push(fingerprint);
        if end <= start {
            return;
        }
        self.intervals.push((start, end));
        self.intervals.sort_unstable();
        let mut merged: Vec<(u64, u64)> = vec![];
        for &(start, end) in &self.intervals {
            if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.intervals = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::ResearchEffort;

    #[test]
    fn source_effort_is_union_not_concurrency_or_duplicate_credit() {
        let mut effort = ResearchEffort::default();
        effort.record("source-a".into(), 100, 200);
        effort.record("source-b".into(), 150, 250);
        assert_eq!(effort.credited_ms(), 150);
        effort.record("source-a".into(), 250, 21_600_250);
        effort.record("source-c".into(), 21_600_250, 21_600_250);
        assert_eq!(effort.credited_ms(), 150);
        effort.record("source-d".into(), 21_600_250, 21_600_300);
        assert_eq!(effort.credited_ms(), 200);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub root: Id,
    pub scenario_sha256: String,
    pub areas: Vec<Area>,
    pub unknowns: Vec<String>,
    pub cells: Vec<Cell>,
    pub inventory: BTreeMap<String, crate::InventoryReceipt>,
    pub jobs: BTreeMap<Id, ResearchJob>,
    pub families: BTreeMap<String, Family>,
    pub candidate_validators: BTreeMap<Id, Id>,
    pub candidate_fingerprints: BTreeMap<String, Id>,
    pub rounds: Vec<Synthesis>,
    pub effort: ResearchEffort,
    pub complete: bool,
}
