use crate::{source::validate_source, *};
use anyhow::ensure;
use std::collections::BTreeMap;

pub(crate) fn unresolved(campaign: &Campaign) -> BTreeMap<&str, &SourceQuestion> {
    let mut questions = BTreeMap::new();
    for record in &campaign.accepted {
        match &record.payload {
            Payload::Workflow {
                action: WorkflowAction::AskSource { question },
                ..
            } => {
                questions.insert(question.key.as_str(), question);
            }
            Payload::Workflow {
                action: WorkflowAction::ResolveSource { resolution },
                ..
            } => {
                questions.remove(resolution.key.as_str());
            }
            _ => {}
        }
    }
    questions
}

pub(crate) fn admit(campaign: &Campaign, action: &WorkflowAction) -> Result<()> {
    let (key, text, sources) = match action {
        WorkflowAction::AskSource { question } => {
            ensure!(!campaign.accepted.iter().any(|record| matches!(&record.payload, Payload::Workflow { action: WorkflowAction::AskSource { question: previous }, .. } if previous.key == question.key)), "source question key already exists");
            (&question.key, &question.question, &question.sources)
        }
        WorkflowAction::ResolveSource { resolution } => {
            ensure!(unresolved(campaign).contains_key(resolution.key.as_str()), "source question is unknown or already resolved; fixed input blockers cannot be resolved here");
            (&resolution.key, &resolution.answer, &resolution.sources)
        }
        _ => anyhow::bail!("not a source-question action"),
    };
    ensure!(
        !key.trim().is_empty() && key.len() <= 128,
        "source question key must be nonempty and at most 128 bytes"
    );
    ensure!(
        !text.trim().is_empty() && text.len() <= 4096,
        "source question or answer must be nonempty and bounded"
    );
    ensure!(
        !sources.is_empty() && sources.len() <= 64,
        "source questions and answers need bounded pinned citations"
    );
    for source in sources {
        validate_source(&campaign.manifest, source)?;
    }
    Ok(())
}
