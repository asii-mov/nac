#![allow(
    clippy::unwrap_used,
    reason = "the checked-in skill fixture path is a build-time invariant"
)]

use anyhow::{ensure, Result};
use nac_appsec::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn brief() -> ResearchBrief {
    ResearchBrief {
        schema_version: 1,
        assurance: Assurance::OpenEnded,
        source_root: "main/".into(),
        attacker_model: "unauthenticated remote attacker".into(),
        deployment_profile: "pinned local fixture".into(),
        impact_goal: "unauthorized read".into(),
        success_property: "attacker receives protected fixture bytes".into(),
        minimum_active_research_ms: Some(21600000),
        max_investigative_agents: 4,
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/appsec")
        .canonicalize()
        .unwrap()
}

#[test]
fn typed_assurance_and_exact_brief_hashes() -> Result<()> {
    let open = brief().render()?;
    assert!(open.text.contains("may or may not contain a vulnerability"));
    assert!(!open.text.contains("has established that at least one"));
    assert!(open
        .text
        .contains("21600000 milliseconds of cumulative active research"));
    assert!(open.text.contains("not a total runtime ceiling"));
    assert_eq!(
        open.sha256,
        format!("{:x}", Sha256::digest(open.text.as_bytes()))
    );
    let mut known = brief();
    known.assurance = Assurance::KnownSolvable {
        evaluator_approval: "operator-approved-task-v1".into(),
    };
    let known = known.render()?;
    assert!(known.text.contains(
        "The evaluator has established that at least one qualifying vulnerability exists"
    ));
    assert_ne!(known.sha256, open.sha256);
    let mut invalid = brief();
    invalid.assurance = Assurance::KnownSolvable {
        evaluator_approval: String::new(),
    };
    assert!(invalid.render().is_err());
    invalid = brief();
    invalid.deployment_profile.clear();
    assert!(invalid.render().is_err());
    Ok(())
}

#[test]
fn frozen_selection_includes_transitive_reference_and_only_selected_stage() -> Result<()> {
    let frozen = FrozenResearch::resolve(
        &root(),
        brief(),
        BTreeMap::from([("task".into(), "discovery".into())]),
    )?;
    let prepared = frozen.prepare("task")?;
    assert_eq!(
        prepared
            .skills
            .iter()
            .map(|skill| skill.id.as_str())
            .collect::<Vec<_>>(),
        vec!["evidence", "discovery"]
    );
    assert!(prepared.prompt.contains("Controller receipt rules"));
    assert!(prepared.prompt.contains("Source discovery 1.0.0"));
    assert!(!prepared
        .prompt
        .contains("Adversarial source validation 1.0.0"));
    assert_eq!(
        prepared.prompt_sha256,
        format!("{:x}", Sha256::digest(prepared.prompt.as_bytes()))
    );
    assert!(prepared
        .skills
        .iter()
        .all(|skill| skill.reason.contains("discovery")));
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let to = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

#[test]
fn drift_missing_helper_incompatible_lock_and_symlinks_fail_before_dispatch() -> Result<()> {
    let directory = std::env::temp_dir().join(format!("nac-skills-{}", uuid::Uuid::new_v4()));
    copy_tree(&root(), &directory)?;
    let resolve = || {
        FrozenResearch::resolve(
            &directory,
            brief(),
            BTreeMap::from([("task".into(), "discovery".into())]),
        )
    };
    let frozen = resolve()?;
    let resource = directory.join("skills/evidence/references/receipt.md");
    let bytes = std::fs::read(&resource)?;
    std::fs::write(&resource, "changed helper")?;
    ensure!(
        resolve().is_err() && frozen.prepare("task").is_err(),
        "active campaign absorbed skill drift"
    );
    std::fs::remove_file(&resource)?;
    ensure!(
        resolve().is_err(),
        "missing transitive resource was accepted"
    );
    std::os::unix::fs::symlink(
        root().join("skills/evidence/references/receipt.md"),
        &resource,
    )?;
    ensure!(resolve().is_err(), "symlink resource was accepted");
    std::fs::remove_file(&resource)?;
    std::fs::write(&resource, bytes)?;
    let path = directory.join("skills.lock.json");
    let mut lock: SkillLock = serde_json::from_slice(&std::fs::read(&path)?)?;
    lock.compatibility = "unreviewed-runtime-v2".into();
    std::fs::write(&path, serde_json::to_vec(&lock)?)?;
    ensure!(resolve().is_err(), "incompatible lock was accepted");
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
