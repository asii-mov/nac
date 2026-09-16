use crate::{
    controller::validate_lease,
    source::{git, safe_source_path},
    *,
};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRead {
    pub repository: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    pub source: SourceRef,
    pub text: String,
    pub progress: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInventory {
    pub repository: String,
    pub after: Option<String>,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFiles {
    pub repository: String,
    pub commit: String,
    pub files: Vec<String>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum InventoryReceipt {
    LegacyHash(String),
    Enumeration(InventoryEnumeration),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEnumeration {
    pub commit: String,
    pub listing_sha256: String,
    pub total_files: u64,
    pub from_start: bool,
    pub delivered: Vec<(u64, u64)>,
    pub mapped: bool,
}

impl InventoryReceipt {
    pub fn complete(&self) -> bool {
        matches!(self, Self::Enumeration(receipt) if receipt.from_start && (receipt.total_files == 0 || receipt.delivered == [(0, receipt.total_files)]))
    }

    pub fn mapped(&self) -> bool {
        self.complete() && matches!(self, Self::Enumeration(receipt) if receipt.mapped)
    }

    pub(crate) fn freeze(&mut self) {
        if let Self::Enumeration(receipt) = self {
            receipt.mapped = true;
        }
    }

    fn observe(
        &mut self,
        commit: &str,
        listing: &str,
        total: u64,
        range: (u64, u64),
        from_start: bool,
    ) -> Result<()> {
        if let Self::LegacyHash(previous) = self {
            ensure!(previous == listing, "pinned inventory identity changed");
            *self = Self::Enumeration(InventoryEnumeration {
                commit: commit.into(),
                listing_sha256: listing.into(),
                total_files: total,
                from_start: false,
                delivered: vec![],
                mapped: false,
            });
        }
        if let Self::Enumeration(receipt) = self {
            ensure!(
                receipt.commit == commit
                    && receipt.listing_sha256 == listing
                    && receipt.total_files == total,
                "pinned inventory identity changed"
            );
            receipt.from_start |= from_start;
            if range.0 < range.1 {
                receipt.delivered.push(range);
                receipt.delivered.sort_unstable();
                let mut merged: Vec<(u64, u64)> = vec![];
                for &(start, end) in &receipt.delivered {
                    if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                        last.1 = last.1.max(end);
                    } else {
                        merged.push((start, end));
                    }
                }
                receipt.delivered = merged;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    #[test]
    fn enumeration_never_combines_different_pinned_listing_identities() -> Result<()> {
        let mut receipt = InventoryReceipt::LegacyHash("listing-a".into());
        assert!(!receipt.complete());
        receipt.observe("commit-a", "listing-a", 4, (0, 2), true)?;
        let before = serde_json::to_value(&receipt)?;
        assert!(receipt
            .observe("commit-a", "listing-b", 4, (2, 4), false)
            .is_err());
        assert!(receipt
            .observe("commit-b", "listing-a", 4, (2, 4), false)
            .is_err());
        assert_eq!(serde_json::to_value(&receipt)?, before);
        receipt.observe("commit-a", "listing-a", 4, (2, 4), false)?;
        assert!(receipt.complete());
        assert!(!receipt.mapped());
        Ok(())
    }
}

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn list_source_files(
        &self,
        lease: &Lease,
        request: SourceInventory,
    ) -> Result<SourceFiles> {
        let mut campaign = self.repository.read(lease.run_id)?;
        validate_lease(&mut campaign, lease, self.clock.now_ms()?)?;
        ensure!(
            (1..=256).contains(&request.limit)
                && request.after.as_deref().is_none_or(safe_source_path),
            "inventory requires a safe cursor and a limit between one and 256"
        );
        let task = campaign
            .tasks
            .iter()
            .find(|task| task.id == lease.task_id)
            .context("missing task")?;
        let limit = task.plan.operation_limits.output_bytes;
        let repo = campaign
            .manifest
            .repositories
            .iter()
            .find(|repo| repo.identity == request.repository)
            .context("undeclared repository")?;
        let listing = git(
            &repo.checkout,
            &["ls-tree", "-r", "-z", "--full-tree", &repo.commit],
        )?;
        let mut paths: Vec<_> = listing
            .split(|byte| *byte == 0)
            .filter(|entry| {
                entry.starts_with(b"100644 blob ") || entry.starts_with(b"100755 blob ")
            })
            .filter_map(|entry| {
                entry
                    .iter()
                    .position(|byte| *byte == b'\t')
                    .and_then(|index| std::str::from_utf8(&entry[index + 1..]).ok())
            })
            .filter(|path| safe_source_path(path))
            .collect();
        paths.sort_unstable();
        let total = paths.len();
        let start = request
            .after
            .as_deref()
            .map_or(0, |after| paths.partition_point(|path| *path <= after));
        let paths = &paths[start..];
        let mut result = SourceFiles {
            repository: repo.identity.clone(),
            commit: repo.commit.clone(),
            files: Vec::new(),
            next_after: None,
        };
        for (index, path) in paths.iter().take(request.limit as usize).enumerate() {
            result.files.push((*path).to_string());
            result.next_after = (index + 1 < paths.len()).then(|| (*path).to_string());
            if serde_json::to_vec(&result)?.len() as u64 > limit {
                result.files.pop();
                ensure!(
                    !result.files.is_empty(),
                    "source inventory entry exceeds response bound"
                );
                result.next_after = result.files.last().cloned();
                break;
            }
        }
        ensure!(
            serde_json::to_vec(&result)?.len() as u64 <= limit,
            "source inventory exceeds response bound"
        );
        if campaign.workflow.is_some() {
            self.repository
                .update(lease.run_id, None, &mut |campaign, _| {
                    validate_lease(campaign, lease, self.clock.now_ms()?)?;
                    if let Some(workflow) = &mut campaign.workflow {
                        let listing_hash = hash(&listing);
                        workflow
                            .inventory
                            .entry(request.repository.clone())
                            .or_insert_with(|| InventoryReceipt::LegacyHash(listing_hash.clone()))
                            .observe(
                                &result.commit,
                                &listing_hash,
                                total.try_into()?,
                                (start.try_into()?, (start + result.files.len()).try_into()?),
                                request.after.is_none(),
                            )?;
                    }
                    Ok(())
                })?;
        }
        Ok(result)
    }

    pub fn read_source(&self, lease: &Lease, request: SourceRead) -> Result<SourceReceipt> {
        let mut campaign = self.repository.read(lease.run_id)?;
        validate_lease(&mut campaign, lease, self.clock.now_ms()?)?;
        let task = campaign
            .tasks
            .iter()
            .find(|task| task.id == lease.task_id)
            .context("missing task")?;
        let limit = task.plan.operation_limits.output_bytes;
        let repo = campaign
            .manifest
            .repositories
            .iter()
            .find(|repo| repo.identity == request.repository)
            .context("undeclared repository")?;
        ensure!(safe_source_path(&request.path), "unsafe source path");
        let object = format!("{}:{}", repo.commit, request.path);
        let started_ms = self.clock.now_ms()?;
        let started = std::time::Instant::now();
        let listing = git(
            &repo.checkout,
            &["ls-tree", "-z", &repo.commit, "--", &request.path],
        )?;
        ensure!(
            listing.starts_with(b"100644 blob ") || listing.starts_with(b"100755 blob "),
            "source must be a pinned regular file"
        );
        let bytes = git(&repo.checkout, &["show", &object])?;
        let text = std::str::from_utf8(&bytes)?;
        let lines: Vec<_> = text.lines().collect();
        ensure!(
            request.start_line > 0
                && request.end_line >= request.start_line
                && request.end_line as usize <= lines.len(),
            "invalid source range"
        );
        let source = SourceRef {
            repository: repo.identity.clone(),
            commit: repo.commit.clone(),
            path: request.path,
            start_line: request.start_line,
            end_line: request.end_line,
            content_sha256: hash(&bytes),
        };
        let ended_ms = self.clock.now_ms()?;
        let measured: u64 = started.elapsed().as_millis().try_into()?;
        let end = started_ms.saturating_add(measured).min(ended_ms);
        let progress = self.artifacts.write(&serde_json::to_vec(&serde_json::json!({"kind":"pinned_source", "repository":source.repository, "commit":source.commit, "path":source.path, "content_sha256":source.content_sha256}))?, limit)?;
        let receipt = SourceReceipt {
            source,
            text: lines[request.start_line as usize - 1..request.end_line as usize].join("\n"),
            progress,
        };
        ensure!(
            serde_json::to_vec(&receipt)?.len() as u64 <= limit,
            "source receipt exceeds output bound"
        );
        if campaign.workflow.is_some() && end >= started_ms {
            self.record_research_interval(lease, &receipt.source, started_ms, end)?;
        }
        Ok(receipt)
    }

    pub fn read_evidence_range(
        &self,
        lease: &Lease,
        artifact: &ArtifactRef,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let mut campaign = self.repository.read(lease.run_id)?;
        validate_lease(&mut campaign, lease, self.clock.now_ms()?)?;
        let task = campaign
            .tasks
            .iter()
            .find(|task| task.id == lease.task_id)
            .context("missing task")?;
        ensure!(
            campaign
                .accepted
                .iter()
                .any(|accepted| accepted.task_id == lease.task_id
                    && accepted.evidence.contains(artifact)),
            "artifact is not an accepted input for this task"
        );
        ensure!(
            length > 0 && length <= task.plan.operation_limits.output_bytes / 8,
            "artifact range exceeds response bound"
        );
        self.artifacts.read_range(artifact, offset, length)
    }
}
