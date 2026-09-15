use crate::{
    controller::{locate, validate_lease},
    source::validate_source,
    *,
};
use anyhow::ensure;

impl<R: Repository, C: Clock> Controller<R, C> {
    pub fn submit(&self, lease: &Lease, key: &str, submission: Submission) -> Result<Accepted> {
        require_version(submission.schema_version)?;
        ensure!(
            !key.is_empty()
                && key.len() <= 128
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "idempotency key must be 1-128 ASCII letters, digits, underscores or hyphens"
        );
        let mut snapshot = self.repository.read(lease.run_id)?;
        validate_lease(&mut snapshot, lease, self.clock.now_ms()?)?;
        let (task, _) = locate(&mut snapshot, lease)?;
        let output_limit = task.plan.operation_limits.output_bytes;
        let payload_bytes = serde_json::to_vec(&submission.payload)?;
        let mut bytes: u64 = payload_bytes.len().try_into()?;
        for evidence in &submission.evidence {
            let length = match evidence {
                EvidenceInput::Upload { bytes } => bytes.len().try_into()?,
                EvidenceInput::Stored { artifact } => artifact.bytes,
            };
            bytes = bytes
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("output size overflow"))?;
        }
        ensure!(
            bytes <= output_limit,
            "submission exceeds per-response output limit"
        );
        match &submission.payload {
            Payload::Candidate { candidate } => {
                ensure!(
                    !candidate.claim.trim().is_empty(),
                    "candidate claim is required"
                );
                ensure!(
                    !submission.evidence.is_empty(),
                    "candidate requires evidence"
                );
                validate_source(&snapshot.manifest, &candidate.source)?;
            }
            Payload::StageResult { result } => match result {
                StageResult::Completed { scope } => {
                    ensure!(
                        scope == &task.plan.scope,
                        "completion must cover the declared task scope"
                    );
                    ensure!(
                        !submission.evidence.is_empty(),
                        "completion requires structured evidence, not final prose"
                    );
                }
                StageResult::Partial { reason }
                | StageResult::Blocked { reason }
                | StageResult::Failed { reason } => {
                    ensure!(
                        !reason.trim().is_empty(),
                        "unfinished scope requires a reason"
                    );
                }
            },
        }
        let evidence = submission
            .evidence
            .iter()
            .map(|input| match input {
                EvidenceInput::Upload { bytes } => Ok(ArtifactRef {
                    sha256: hash(bytes),
                    bytes: bytes.len().try_into()?,
                }),
                EvidenceInput::Stored { artifact } => {
                    self.artifacts.verify(artifact)?;
                    Ok(artifact.clone())
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let payload_hash = hash(&serde_json::to_vec(&(
            submission.schema_version,
            &submission.payload,
            &evidence,
        ))?);
        let mut accepted = None;
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                validate_lease(campaign, lease, now)?;
                if let Some(existing) = campaign
                    .accepted
                    .iter()
                    .find(|a| a.task_id == lease.task_id && a.key == key)
                {
                    ensure!(
                        existing.payload_hash == payload_hash,
                        "idempotency conflict: same key has different content"
                    );
                    accepted = Some(existing.clone());
                    return Ok(());
                }
                for pending in campaign
                    .pending_submissions
                    .iter()
                    .filter(|p| p.task_id == lease.task_id && p.key == key)
                {
                    ensure!(
                        pending.payload_hash == payload_hash,
                        "idempotency conflict: reserved key has different content"
                    );
                }
                if campaign
                    .pending_submissions
                    .iter()
                    .any(|p| p.attempt_id == lease.attempt_id && p.key == key)
                {
                    return Ok(());
                }
                let (task, index) = locate(campaign, lease)?;
                ensure!(
                    task.state == ExecutionState::Running,
                    "task no longer accepts new submissions"
                );
                let attempt = &mut task.attempts[index];
                let output = attempt
                    .reserved_submission_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| anyhow::anyhow!("output size overflow"))?;
                attempt.reserved_submission_bytes = output;
                campaign.pending_submissions.push(ReservedSubmission {
                    task_id: lease.task_id,
                    attempt_id: lease.attempt_id,
                    key: key.to_string(),
                    payload_hash: payload_hash.clone(),
                });
                campaign.updated_ms = now;
                Ok(())
            })?;
        if let Some(record) = accepted {
            for artifact in &record.evidence {
                self.artifacts.verify(artifact)?;
            }
            return Ok(record);
        }
        for input in &submission.evidence {
            match input {
                EvidenceInput::Upload { bytes } => {
                    self.artifacts.write(bytes, output_limit)?;
                }
                EvidenceInput::Stored { artifact } => self.artifacts.verify(artifact)?,
            }
        }
        self.repository
            .update(lease.run_id, None, &mut |campaign, _| {
                let now = self.clock.now_ms()?;
                validate_lease(campaign, lease, now)?;
                for artifact in &evidence {
                    self.artifacts.verify(artifact)?;
                }
                if let Some(existing) = campaign
                    .accepted
                    .iter()
                    .find(|a| a.task_id == lease.task_id && a.key == key)
                {
                    ensure!(
                        existing.payload_hash == payload_hash,
                        "idempotency conflict: same key has different content"
                    );
                    accepted = Some(existing.clone());
                    return Ok(());
                }
                let (task, _) = locate(campaign, lease)?;
                ensure!(
                    task.state == ExecutionState::Running,
                    "task no longer accepts new submissions"
                );
                if let Payload::StageResult { result } = &submission.payload {
                    let (state, reason) = match result {
                        StageResult::Completed { .. } => (ExecutionState::Completed, None),
                        StageResult::Partial { reason } => {
                            (ExecutionState::Partial, Some(reason.clone()))
                        }
                        StageResult::Blocked { reason } => {
                            (ExecutionState::Blocked, Some(reason.clone()))
                        }
                        StageResult::Failed { reason } => {
                            (ExecutionState::Failed, Some(reason.clone()))
                        }
                    };
                    task.state = state;
                    task.reason = reason;
                    task.attempts
                        .last_mut()
                        .ok_or_else(|| anyhow::anyhow!("missing attempt"))?
                        .stop_intent = Some(StopIntent::AcceptedResultCleanup);
                }
                if let Payload::Candidate { candidate } = &submission.payload {
                    let fingerprint = &candidate.source.content_sha256;
                    if !task.progress_fingerprints.contains(fingerprint) {
                        task.progress_fingerprints.push(fingerprint.clone());
                        let current = task
                            .attempts
                            .last_mut()
                            .ok_or_else(|| anyhow::anyhow!("missing attempt"))?;
                        current.last_progress_ms = now;
                        current.made_meaningful_progress = true;
                        current.last_liveness_ms = now;
                        current.watchdog_state = WatchdogState::Healthy;
                        current.diagnostic_ms = None;
                        current.diagnostic_evidence = None;
                        task.failed_recoveries = 0;
                    }
                }
                let candidate = matches!(submission.payload, Payload::Candidate { .. });
                let record = Accepted {
                    id: Id::new(),
                    task_id: lease.task_id,
                    attempt_id: lease.attempt_id,
                    key: key.to_string(),
                    payload_hash: payload_hash.clone(),
                    accepted_ms: now,
                    payload: submission.payload.clone(),
                    evidence: evidence.clone(),
                    evidence_state: candidate.then_some(EvidenceState::Candidate),
                    remediation_state: candidate.then_some(RemediationState::NotStarted),
                };
                campaign.accepted.push(record.clone());
                campaign
                    .pending_submissions
                    .retain(|pending| pending.task_id != lease.task_id || pending.key != key);
                campaign.updated_ms = now;
                accepted = Some(record);
                Ok(())
            })?;
        accepted.ok_or_else(|| anyhow::anyhow!("repository did not accept the submission"))
    }
}
