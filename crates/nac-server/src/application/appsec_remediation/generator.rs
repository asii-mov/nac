//! `PatchGenerator` adapter for the Go authorization remediation pilot.
//!
//! [`RemediationPatchGenerator`] implements `nac_appsec::PatchGenerator` for
//! `RemediationPhase::GeneratePatch` plans. Per turn it:
//!
//! 1. Exports the frozen `SourcePackage` blobs (pinned Git blobs identified by
//!    hash, never a live checkout) into an owner-only, verified cache
//!    directory, then reads the exact bytes back.
//! 2. Materializes a `nac_core::controlled_coding::ControlledCodingFacade`
//!    from those exact bytes. Facade construction is the only confinement
//!    gate: a missing or empty backend/mount identity fails launch outright
//!    (see `ControlledCodingFacade::materialize`), and this adapter never
//!    substitutes local execution when that happens.
//! 3. Drives the coding model against exactly the facade-backed tool surface
//!    (read / search / replace / format / one bounded check) through a
//!    [`PatchGeneratorDriver`]. The production driver runs the model through
//!    the existing controlled-managed-worker path; nothing else is reachable
//!    from the model: no artifact browser, validator records, evaluator
//!    registry, network tool, or delegation tool.
//! 4. Captures the canonical exact-preimage replacement set via
//!    `facade.capture()`, renders the canonical unified diff through the
//!    core's own `nac_appsec::canonical_replacement_diff` projection, and
//!    returns a `PatchGeneratorSubmission` carrying the facade authority
//!    receipt and closed diagnostics only.
//!
//! On `desired.stop` the adapter never touches disk (each turn's workspace is
//! local to that turn's own call and is already gone by the time control
//! returns); it just reports the settled cleanup receipt the core's reducer
//! expects, whose workspace hash is the frozen source package manifest hash.

#![allow(
    dead_code,
    reason = "the generator adapter and its production controlled-managed-worker \
    driver are composed by a follow-up CLI/HTTP wiring task; this module is \
    exercised directly by generator_tests.rs until that lands"
)]

use anyhow::{ensure, Context, Result};
use nac_appsec::{
    canonical_replacement_diff, ArtifactStore, CleanupReceipt, EffectFence, FileReplacement, Id,
    PatchGenerator, PatchGeneratorSubmission, PublicFinding, RemediationAuthorityReceipt,
    RemediationDesiredEffect, RemediationEffectOutput, RemediationEffectPlan, RemediationLimits,
    RepositoryInput, SourcePackage,
};
use nac_core::controlled_coding::{
    ConfinedCodingBackend, ControlledCodingCapture, ControlledCodingFacade, ControlledCodingLimits,
    ControlledCodingPolicy, ControlledGoCheck, ControlledSourceFile,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// The fixed pilot check: `go vet ./...` under the materialized workspace.
/// Committed here (rather than threaded through the plan) because it, like
/// the rest of the confined tool policy, is part of the frozen generator
/// worker identity the core compares by hash, not per-run input.
const GO_CHECK_ARGS: [&str; 2] = ["vet", "./..."];
const MAX_READ_BYTES: usize = 4 * 1024 * 1024;

/// Drives the coding model against a facade-backed tool surface until it
/// stops. Implementations must not expose any capability beyond `tools`.
pub(crate) trait PatchGeneratorDriver {
    fn drive(&mut self, tools: GeneratorTools, prompt: String, action: String) -> Result<()>;
}

pub(crate) struct RemediationPatchGenerator<D: PatchGeneratorDriver> {
    repositories: Vec<RepositoryInput>,
    packages_root: PathBuf,
    workspace_root: PathBuf,
    artifacts: ArtifactStore,
    backend: Arc<dyn ConfinedCodingBackend>,
    driver: D,
}

impl<D: PatchGeneratorDriver> RemediationPatchGenerator<D> {
    /// `state` is the same durable state directory the campaign's
    /// `ArtifactStore`/`SqliteRepository` are opened against, so replacement
    /// and diff artifacts land where the core reducer can verify them.
    pub(crate) fn new(
        state: &Path,
        repositories: Vec<RepositoryInput>,
        backend: Arc<dyn ConfinedCodingBackend>,
        driver: D,
    ) -> Result<Self> {
        Ok(Self {
            repositories,
            packages_root: state.join("remediation-packages"),
            workspace_root: state.join("remediation-workspaces"),
            artifacts: ArtifactStore::open(state)?,
            backend,
            driver,
        })
    }
}

impl<D: PatchGeneratorDriver> PatchGenerator for RemediationPatchGenerator<D> {
    fn reconcile_patch(
        &mut self,
        desired: &RemediationDesiredEffect,
    ) -> Result<RemediationEffectOutput> {
        let RemediationEffectPlan::GeneratePatch {
            finding,
            source_package,
            editable_roots,
            limits,
            ..
        } = &desired.plan
        else {
            anyhow::bail!("generator received a plan for another remediation phase")
        };
        if desired.stop {
            return Ok(cleanup_settled(
                desired.remediation_id,
                &desired.fence,
                source_package,
            ));
        }
        let export_dir = self.export_package(source_package)?;
        let files = load_controlled_source_files(source_package, &export_dir)?;
        let policy = controlled_policy(editable_roots, &finding.source.path, limits);
        let owner_root = fresh_owner_root(&self.workspace_root)?;
        let facade = ControlledCodingFacade::materialize(
            &owner_root,
            files,
            policy,
            Arc::clone(&self.backend),
        )
        .context(
            "controlled coding facade launch failed; confinement is required \
             and this adapter never substitutes local execution",
        )?;
        let facade = Arc::new(tokio::sync::Mutex::new(facade));
        let tools = GeneratorTools {
            facade: Arc::clone(&facade),
        };
        let prompt = build_prompt(finding, editable_roots);
        let action = build_action(finding);
        self.driver.drive(tools, prompt, action)?;
        let facade = Arc::try_unwrap(facade)
            .map_err(|_| anyhow::anyhow!("controlled coding facade is still referenced"))?
            .into_inner();
        let capture = facade.capture()?;
        let proposal = build_submission(
            &self.artifacts,
            &capture,
            source_package.manifest_sha256.clone(),
        )?;
        Ok(RemediationEffectOutput::PatchProposed { proposal })
    }
}

impl<D: PatchGeneratorDriver> RemediationPatchGenerator<D> {
    fn export_package(&self, source_package: &SourcePackage) -> Result<PathBuf> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.packages_root)
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&self.packages_root)?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "remediation source package cache must be an owner-only real directory"
        );
        let destination = self.packages_root.join(&source_package.manifest_sha256);
        if destination.exists() {
            source_package.verify_export(&destination)?;
        } else {
            source_package.export(&self.repositories, &destination)?;
        }
        Ok(destination)
    }
}

fn fresh_owner_root(workspace_root: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(workspace_root)?;
    Ok(workspace_root.to_path_buf())
}

fn load_controlled_source_files(
    source_package: &SourcePackage,
    export_dir: &Path,
) -> Result<Vec<ControlledSourceFile>> {
    let mut files = Vec::with_capacity(source_package.files.len());
    for file in &source_package.files {
        let path = export_dir
            .join("main")
            .join(&file.repository)
            .join(&file.path);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("exported remediation source is missing: {}", file.path))?;
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == file.content_sha256,
            "exported remediation source content drift for {}",
            file.path
        );
        files.push(ControlledSourceFile {
            path: file.path.clone(),
            bytes,
            mode: 0o644,
        });
    }
    Ok(files)
}

fn controlled_policy(
    editable_roots: &[String],
    required_production_path: &str,
    limits: &RemediationLimits,
) -> ControlledCodingPolicy {
    ControlledCodingPolicy {
        editable_roots: editable_roots.to_vec(),
        required_production_path: required_production_path.to_string(),
        go_check: ControlledGoCheck {
            args: GO_CHECK_ARGS.iter().map(ToString::to_string).collect(),
        },
        environment: BTreeMap::new(),
        limits: ControlledCodingLimits {
            operation_timeout: Duration::from_millis(limits.operation_ms),
            max_output_bytes: limits.output_bytes as usize,
            max_read_bytes: MAX_READ_BYTES,
            max_files: limits.max_files as usize,
            max_patch_bytes: limits.max_patch_bytes as usize,
        },
    }
}

fn build_prompt(finding: &PublicFinding, editable_roots: &[String]) -> String {
    format!(
        "You are a narrow Go authorization remediation agent. Fix only the \
         described finding by editing production Go source under these \
         frozen editable roots: {editable_roots:?}. You may not touch tests, \
         go.mod, go.sum, vendor, or generated files, and this workspace has \
         no network or delegation access and no route to any other system. \
         Use read_source and search_source to inspect the workspace, \
         replace_source for exact-preimage edits, format_go before \
         finishing, and check_go at most once.\n\
         Finding: {claim}\n\
         Prerequisites: {prerequisites:?}\n\
         Production source: {path} (lines {start}-{end})",
        claim = finding.claim,
        prerequisites = finding.prerequisites,
        path = finding.source.path,
        start = finding.source.start_line,
        end = finding.source.end_line,
    )
}

fn build_action(finding: &PublicFinding) -> String {
    format!(
        "Fix the finding at {} and stop once the change is complete.",
        finding.source.path
    )
}

fn cleanup_settled(
    remediation_id: Id,
    fence: &EffectFence,
    source_package: &SourcePackage,
) -> RemediationEffectOutput {
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(remediation_id, fence, "remediation-generator-cleanup-v1"))
                .unwrap_or_default()
        )
    );
    RemediationEffectOutput::CleanupSettled {
        receipt: CleanupReceipt {
            process_sha256: digest.clone(),
            workspace_sha256: source_package.manifest_sha256.clone(),
            target_sha256: None,
            network_sha256: Some(digest),
            delayed_launches_settled: true,
            descendants_terminated: true,
        },
    }
}

fn build_submission(
    artifacts: &ArtifactStore,
    capture: &ControlledCodingCapture,
    source_package_sha256: String,
) -> Result<PatchGeneratorSubmission> {
    let mut replacements = Vec::with_capacity(capture.replacements.len());
    let mut diff_entries = Vec::with_capacity(capture.replacements.len());
    for replacement in &capture.replacements {
        let content = artifacts.write(
            &replacement.replacement,
            replacement.replacement.len() as u64,
        )?;
        ensure!(
            content.sha256 == replacement.replacement_sha256,
            "captured replacement content hash drift for {}",
            replacement.path
        );
        replacements.push(FileReplacement {
            path: replacement.path.clone(),
            original_sha256: replacement.original_sha256.clone(),
            replacement_sha256: replacement.replacement_sha256.clone(),
            replacement_bytes: content.bytes,
            content,
        });
        diff_entries.push(nac_appsec::ReplacementDiffEntry {
            path: replacement.path.clone(),
            original: replacement.original.clone(),
            replacement: replacement.replacement.clone(),
        });
    }
    let diff_bytes = canonical_replacement_diff(&diff_entries)?;
    let unified_diff = artifacts.write(&diff_bytes, diff_bytes.len() as u64)?;
    Ok(PatchGeneratorSubmission {
        schema_version: 1,
        authority: RemediationAuthorityReceipt {
            tools_sha256: capture.authority.tools_sha256.clone(),
            mounts_sha256: capture.authority.mounts_sha256.clone(),
            environment_sha256: capture.authority.environment_sha256.clone(),
            backend_sha256: capture.authority.backend_sha256.clone(),
            process_supervision_sha256: capture.authority.process_supervision_sha256.clone(),
            workspace_sha256: source_package_sha256,
        },
        replacements,
        unified_diff,
        diagnostics: Vec::new(),
    })
}

/// The exact, closed tool surface the model receives: scoped read, search,
/// exact-preimage edit, Go formatting, and one bounded Go check. Nothing else
/// is reachable through this type: no artifact browser, validator records,
/// evaluator registry, network, or delegation.
#[derive(Clone)]
pub(crate) struct GeneratorTools {
    facade: Arc<tokio::sync::Mutex<ControlledCodingFacade>>,
}

impl GeneratorTools {
    pub(crate) const TOOL_NAMES: [&'static str; 5] = [
        "read_source",
        "search_source",
        "replace_source",
        "format_go",
        "check_go",
    ];

    pub(crate) fn tool_names(&self) -> Vec<&'static str> {
        Self::TOOL_NAMES.to_vec()
    }

    pub(crate) async fn call(&self, name: &str, arguments: Value) -> Result<Value> {
        match name {
            "read_source" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Args {
                    path: String,
                }
                let args: Args = serde_json::from_value(arguments)?;
                let bytes = self.facade.lock().await.read(&args.path)?;
                Ok(json!({ "content": String::from_utf8(bytes)? }))
            }
            "search_source" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Args {
                    needle: String,
                }
                let args: Args = serde_json::from_value(arguments)?;
                let paths = self.facade.lock().await.search(args.needle.as_bytes())?;
                Ok(json!({ "paths": paths }))
            }
            "replace_source" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Args {
                    path: String,
                    expected_sha256: Option<String>,
                    content: String,
                }
                let args: Args = serde_json::from_value(arguments)?;
                self.facade.lock().await.replace(
                    &args.path,
                    args.expected_sha256.as_deref(),
                    args.content.as_bytes(),
                )?;
                Ok(json!({ "ok": true }))
            }
            "format_go" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Args {
                    paths: Vec<String>,
                }
                let args: Args = serde_json::from_value(arguments)?;
                let output = self.facade.lock().await.gofmt(&args.paths).await?;
                Ok(command_output_json(&output))
            }
            "check_go" => {
                let output = self.facade.lock().await.run_go_check().await?;
                Ok(command_output_json(&output))
            }
            other => anyhow::bail!("unknown remediation generator tool: {other}"),
        }
    }
}

fn command_output_json(output: &nac_core::controlled_coding::ControlledCommandOutput) -> Value {
    json!({
        "success": output.success,
        "code": output.code,
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
    })
}

/// Production [`PatchGeneratorDriver`]: runs the coding model through
/// `nac_core::runtime`'s existing controlled-managed-worker path, over a
/// loopback MCP transport that serves only [`GeneratorTools`]. Nothing else
/// is reachable: `allowed_tools` is fenced to exactly those five names, so a
/// tool the model asks for outside that set is rejected by the managed
/// worker's own inventory check before any call reaches this workspace.
pub(crate) struct ManagedWorkerDriver {
    model: nac_core::runtime::ModelOptions,
    wall: Duration,
    output_bytes: usize,
}

impl ManagedWorkerDriver {
    pub(crate) fn new(
        model: nac_core::runtime::ModelOptions,
        wall: Duration,
        output_bytes: usize,
    ) -> Self {
        Self {
            model,
            wall,
            output_bytes,
        }
    }

    async fn drive_async(
        &mut self,
        tools: GeneratorTools,
        prompt: String,
        action: String,
    ) -> Result<()> {
        use nac_core::{
            mcp_configurations::{McpServerConfig, McpTransportConfig},
            runtime::{
                build_controlled_managed_worker, run_controlled_managed_worker,
                ControlledWorkerOptions, ManagedWorkerControl,
            },
        };
        let control = ManagedWorkerControl::new(self.wall, self.output_bytes)?;
        let token = uuid::Uuid::new_v4().to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/mcp", listener.local_addr()?);
        let router = crate::delivery::appsec_remediation_mcp::router(
            tools,
            token.clone(),
            self.output_bytes,
        );
        let service = tokio::spawn(async move { axum::serve(listener, router).await });
        let directory = std::env::temp_dir().join(format!(
            "nac-remediation-generator-worker-{}",
            uuid::Uuid::new_v4()
        ));
        let options = ControlledWorkerOptions {
            directory,
            model: self.model.clone(),
            prompt,
            action,
            mcp_servers: BTreeMap::from([(
                "remediation".into(),
                McpServerConfig {
                    enabled: true,
                    library_id: None,
                    transport: McpTransportConfig::StreamableHttp {
                        url,
                        headers: BTreeMap::from([(
                            "Authorization".into(),
                            format!("Bearer {token}"),
                        )]),
                    },
                },
            )]),
            allowed_tools: GeneratorTools::TOOL_NAMES
                .iter()
                .map(|name| format!("mcp__remediation__{name}"))
                .collect(),
            control: control.clone(),
        };
        let (config, _proof) = build_controlled_managed_worker(options).await?;
        let result = run_controlled_managed_worker(config, control).await;
        service.abort();
        result.map(|_| ())
    }
}

impl PatchGeneratorDriver for ManagedWorkerDriver {
    fn drive(&mut self, tools: GeneratorTools, prompt: String, action: String) -> Result<()> {
        tokio::runtime::Runtime::new()?.block_on(self.drive_async(tools, prompt, action))
    }
}

#[cfg(test)]
#[path = "generator_tests.rs"]
mod tests;
