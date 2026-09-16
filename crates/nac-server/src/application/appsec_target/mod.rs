use anyhow::{ensure, Context, Result};
use nac_appsec::{
    Assessment, ControlKind, ControlResult, EvaluatorVerdict, ExperimentCode, ExperimentDesired,
    ExperimentPhase, ExperimentRunner, ExperimentVerdict, HttpRequest, OracleClass,
    PublicDiagnostic, RecipeBinding, RunnerObservation, TargetIdentity,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod build;
mod docker;
mod export;
mod http;
mod prepare;
mod private;
mod process;

pub use prepare::{LocalPilotArtifacts, LocalPilotPreparation};

const PRIVATE_CAPTURE_CAP: u64 = 192 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPilot {
    pub schema_version: u32,
    pub id: String,
    pub recipe_sha256: String,
    pub target: TargetIdentity,
    pub image: String,
    pub source_export_sha256: String,
    pub build_receipt_sha256: String,
    pub builder_image: String,
    pub environment_sha256: String,
    pub evaluator: String,
    pub rubric: String,
    pub protected: bool,
    pub private_sha256: String,
    pub production_export: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDiagnosticProjection {
    pub code: ExperimentCode,
    pub stream: Option<BuildOutputStream>,
    pub source_path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub byte_offset: Option<u64>,
    pub truncated: bool,
}

impl FrozenPilot {
    pub fn effective_environment_sha256(protected: bool) -> Result<String> {
        let bytes = serde_json::to_vec(&(
            "nac-appsec-target-v2",
            protected,
            "65534:65534",
            true,
            "ALL",
            "seccomp=builtin",
            "no-new-privileges=true",
            32_u32,
            67_108_864_u64,
            500_000_000_u64,
            "internal-ipv4-isolated-ipv6-disabled",
            "none",
        ))?;
        Ok(private::digest(&bytes))
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(private::digest(&serde_json::to_vec(&(
            1_u32,
            &self.id,
            &self.recipe_sha256,
            &self.target,
            &self.image,
            &self.source_export_sha256,
            &self.build_receipt_sha256,
            &self.builder_image,
            &self.environment_sha256,
            &self.evaluator,
            &self.rubric,
            self.protected,
        ))?))
    }

    fn verify(&self, binding: &RecipeBinding) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "invalid private pilot identity"
        );
        ensure!(
            self.schema_version == 1
                && self.id == binding.id
                && self.recipe_sha256 == binding.recipe_sha256
                && self.target == binding.target,
            "private pilot identity mismatch"
        );
        ensure!(
            self.private_sha256 == self.canonical_sha256()?,
            "private pilot policy digest drift"
        );
        ensure!(
            self.image == format!("sha256:{}", binding.target.image_sha256)
                && self
                    .builder_image
                    .strip_prefix("sha256:")
                    .is_some_and(|digest| digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
                && self.source_export_sha256 == binding.production.manifest_sha256
                && self.build_receipt_sha256 == binding.target.build_sha256
                && self.environment_sha256 == binding.target.environment_sha256
                && self.environment_sha256 == Self::effective_environment_sha256(self.protected)?,
            "private pilot digest mismatch"
        );
        let expected = match binding.oracle_class {
            OracleClass::Authorization => (
                "nac-local-authz-v1",
                "actual-forbidden-delivery-and-state-change-v1",
            ),
            OracleClass::RceNonce => (
                "nac-local-rce-nonce-v1",
                "exact-current-target-nonce-disclosure-v1",
            ),
        };
        ensure!(
            (self.evaluator.as_str(), self.rubric.as_str()) == expected,
            "unsupported private evaluator"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Resource {
    run_key: nac_appsec::Id,
    #[serde(default)]
    instance: String,
    name: String,
    network_pending: bool,
    network_ack: bool,
    create_pending: bool,
    container: Option<String>,
    injected: bool,
    start_pending: bool,
    started: bool,
    request_pending: bool,
    #[serde(default)]
    request_plan_sha256: Option<String>,
    capture_ack: bool,
    #[serde(default)]
    attack_capture_ack: bool,
    #[serde(default)]
    execution_receipt: Option<nac_appsec::ExecutionReceipt>,
    stopped: bool,
    cleaned: bool,
    nonce: String,
    nonce_sha256: String,
    owner: String,
    #[serde(default)]
    protected: bool,
}

pub struct AppsecTargetRunner {
    root: PathBuf,
    pilots: Vec<FrozenPilot>,
}

impl AppsecTargetRunner {
    pub fn prepare_local_pilot(input: LocalPilotPreparation) -> Result<LocalPilotArtifacts> {
        prepare::prepare(input)
    }

    pub fn freeze_registry(
        state: &Path,
        bindings: &[RecipeBinding],
        pilots: Vec<FrozenPilot>,
    ) -> Result<()> {
        ensure!(
            bindings.len() == pilots.len() && !pilots.is_empty(),
            "every public recipe needs one private pilot"
        );
        private::directory(state)?;
        let root = state.join("targets");
        private::directory(&root)?;
        let export_root = root.join("production-exports");
        private::directory(&export_root)?;
        let mut frozen = pilots;
        for binding in bindings {
            let index = frozen
                .iter()
                .position(|pilot| pilot.id == binding.id)
                .context("missing private pilot")?;
            let pilot = &frozen[index];
            pilot.verify(binding)?;
            export::verify_package_source(&pilot.production_export, &binding.production)?;
            let destination = export_root.join(&pilot.id);
            if destination.exists() {
                export::verify_package_source(&destination, &binding.production)?;
            } else {
                export::copy(&pilot.production_export, &destination)?;
                export::verify_package_source(&destination, &binding.production)?;
            }
            build::verify_build(
                &frozen[index],
                &destination,
                &root.join("build-verification"),
            )?;
            frozen[index].production_export = destination;
        }
        let path = root.join("registry.json");
        if path.exists() {
            let existing: Vec<FrozenPilot> = private::read(&path)?;
            ensure!(
                serde_json::to_vec(&existing)? == serde_json::to_vec(&frozen)?,
                "frozen private registry differs"
            );
        } else {
            private::write(&path, &frozen)?;
        }
        let registry_bytes = std::fs::read(&path)?;
        let digest_path = root.join("registry.sha256");
        if digest_path.exists() {
            let expected = std::fs::read_to_string(&digest_path)?;
            ensure!(
                expected.trim() == private::digest(&registry_bytes),
                "frozen private registry digest drift"
            );
        } else {
            private::write_bytes(&digest_path, private::digest(&registry_bytes).as_bytes())?;
        }
        Ok(())
    }

    pub fn new(state: &Path) -> Result<Self> {
        let root = state.join("targets");
        private::directory(&root)?;
        let pilots = private::read(&root.join("registry.json"))
            .context("private experiment registry unavailable")?;
        let registry_bytes = std::fs::read(root.join("registry.json"))?;
        let expected = std::fs::read_to_string(root.join("registry.sha256"))?;
        ensure!(
            expected.trim() == private::digest(&registry_bytes),
            "frozen private registry digest drift"
        );
        Ok(Self { root, pilots })
    }

    pub fn private_diagnostic(&self, run_key: nac_appsec::Id) -> Result<Vec<u8>> {
        private::bytes(
            &self
                .root
                .join(run_key.to_string())
                .join("attack")
                .join("capture.bin"),
            PRIVATE_CAPTURE_CAP,
        )
    }

    pub fn operator_build_diagnostics(
        state: &Path,
        pilot_id: &str,
    ) -> Result<Vec<BuildDiagnosticProjection>> {
        build::read_projection(&state.join("targets").join("build-verification"), pilot_id)
    }

    fn resource(
        &self,
        desired: &ExperimentDesired,
        instance: &str,
        protected: bool,
    ) -> Result<(PathBuf, Resource)> {
        ensure!(
            !instance.is_empty()
                && instance.len() <= 32
                && instance
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
            "invalid private target instance"
        );
        let run_directory = self.root.join(desired.run_key.to_string());
        private::directory(&run_directory)?;
        let directory = run_directory.join(instance);
        private::directory(&directory)?;
        let path = directory.join("resource.json");
        let resource = if path.exists() {
            let resource: Resource = private::read(&path)?;
            ensure!(
                resource.run_key == desired.run_key,
                "private resource identity drift"
            );
            ensure!(
                resource.instance == instance && resource.protected == protected,
                "private target purpose drift"
            );
            resource
        } else {
            let nonce = uuid::Uuid::new_v4().to_string();
            let resource = Resource {
                run_key: desired.run_key,
                instance: instance.into(),
                name: format!("nac-appsec-{}-{instance}", desired.run_key),
                network_pending: false,
                network_ack: false,
                create_pending: false,
                container: None,
                injected: false,
                start_pending: false,
                started: false,
                request_pending: false,
                request_plan_sha256: None,
                capture_ack: false,
                attack_capture_ack: false,
                execution_receipt: None,
                stopped: false,
                cleaned: false,
                nonce_sha256: private::digest(nonce.as_bytes()),
                nonce,
                owner: uuid::Uuid::new_v4().to_string(),
                protected,
            };
            private::write(&path, &resource)?;
            resource
        };
        Ok((path, resource))
    }

    fn pilot(&self, binding: &RecipeBinding) -> Result<&FrozenPilot> {
        let pilot = self
            .pilots
            .iter()
            .find(|pilot| pilot.id == binding.id)
            .context("private pilot unavailable")?;
        pilot.verify(binding)?;
        Ok(pilot)
    }
}

impl ExperimentRunner for AppsecTargetRunner {
    fn reconcile(
        &mut self,
        desired: &ExperimentDesired,
    ) -> std::result::Result<RunnerObservation, ExperimentCode> {
        if process::capabilities(desired.recipe.operation_ms).is_err() {
            return Err(ExperimentCode::Unsupported);
        }
        if self.pilot(&desired.recipe).is_err() {
            return Err(ExperimentCode::IdentityDrift);
        }
        self.reconcile_private(desired).map_err(|error| {
            if error
                .chain()
                .any(|cause| cause.to_string() == "identity_drift")
            {
                ExperimentCode::IdentityDrift
            } else {
                ExperimentCode::AdapterUnavailable
            }
        })
    }
}

impl AppsecTargetRunner {
    fn reconcile_private(&self, desired: &ExperimentDesired) -> Result<RunnerObservation> {
        let pilot = self.pilot(&desired.recipe)?.clone();
        let (journal, _) = self.resource(desired, "attack", pilot.protected)?;
        let _writer = private::lock(&journal.with_extension("lock"))?;
        let mut resource: Resource = private::read(&journal)?;
        let captured_attack_can_advance = resource.attack_capture_ack
            && matches!(
                desired.phase,
                ExperimentPhase::PendingRequest
                    | ExperimentPhase::Captured
                    | ExperimentPhase::Assessed
                    | ExperimentPhase::CleanupPending
            );
        if desired.stop || (resource.stopped && !captured_attack_can_advance) {
            docker::cleanup(&mut resource, &journal, desired.recipe.operation_ms)?;
            self.cleanup_control_resources(desired.run_key, &pilot, desired.recipe.operation_ms)?;
            return Ok(observation(
                desired,
                ExperimentPhase::Cleaned,
                ExperimentCode::Cancelled,
                None,
            ));
        }
        if desired.phase == ExperimentPhase::Assessed {
            return Ok(observation(
                desired,
                ExperimentPhase::CleanupPending,
                ExperimentCode::Pending,
                Some(pilot.target),
            ));
        }
        if desired.phase == ExperimentPhase::CleanupPending {
            docker::cleanup(&mut resource, &journal, desired.recipe.operation_ms)?;
            return Ok(observation(
                desired,
                ExperimentPhase::Cleaned,
                ExperimentCode::Pending,
                None,
            ));
        }
        match desired.phase {
            ExperimentPhase::PendingCreate => {
                docker::prepare(&mut resource, &pilot, &journal, desired.recipe.operation_ms)
                    .context("target preparation failed")?;
                Ok(observation(
                    desired,
                    ExperimentPhase::PendingStart,
                    ExperimentCode::Pending,
                    Some(pilot.target),
                ))
            }
            ExperimentPhase::PendingStart => {
                docker::start(&mut resource, &pilot, &journal, desired.recipe.operation_ms)
                    .context("target start failed")?;
                docker::deny_checks(&resource, desired.recipe.operation_ms)
                    .context("adapter network isolation failed")?;
                Ok(observation(
                    desired,
                    ExperimentPhase::Ready,
                    ExperimentCode::Pending,
                    Some(pilot.target),
                ))
            }
            ExperimentPhase::Ready => {
                docker::verify_target(
                    &docker::inspect_bounded(
                        resource.container.as_ref().context("target missing")?,
                        desired.recipe.operation_ms,
                    )?,
                    &resource,
                    &pilot,
                    desired.recipe.operation_ms,
                )
                .context("identity_drift")?;
                readiness(
                    &resource,
                    &desired.recipe,
                    &journal,
                    desired.recipe.operation_ms,
                )
                .context("target readiness failed")?;
                Ok(observation(
                    desired,
                    ExperimentPhase::PendingRequest,
                    ExperimentCode::Pending,
                    Some(pilot.target),
                ))
            }
            ExperimentPhase::PendingRequest => {
                self.cleanup_control_resources(
                    desired.run_key,
                    &pilot,
                    desired.recipe.operation_ms,
                )?;
                if self.incomplete_control_exists(desired.run_key)? {
                    resource.stopped = true;
                    private::write(&journal, &resource)?;
                    return Ok(observation(
                        desired,
                        ExperimentPhase::CleanupPending,
                        ExperimentCode::DeliveryUncertain,
                        Some(pilot.target),
                    ));
                }
                if resource.capture_ack {
                    ensure!(
                        resource.request_plan_sha256.as_deref()
                            == Some(desired.plan_sha256.as_str()),
                        "captured request plan identity drift"
                    );
                    return Ok(observation(
                        desired,
                        ExperimentPhase::Captured,
                        ExperimentCode::Pending,
                        Some(pilot.target),
                    ));
                }
                if resource.request_pending {
                    resource.stopped = true;
                    private::write(&journal, &resource)?;
                    return Ok(observation(
                        desired,
                        ExperimentPhase::CleanupPending,
                        ExperimentCode::DeliveryUncertain,
                        Some(pilot.target),
                    ));
                }
                let attack = if resource.attack_capture_ack {
                    serde_json::from_slice(&private::bytes(
                        &journal.with_file_name("attack.bin"),
                        PRIVATE_CAPTURE_CAP,
                    )?)?
                } else {
                    resource.request_pending = true;
                    resource.request_plan_sha256 = Some(desired.plan_sha256.clone());
                    private::write(&journal, &resource)?;
                    docker::verify_target(
                        &docker::inspect_bounded(
                            resource.container.as_ref().context("target missing")?,
                            desired.recipe.operation_ms,
                        )?,
                        &resource,
                        &pilot,
                        desired.recipe.operation_ms,
                    )
                    .context("identity_drift")?;
                    validate_requests(&desired.recipe, &desired.requests)?;
                    let requests = evaluator_requests(&desired.recipe, &desired.requests);
                    let attack = capture(&resource, &desired.recipe, &requests, false)
                        .context("attack probe failed")?;
                    private::write_bytes(
                        &journal.with_file_name("attack.bin"),
                        &serde_json::to_vec(&attack)?,
                    )?;
                    resource.execution_receipt = Some(receipt(&resource, &pilot, desired)?);
                    resource.attack_capture_ack = true;
                    resource.request_pending = false;
                    private::write(&journal, &resource)?;
                    docker::cleanup(&mut resource, &journal, desired.recipe.operation_ms)?;
                    attack
                };
                let capture = encode_private_capture(
                    attack,
                    self.capture_controls(desired, &pilot)
                        .context("fresh private controls failed")?,
                    PRIVATE_CAPTURE_CAP,
                )?;
                private::write_bytes(&journal.with_file_name("capture.bin"), &capture)?;
                resource.capture_ack = true;
                private::write(&journal, &resource)?;
                Ok(observation(
                    desired,
                    ExperimentPhase::Captured,
                    ExperimentCode::Pending,
                    Some(pilot.target),
                ))
            }
            ExperimentPhase::Captured => {
                let capture =
                    private::bytes(&journal.with_file_name("capture.bin"), PRIVATE_CAPTURE_CAP)?;
                let verdict = evaluate(&resource, &desired.recipe, &capture)?;
                Ok(RunnerObservation {
                    run_key: desired.run_key,
                    phase: ExperimentPhase::Assessed,
                    code: verdict
                        .diagnostics
                        .first()
                        .map(|diagnostic| diagnostic.code)
                        .unwrap_or(ExperimentCode::Pending),
                    effective_target: Some(pilot.target.clone()),
                    execution_receipt: Some(
                        resource
                            .execution_receipt
                            .clone()
                            .context("private execution receipt missing")?,
                    ),
                    evaluation: Some(EvaluatorVerdict(verdict)),
                })
            }
            _ => anyhow::bail!("unsupported private reconciliation phase"),
        }
    }
}

impl AppsecTargetRunner {
    fn incomplete_control_exists(&self, run_key: nac_appsec::Id) -> Result<bool> {
        let run_directory = self.root.join(run_key.to_string());
        for instance in [
            "owner-access",
            "public-access",
            "benign",
            "no-prerequisite",
            "legitimate-use",
            "health",
        ] {
            let journal = run_directory.join(instance).join("resource.json");
            if !journal.exists() {
                continue;
            }
            let resource: Resource = private::read(&journal)?;
            if resource.cleaned && !resource.capture_ack {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn cleanup_control_resources(
        &self,
        run_key: nac_appsec::Id,
        pilot: &FrozenPilot,
        timeout_ms: u64,
    ) -> Result<()> {
        let run_directory = self.root.join(run_key.to_string());
        for instance in [
            "owner-access",
            "public-access",
            "benign",
            "no-prerequisite",
            "legitimate-use",
            "health",
        ] {
            let journal = run_directory.join(instance).join("resource.json");
            if !journal.exists() {
                continue;
            }
            let _writer = private::lock(&journal.with_extension("lock"))?;
            let mut resource: Resource = private::read(&journal)?;
            docker::cleanup(&mut resource, &journal, timeout_ms)
                .with_context(|| format!("private control cleanup uncertain for {}", pilot.id))?;
        }
        Ok(())
    }

    fn capture_controls(
        &self,
        desired: &ExperimentDesired,
        pilot: &FrozenPilot,
    ) -> Result<Vec<ControlCapture>> {
        desired
            .recipe
            .oracle_class
            .required_controls()
            .iter()
            .map(|control| self.capture_control(desired, pilot, *control))
            .collect()
    }

    fn capture_control(
        &self,
        desired: &ExperimentDesired,
        pilot: &FrozenPilot,
        control: ControlKind,
    ) -> Result<ControlCapture> {
        let requests = control_requests(control, &desired.recipe, &desired.requests)?;
        let instance = control_instance(control);
        let (journal, _) = self.resource(desired, instance, true)?;
        let _writer = private::lock(&journal.with_extension("lock"))?;
        let mut resource: Resource = private::read(&journal)?;
        let capture_path = journal.with_file_name("capture.bin");
        if resource.capture_ack && resource.cleaned {
            return Ok(ControlCapture {
                control,
                nonce: resource.nonce,
                capture: serde_json::from_slice(&private::bytes(
                    &capture_path,
                    PRIVATE_CAPTURE_CAP,
                )?)?,
            });
        }
        ensure!(
            !resource.request_pending || resource.capture_ack,
            "private control request delivery is uncertain"
        );
        let result = (|| {
            docker::prepare(&mut resource, pilot, &journal, desired.recipe.operation_ms)?;
            docker::start(&mut resource, pilot, &journal, desired.recipe.operation_ms)?;
            docker::deny_checks(&resource, desired.recipe.operation_ms)?;
            readiness(
                &resource,
                &desired.recipe,
                &journal,
                desired.recipe.operation_ms,
            )?;
            resource.request_pending = true;
            resource.request_plan_sha256 = Some(desired.plan_sha256.clone());
            private::write(&journal, &resource)?;
            let capture = capture(&resource, &desired.recipe, &requests, false)?;
            private::write_bytes(&capture_path, &serde_json::to_vec(&capture)?)?;
            resource.capture_ack = true;
            private::write(&journal, &resource)?;
            Ok(capture)
        })();
        let capture = match result {
            Ok(capture) => {
                docker::cleanup(&mut resource, &journal, desired.recipe.operation_ms)?;
                capture
            }
            Err(error) => {
                let _ = docker::cleanup(&mut resource, &journal, desired.recipe.operation_ms);
                return Err(error);
            }
        };
        Ok(ControlCapture {
            control,
            nonce: resource.nonce,
            capture,
        })
    }
}

fn observation(
    desired: &ExperimentDesired,
    phase: ExperimentPhase,
    code: ExperimentCode,
    target: Option<TargetIdentity>,
) -> RunnerObservation {
    RunnerObservation {
        run_key: desired.run_key,
        phase,
        code,
        effective_target: target,
        execution_receipt: None,
        evaluation: None,
    }
}

fn readiness(
    resource: &Resource,
    recipe: &RecipeBinding,
    journal: &Path,
    timeout_ms: u64,
) -> Result<()> {
    let pid = docker::inspect_bounded(
        resource.container.as_ref().context("target missing")?,
        timeout_ms,
    )?["State"]["Pid"]
        .as_u64()
        .context("target PID missing")?;
    let health = HttpRequest {
        actor: "anonymous".into(),
        method: nac_appsec::HttpMethod::Get,
        path: "/health".into(),
        body: String::new(),
    };
    let response = http::send(
        pid,
        &health,
        &resource.owner,
        recipe.capture_bytes.try_into()?,
        timeout_ms,
    )?;
    ensure!(
        response.complete && response.body == b"healthy",
        "target readiness failed"
    );
    private::write_bytes(&journal.with_file_name("readiness.bin"), &response.raw)?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
struct CapturedExchange {
    request: HttpRequest,
    complete: bool,
    raw: Vec<u8>,
    tail: Vec<u8>,
    total: u64,
    body_start: usize,
    status: Option<u16>,
}

#[derive(Serialize, Deserialize)]
struct PrivateCapture {
    attack: Vec<CapturedExchange>,
    controls: Vec<ControlCapture>,
    #[serde(default)]
    incomplete: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ControlCapture {
    control: ControlKind,
    nonce: String,
    capture: Vec<CapturedExchange>,
}

fn encode_private_capture(
    attack: Vec<CapturedExchange>,
    controls: Vec<ControlCapture>,
    cap: u64,
) -> Result<Vec<u8>> {
    let capture = PrivateCapture {
        attack,
        controls,
        incomplete: false,
    };
    let bytes = serde_json::to_vec(&capture)?;
    if bytes.len() as u64 <= cap {
        return Ok(bytes);
    }
    let marker = serde_json::to_vec(&PrivateCapture {
        attack: vec![],
        controls: vec![],
        incomplete: true,
    })?;
    ensure!(
        marker.len() as u64 <= cap,
        "private capture marker exceeds spool bound"
    );
    Ok(marker)
}

fn control_instance(control: ControlKind) -> &'static str {
    match control {
        ControlKind::OwnerAccess => "owner-access",
        ControlKind::PublicAccess => "public-access",
        ControlKind::Benign => "benign",
        ControlKind::NoPrerequisite => "no-prerequisite",
        ControlKind::LegitimateUse => "legitimate-use",
        ControlKind::Health => "health",
    }
}

fn control_requests(
    control: ControlKind,
    recipe: &RecipeBinding,
    attack: &[HttpRequest],
) -> Result<Vec<HttpRequest>> {
    let request = |actor: &str, method, path: &str, body: &str| HttpRequest {
        actor: actor.into(),
        method,
        path: path.into(),
        body: body.into(),
    };
    let controls = match (recipe.oracle_class, control) {
        (OracleClass::Authorization, ControlKind::OwnerAccess) => {
            vec![request(
                "owner",
                nac_appsec::HttpMethod::Get,
                "/object/owner",
                "",
            )]
        }
        (OracleClass::Authorization, ControlKind::PublicAccess)
        | (OracleClass::RceNonce, ControlKind::LegitimateUse) => {
            vec![request(
                "anonymous",
                nac_appsec::HttpMethod::Get,
                "/public",
                "",
            )]
        }
        (OracleClass::Authorization, ControlKind::LegitimateUse) => vec![request(
            "owner",
            nac_appsec::HttpMethod::Post,
            "/state",
            "owner-change",
        )],
        (OracleClass::Authorization, ControlKind::Health)
        | (OracleClass::RceNonce, ControlKind::Health) => {
            vec![request(
                "anonymous",
                nac_appsec::HttpMethod::Get,
                "/health",
                "",
            )]
        }
        (OracleClass::RceNonce, ControlKind::Benign) => vec![request(
            "owner",
            nac_appsec::HttpMethod::Post,
            "/execute",
            "/target echo",
        )],
        (OracleClass::RceNonce, ControlKind::NoPrerequisite) => {
            let attacker: Vec<_> = attack
                .iter()
                .filter(|request| request.actor == "attacker")
                .cloned()
                .collect();
            ensure!(
                !attacker.is_empty()
                    && attacker.iter().any(|request| request.path == "/execute"),
                "RCE experiment requires an attacker /execute probe for its no-prerequisite control"
            );
            attacker
        }
        _ => anyhow::bail!("private control does not match the selected oracle"),
    };
    Ok(controls)
}

fn evaluator_requests(recipe: &RecipeBinding, attack: &[HttpRequest]) -> Vec<HttpRequest> {
    let mut requests = Vec::with_capacity(attack.len().saturating_mul(3));
    for request in attack {
        if recipe.oracle_class == OracleClass::Authorization
            && request.actor == "attacker"
            && request.method == nac_appsec::HttpMethod::Post
            && request.path == "/state"
        {
            let read = HttpRequest {
                actor: "attacker".into(),
                method: nac_appsec::HttpMethod::Get,
                path: "/state".into(),
                body: String::new(),
            };
            requests.push(read.clone());
            requests.push(request.clone());
            requests.push(read);
        } else {
            requests.push(request.clone());
        }
    }
    requests
}

fn capture(
    resource: &Resource,
    recipe: &RecipeBinding,
    requests: &[HttpRequest],
    enforce_interface: bool,
) -> Result<Vec<CapturedExchange>> {
    if enforce_interface {
        validate_requests(recipe, requests)?;
    }
    let pid = docker::inspect_bounded(
        resource.container.as_ref().context("target missing")?,
        recipe.operation_ms,
    )?["State"]["Pid"]
        .as_u64()
        .context("target PID missing")?;
    let per = (16_usize * 1024 * 1024)
        .checked_div(requests.len())
        .context("capture spool bound too small")?
        .max(1);
    let public_bound = usize::try_from(recipe.capture_bytes)?
        .checked_div(requests.len())
        .context("capture public bound too small")?
        .max(1);
    let exchanges: Vec<_> = requests
        .iter()
        .map(|request| {
            let exchange = http::send(pid, request, &resource.owner, per, recipe.operation_ms)?;
            let body_start = exchange
                .raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| offset + 4)
                .unwrap_or(exchange.raw.len());
            let status = std::str::from_utf8(
                exchange
                    .raw
                    .split(|byte| *byte == b'\r')
                    .next()
                    .unwrap_or_default(),
            )
            .ok()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok());
            Ok(CapturedExchange {
                request: request.clone(),
                complete: exchange.complete && exchange.total <= public_bound as u64,
                raw: exchange.raw,
                tail: exchange.tail,
                total: exchange.total,
                body_start,
                status,
            })
        })
        .collect::<Result<_>>()?;
    let bytes = serde_json::to_vec(&exchanges)?;
    ensure!(
        bytes.len() as u64 <= PRIVATE_CAPTURE_CAP,
        "private capture spool overflow"
    );
    Ok(exchanges)
}

fn validate_requests(recipe: &RecipeBinding, requests: &[HttpRequest]) -> Result<()> {
    ensure!(
        !requests.is_empty() && requests.len() <= recipe.interface.max_requests as usize,
        "experiment request sequence exceeds the declared interface"
    );
    for request in requests {
        ensure!(
            recipe.interface.routes.iter().any(|route| {
                route.actor == request.actor
                    && route.method == request.method
                    && (route.path_prefix == "/"
                        || request.path == route.path_prefix
                        || request.path.starts_with(&format!("{}/", route.path_prefix)))
                    && request.body.len() as u64 <= route.max_body_bytes
            }),
            "experiment request lies outside the declared interface"
        );
    }
    Ok(())
}

fn receipt(
    resource: &Resource,
    pilot: &FrozenPilot,
    desired: &ExperimentDesired,
) -> Result<nac_appsec::ExecutionReceipt> {
    let inspected = docker::inspect_bounded(
        resource.container.as_ref().context("target missing")?,
        desired.recipe.operation_ms,
    )?;
    let target = &inspected["Config"];
    let host = &inspected["HostConfig"];
    Ok(nac_appsec::ExecutionReceipt {
        adapter_version: "nac-appsec-target-v2".into(),
        broker_sha256: private::digest(include_bytes!("http_broker.py")),
        evaluator_sha256: private::digest(include_bytes!("mod.rs")),
        source_manifest_sha256: desired.recipe.target.source_sha256.clone(),
        build_sha256: pilot.build_receipt_sha256.clone(),
        image_sha256: pilot
            .image
            .strip_prefix("sha256:")
            .context("private image identity malformed")?
            .into(),
        environment_sha256: FrozenPilot::effective_environment_sha256(pilot.protected)?,
        launch_sha256: private::digest(&serde_json::to_vec(&(
            target["User"].clone(),
            target["WorkingDir"].clone(),
            target["Entrypoint"].clone(),
            target["Cmd"].clone(),
            target["Env"].clone(),
        ))?),
        mount_sha256: private::digest(&serde_json::to_vec(&inspected["Mounts"])?),
        network_sha256: private::digest(&serde_json::to_vec(&(
            host["NetworkMode"].clone(),
            host["PortBindings"].clone(),
            host["PublishAllPorts"].clone(),
        ))?),
        log_sha256: private::digest(&serde_json::to_vec(&host["LogConfig"])?),
        resource_sha256: private::digest(&serde_json::to_vec(&(
            host["ReadonlyRootfs"].clone(),
            host["CapDrop"].clone(),
            host["SecurityOpt"].clone(),
            host["PidsLimit"].clone(),
            host["Memory"].clone(),
            host["NanoCpus"].clone(),
        ))?),
        request_plan_sha256: desired.plan_sha256.clone(),
    })
}

fn exchange_body(exchange: &CapturedExchange) -> &[u8] {
    &exchange.raw[exchange.body_start.min(exchange.raw.len())..]
}

fn evaluate(
    resource: &Resource,
    recipe: &RecipeBinding,
    bytes: &[u8],
) -> Result<ExperimentVerdict> {
    let captured: PrivateCapture = serde_json::from_slice(bytes)?;
    if captured.incomplete {
        return Ok(ExperimentVerdict {
            assessment: Assessment::Inconclusive,
            controls: vec![],
            diagnostics: vec![diagnostic(ExperimentCode::CaptureIncomplete, None, true)],
        });
    }
    let exchanges = captured.attack;
    if exchanges.is_empty() || exchanges.iter().any(|exchange| !exchange.complete) {
        return Ok(ExperimentVerdict {
            assessment: Assessment::Inconclusive,
            controls: vec![],
            diagnostics: sanitize(&exchanges),
        });
    }
    let exchange = |path: &str, actor: &str, method| {
        exchanges.iter().find(|exchange| {
            exchange.request.path == path
                && exchange.request.actor == actor
                && exchange.request.method == method
                && exchange
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
        })
    };
    let controls: Vec<ControlResult> = recipe
        .oracle_class
        .required_controls()
        .iter()
        .map(|kind| {
            let result = captured
                .controls
                .iter()
                .find(|capture| capture.control == *kind)
                .is_some_and(|capture| {
                    control_passed(recipe.oracle_class, *kind, &capture.nonce, &capture.capture)
                });
            control(*kind, result)
        })
        .collect();
    if controls.iter().any(|control| !control.passed) {
        return Ok(ExperimentVerdict {
            assessment: Assessment::Inconclusive,
            controls,
            diagnostics: vec![diagnostic(ExperimentCode::ControlFailed, None, false)],
        });
    }
    let confirmed = match recipe.oracle_class {
        OracleClass::Authorization => {
            exchange("/object/owner", "attacker", nac_appsec::HttpMethod::Get)
                .is_some_and(|exchange| exchange_body(exchange) == resource.nonce.as_bytes())
                || exchanges.windows(3).any(|triple| {
                    let before = &triple[0];
                    let write = &triple[1];
                    let after = &triple[2];
                    before.request.actor == "attacker"
                        && before.request.method == nac_appsec::HttpMethod::Get
                        && before.request.path == "/state"
                        && before
                            .status
                            .is_some_and(|status| (200..300).contains(&status))
                        && write.request.actor == "attacker"
                        && write.request.method == nac_appsec::HttpMethod::Post
                        && write.request.path == "/state"
                        && write
                            .status
                            .is_some_and(|status| (200..300).contains(&status))
                        && after.request.actor == "attacker"
                        && after.request.method == nac_appsec::HttpMethod::Get
                        && after.request.path == "/state"
                        && after
                            .status
                            .is_some_and(|status| (200..300).contains(&status))
                        && exchange_body(before) != write.request.body.as_bytes()
                        && exchange_body(after) == write.request.body.as_bytes()
                })
        }
        OracleClass::RceNonce => exchange("/execute", "attacker", nac_appsec::HttpMethod::Post)
            .is_some_and(|exchange| exchange_body(exchange) == resource.nonce.as_bytes()),
    };
    Ok(ExperimentVerdict {
        assessment: if confirmed {
            Assessment::Confirmed
        } else {
            Assessment::NotObserved
        },
        controls,
        diagnostics: vec![],
    })
}

fn control_passed(
    oracle: OracleClass,
    control: ControlKind,
    nonce: &str,
    exchanges: &[CapturedExchange],
) -> bool {
    if exchanges.is_empty() || exchanges.iter().any(|exchange| !exchange.complete) {
        return false;
    }
    let response = |path: &str, actor: &str, method| {
        exchanges.iter().find(|exchange| {
            exchange.request.path == path
                && exchange.request.actor == actor
                && exchange.request.method == method
                && exchange
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
        })
    };
    match (oracle, control) {
        (OracleClass::Authorization, ControlKind::OwnerAccess) => {
            response("/object/owner", "owner", nac_appsec::HttpMethod::Get)
                .is_some_and(|exchange| exchange_body(exchange) == nonce.as_bytes())
        }
        (OracleClass::Authorization, ControlKind::PublicAccess)
        | (OracleClass::RceNonce, ControlKind::LegitimateUse) => {
            response("/public", "anonymous", nac_appsec::HttpMethod::Get)
                .is_some_and(|exchange| exchange_body(exchange) == b"intentionally-public")
        }
        (OracleClass::Authorization, ControlKind::LegitimateUse) => {
            response("/state", "owner", nac_appsec::HttpMethod::Post).is_some_and(|exchange| {
                exchange.request.body == "owner-change"
                    && exchange_body(exchange) == b"owner-change"
            })
        }
        (OracleClass::RceNonce, ControlKind::Benign) => {
            response("/execute", "owner", nac_appsec::HttpMethod::Post).is_some_and(|exchange| {
                exchange.request.body == "/target echo"
                    && exchange_body(exchange) == b"legitimate-use-ok"
            })
        }
        (OracleClass::RceNonce, ControlKind::NoPrerequisite) => exchanges
            .iter()
            .filter(|exchange| exchange.request.actor == "attacker")
            .all(|exchange| exchange_body(exchange) != nonce.as_bytes()),
        (OracleClass::Authorization | OracleClass::RceNonce, ControlKind::Health) => {
            response("/health", "anonymous", nac_appsec::HttpMethod::Get)
                .is_some_and(|exchange| exchange_body(exchange) == b"healthy")
        }
        _ => false,
    }
}

fn control(control: ControlKind, passed: bool) -> ControlResult {
    ControlResult { control, passed }
}

fn diagnostic(code: ExperimentCode, byte_offset: Option<u64>, truncated: bool) -> PublicDiagnostic {
    PublicDiagnostic {
        code,
        byte_offset,
        truncated,
    }
}

fn sanitize(exchanges: &[CapturedExchange]) -> Vec<PublicDiagnostic> {
    const RECOGNIZED: &[u8] = b"NAC_PILOT_ERROR:INPUT_REJECTED";
    let mut diagnostics = vec![diagnostic(ExperimentCode::CaptureIncomplete, None, true)];
    for exchange in exchanges {
        if let Some(offset) = find(&exchange.raw, RECOGNIZED)
            .map(|offset| offset as u64)
            .or_else(|| {
                find(&exchange.tail, RECOGNIZED).map(|offset| {
                    exchange
                        .total
                        .saturating_sub(exchange.tail.len() as u64)
                        .saturating_add(offset as u64)
                })
            })
        {
            diagnostics.push(diagnostic(
                ExperimentCode::RecognizedTargetError,
                Some(offset),
                true,
            ));
        }
    }
    if diagnostics.len() == 1 {
        diagnostics.push(diagnostic(
            ExperimentCode::UnknownOutputWithheld,
            None,
            true,
        ));
    }
    diagnostics
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests;
