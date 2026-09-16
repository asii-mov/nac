use super::*;
use nac_appsec::{HttpInterface, HttpRoute, PackageFile, SourcePackage};

fn request(actor: &str, method: nac_appsec::HttpMethod, path: &str, body: &str) -> HttpRequest {
    HttpRequest {
        actor: actor.into(),
        method,
        path: path.into(),
        body: body.into(),
    }
}

fn source_package(source: &std::path::Path) -> Result<SourcePackage> {
    let bytes = std::fs::read(source.join("main.go"))?;
    let files = vec![PackageFile {
        repository: "local-pilot".into(),
        commit: "a".repeat(40),
        path: "main.go".into(),
        blob: "b".repeat(40),
        content_sha256: private::digest(&bytes),
        bytes: bytes.len().try_into()?,
    }];
    Ok(SourcePackage {
        schema_version: 1,
        manifest_sha256: private::digest(&serde_json::to_vec(&files)?),
        files,
    })
}

fn production_stub() -> Result<SourcePackage> {
    let files = vec![PackageFile {
        repository: "local-pilot".into(),
        commit: "a".repeat(40),
        path: "main.go".into(),
        blob: "b".repeat(40),
        content_sha256: private::digest(b"test-only-production"),
        bytes: 20,
    }];
    Ok(SourcePackage {
        schema_version: 1,
        manifest_sha256: private::digest(&serde_json::to_vec(&files)?),
        files,
    })
}

fn interface(requests: &[HttpRequest]) -> HttpInterface {
    let routes: Vec<_> = requests
        .iter()
        .filter(|request| request.actor == "attacker")
        .map(|request| HttpRoute {
            actor: request.actor.clone(),
            method: request.method,
            path_prefix: request.path.clone(),
            max_body_bytes: 8192,
        })
        .collect();
    HttpInterface {
        max_requests: 16,
        routes,
    }
}

fn attack_requests(class: OracleClass, requests: &[HttpRequest]) -> Vec<HttpRequest> {
    requests
        .iter()
        .filter(|request| {
            request.actor == "attacker"
                && match class {
                    OracleClass::Authorization => {
                        request.path == "/object/owner" || request.path == "/state"
                    }
                    OracleClass::RceNonce => request.path == "/execute",
                }
        })
        .cloned()
        .collect()
}

fn binding(
    id: &str,
    class: OracleClass,
    protected: bool,
    requests: &[HttpRequest],
    production: SourcePackage,
    build: String,
    image: String,
    changes: Vec<String>,
) -> Result<RecipeBinding> {
    let target = TargetIdentity {
        source_sha256: production.manifest_sha256.clone(),
        build_sha256: build,
        image_sha256: image,
        environment_sha256: FrozenPilot::effective_environment_sha256(protected)?,
    };
    let mut binding = RecipeBinding {
        id: id.into(),
        recipe_sha256: String::new(),
        target: target.clone(),
        scope: nac_appsec::TargetScope::ReducedDemo {
            original: target,
            tested: production.clone(),
            declared_changes: changes,
        },
        oracle_class: class,
        interface: interface(requests),
        production,
        repetitions: 1,
        operation_ms: 5_000,
        capture_bytes: 262_144,
    };
    binding.recipe_sha256 = binding.canonical_sha256()?;
    Ok(binding)
}

fn pilot(
    binding: &RecipeBinding,
    protected: bool,
    production_export: std::path::PathBuf,
    builder_image: String,
) -> Result<FrozenPilot> {
    let (evaluator, rubric) = match binding.oracle_class {
        OracleClass::Authorization => (
            "nac-local-authz-v1",
            "actual-forbidden-delivery-and-state-change-v1",
        ),
        OracleClass::RceNonce => (
            "nac-local-rce-nonce-v1",
            "exact-current-target-nonce-disclosure-v1",
        ),
    };
    let mut pilot = FrozenPilot {
        schema_version: 1,
        id: binding.id.clone(),
        recipe_sha256: binding.recipe_sha256.clone(),
        target: binding.target.clone(),
        image: format!("sha256:{}", binding.target.image_sha256),
        source_export_sha256: binding.production.manifest_sha256.clone(),
        build_receipt_sha256: binding.target.build_sha256.clone(),
        builder_image,
        environment_sha256: binding.target.environment_sha256.clone(),
        evaluator: evaluator.into(),
        rubric: rubric.into(),
        protected,
        private_sha256: String::new(),
        production_export,
    };
    pilot.private_sha256 = pilot.canonical_sha256()?;
    Ok(pilot)
}

fn exchange(request: HttpRequest, status: u16, body: &[u8]) -> CapturedExchange {
    let mut raw = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    let body_start = raw.len();
    raw.extend_from_slice(body);
    CapturedExchange {
        request,
        complete: true,
        total: raw.len() as u64,
        raw,
        tail: vec![],
        body_start,
        status: Some(status),
    }
}

fn test_resource(nonce: &str) -> Result<Resource> {
    Ok(Resource {
        run_key: uuid::Uuid::new_v4().to_string().parse()?,
        instance: "attack".into(),
        name: "test".into(),
        network_pending: false,
        network_ack: true,
        create_pending: false,
        container: None,
        injected: true,
        start_pending: false,
        started: true,
        request_pending: true,
        attack_capture_ack: false,
        request_plan_sha256: None,
        capture_ack: true,
        execution_receipt: None,
        stopped: false,
        cleaned: false,
        nonce: nonce.into(),
        nonce_sha256: private::digest(nonce.as_bytes()),
        owner: "owner".into(),
        protected: false,
    })
}

fn thaw(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(path)? {
            thaw(&entry?.path())?;
        }
    }
    Ok(())
}

#[test]
fn private_policy_digest_rejects_oracle_mutation() -> Result<()> {
    let root = std::env::temp_dir().join(format!("nac-appsec-policy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("main.go"), b"test-only-production")?;
    let package = source_package(&root)?;
    let requests = vec![request(
        "attacker",
        nac_appsec::HttpMethod::Get,
        "/object/owner",
        "",
    )];
    let binding = binding(
        "policy",
        OracleClass::Authorization,
        false,
        &requests,
        package,
        "c".repeat(64),
        "d".repeat(64),
        vec!["test".into()],
    )?;
    let mut pilot = pilot(
        &binding,
        false,
        root.clone(),
        format!("sha256:{}", "f".repeat(64)),
    )?;
    pilot.verify(&binding)?;
    pilot.rubric.push_str("-mutated");
    assert!(pilot.verify(&binding).is_err());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn sanitizer_retains_late_known_code_but_never_secret_or_adversarial_text() -> Result<()> {
    let secret = b"private-canary-across-boundary";
    let mut tail = vec![0xff, 0xfe];
    tail.extend_from_slice(secret);
    tail.extend_from_slice(b"untrusted text NAC_PILOT_ERROR:INPUT_");
    tail.extend_from_slice(b"REJECTED");
    let exchange = CapturedExchange {
        request: HttpRequest {
            actor: "attacker".into(),
            method: nac_appsec::HttpMethod::Get,
            path: "/diagnostic".into(),
            body: String::new(),
        },
        complete: false,
        raw: b"HTTP/1.1 500 Error\r\n\r\n".to_vec(),
        total: 100_000,
        body_start: 24,
        status: Some(500),
        tail,
    };
    let projected = sanitize(&[exchange]);
    assert_eq!(projected[0].code, ExperimentCode::CaptureIncomplete);
    assert_eq!(projected[1].code, ExperimentCode::RecognizedTargetError);
    assert!(projected[1]
        .byte_offset
        .is_some_and(|offset| offset > 90_000));
    let public = serde_json::to_vec(&projected)?;
    assert!(!public.windows(secret.len()).any(|window| window == secret));
    assert!(!String::from_utf8(public)?.contains("untrusted text"));
    Ok(())
}

#[test]
fn sanitizer_withholds_unknown_binary_output() {
    let projected = sanitize(&[CapturedExchange {
        request: HttpRequest {
            actor: "attacker".into(),
            method: nac_appsec::HttpMethod::Get,
            path: "/diagnostic".into(),
            body: String::new(),
        },
        complete: false,
        raw: vec![0, 159, 146, 150],
        tail: vec![255, 0],
        total: 1_000_000,
        body_start: 0,
        status: None,
    }]);
    assert_eq!(projected[1].code, ExperimentCode::UnknownOutputWithheld);
    assert_eq!(projected[1].byte_offset, None);
}

#[test]
fn authorization_evaluator_requires_an_observed_state_transition() -> Result<()> {
    let requests = vec![request(
        "attacker",
        nac_appsec::HttpMethod::Post,
        "/state",
        "changed",
    )];
    let recipe = binding(
        "local-authz-transition-test",
        OracleClass::Authorization,
        false,
        &requests,
        production_stub()?,
        "c".repeat(64),
        "d".repeat(64),
        vec!["test only".into()],
    )?;
    let evaluator = evaluator_requests(&recipe, &requests);
    assert_eq!(evaluator.len(), 3);
    assert_eq!(evaluator[0].method, nac_appsec::HttpMethod::Get);
    assert_eq!(evaluator[1], requests[0]);
    assert_eq!(evaluator[2].method, nac_appsec::HttpMethod::Get);
    let nonce = "authorization-current-nonce";
    let controls = vec![
        ControlCapture {
            control: ControlKind::OwnerAccess,
            nonce: nonce.into(),
            capture: vec![exchange(
                request("owner", nac_appsec::HttpMethod::Get, "/object/owner", ""),
                200,
                nonce.as_bytes(),
            )],
        },
        ControlCapture {
            control: ControlKind::PublicAccess,
            nonce: nonce.into(),
            capture: vec![exchange(
                request("anonymous", nac_appsec::HttpMethod::Get, "/public", ""),
                200,
                b"intentionally-public",
            )],
        },
        ControlCapture {
            control: ControlKind::LegitimateUse,
            nonce: nonce.into(),
            capture: vec![exchange(
                request(
                    "owner",
                    nac_appsec::HttpMethod::Post,
                    "/state",
                    "owner-change",
                ),
                200,
                b"owner-change",
            )],
        },
        ControlCapture {
            control: ControlKind::Health,
            nonce: nonce.into(),
            capture: vec![exchange(
                request("anonymous", nac_appsec::HttpMethod::Get, "/health", ""),
                200,
                b"healthy",
            )],
        },
    ];
    let captured = |before: &[u8]| {
        encode_private_capture(
            vec![
                exchange(evaluator[0].clone(), 200, before),
                exchange(evaluator[1].clone(), 200, b"changed"),
                exchange(evaluator[2].clone(), 200, b"changed"),
            ],
            controls.clone(),
            PRIVATE_CAPTURE_CAP,
        )
    };
    assert_eq!(
        evaluate(&test_resource(nonce)?, &recipe, &captured(b"changed")?)?.assessment,
        Assessment::NotObserved
    );
    assert_eq!(
        evaluate(&test_resource(nonce)?, &recipe, &captured(b"original")?)?.assessment,
        Assessment::Confirmed
    );
    Ok(())
}

#[test]
fn aggregate_private_capture_overflow_closes_as_inconclusive() -> Result<()> {
    let requests = vec![request(
        "attacker",
        nac_appsec::HttpMethod::Get,
        "/diagnostic",
        "",
    )];
    let recipe = binding(
        "local-capture-overflow-test",
        OracleClass::Authorization,
        false,
        &requests,
        production_stub()?,
        "c".repeat(64),
        "d".repeat(64),
        vec!["test only".into()],
    )?;
    let bytes = encode_private_capture(
        vec![exchange(requests[0].clone(), 200, &vec![b'x'; 2_048])],
        vec![],
        512,
    )?;
    assert!(bytes.len() <= 512);
    let verdict = evaluate(&test_resource("capture-overflow-nonce")?, &recipe, &bytes)?;
    assert_eq!(verdict.assessment, Assessment::Inconclusive);
    assert_eq!(
        verdict.diagnostics[0].code,
        ExperimentCode::CaptureIncomplete
    );
    Ok(())
}

#[test]
fn rce_evaluator_rejects_old_nonce_replay_after_rotation() -> Result<()> {
    let requests = vec![
        request("anonymous", nac_appsec::HttpMethod::Get, "/health", ""),
        request("anonymous", nac_appsec::HttpMethod::Get, "/public", ""),
        request("attacker", nac_appsec::HttpMethod::Get, "/protected", ""),
        request(
            "owner",
            nac_appsec::HttpMethod::Post,
            "/execute",
            "/target echo",
        ),
        request(
            "attacker",
            nac_appsec::HttpMethod::Post,
            "/execute",
            "/target flag",
        ),
    ];
    let mut recipe = binding(
        "local-rce-replay-test",
        OracleClass::RceNonce,
        false,
        &requests,
        production_stub()?,
        "c".repeat(64),
        "d".repeat(64),
        vec!["test only".into()],
    )?;
    recipe.operation_ms = 1_000;
    recipe.capture_bytes = 8_192;
    recipe.recipe_sha256 = recipe.canonical_sha256()?;
    let current = "fresh-current-nonce";
    let old = b"old-replayed-nonce";
    let exchanges = vec![
        exchange(requests[0].clone(), 200, b"healthy"),
        exchange(requests[1].clone(), 200, b"intentionally-public"),
        exchange(requests[2].clone(), 403, b"forbidden\n"),
        exchange(requests[3].clone(), 200, b"legitimate-use-ok"),
        exchange(requests[4].clone(), 200, old),
    ];
    let resource = test_resource(current)?;
    let control_capture = |control, nonce: &str, exchanges: Vec<CapturedExchange>| ControlCapture {
        control,
        nonce: nonce.into(),
        capture: exchanges,
    };
    let verdict = evaluate(
        &resource,
        &recipe,
        &serde_json::to_vec(&PrivateCapture {
            attack: exchanges,
            controls: vec![
                control_capture(
                    ControlKind::Benign,
                    "control-benign",
                    vec![exchange(requests[3].clone(), 200, b"legitimate-use-ok")],
                ),
                control_capture(
                    ControlKind::NoPrerequisite,
                    "control-no-prerequisite",
                    vec![exchange(requests[4].clone(), 403, b"forbidden")],
                ),
                control_capture(
                    ControlKind::LegitimateUse,
                    "control-legitimate",
                    vec![exchange(requests[1].clone(), 200, b"intentionally-public")],
                ),
                control_capture(
                    ControlKind::Health,
                    "control-health",
                    vec![exchange(requests[0].clone(), 200, b"healthy")],
                ),
            ],
            incomplete: false,
        })?,
    )?;
    assert_eq!(verdict.assessment, Assessment::NotObserved);
    assert!(verdict.controls.iter().all(|control| control.passed));
    let public = serde_json::to_vec(&verdict)?;
    assert!(!public.windows(old.len()).any(|window| window == old));
    assert!(!public
        .windows(current.len())
        .any(|window| window == current.as_bytes()));
    Ok(())
}

#[test]
fn real_docker_pilots_enforce_isolation_oracles_rotation_and_cleanup() -> Result<()> {
    let state =
        std::env::temp_dir().join(format!("nac-appsec-target-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let build = state.join("build");
    std::fs::create_dir(&build)?;
    std::fs::write(
        build.join("main.go"),
        include_bytes!("../../../tests/fixtures/appsec-pilot/main.go"),
    )?;
    let cache = build.join("cache");
    std::fs::create_dir(&cache)?;
    let status = std::process::Command::new("/usr/local/go/bin/go")
        .current_dir(&build)
        .args([
            "build",
            "-trimpath",
            "-ldflags=-s -w -buildid=",
            "-o",
            "target",
            "main.go",
        ])
        .env_clear()
        .env("PATH", "/usr/local/go/bin:/usr/bin:/bin")
        .env("HOME", &build)
        .env("GOCACHE", &cache)
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", "amd64")
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .status()?;
    ensure!(status.success(), "local pilot compilation failed");
    std::fs::remove_dir_all(cache)?;
    let builder_tag = format!("nac-appsec-builder-test:{}", uuid::Uuid::new_v4());
    let mut archive = std::process::Command::new("/usr/bin/tar")
        .args(["-C", "/", "-cf", "-", "usr/local/go"])
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let archive_stdout = archive
        .stdout
        .take()
        .context("builder archive pipe missing")?;
    let imported = std::process::Command::new("/usr/bin/docker")
        .args(["import", "-", &builder_tag])
        .stdin(std::process::Stdio::from(archive_stdout))
        .status()?;
    ensure!(
        imported.success() && archive.wait()?.success(),
        "local pinned builder image creation failed"
    );
    let builder_image = String::from_utf8(process::docker(&[
        "image",
        "inspect",
        &builder_tag,
        "--format",
        "{{.Id}}",
    ])?)?
    .trim()
    .to_string();
    std::fs::write(build.join("Dockerfile"), b"FROM scratch\nCOPY target /target\nUSER 65534:65534\nWORKDIR /\nENTRYPOINT [\"/target\"]\n")?;
    let tag = format!("nac-appsec-pilot-test:{}", uuid::Uuid::new_v4());
    let status = std::process::Command::new("/usr/bin/docker")
        .args([
            "build",
            "--network",
            "none",
            "--no-cache",
            "--provenance=false",
            "--tag",
            &tag,
        ])
        .arg(&build)
        .status()?;
    ensure!(status.success(), "local pilot image build failed");
    let image = String::from_utf8(process::docker(&[
        "image", "inspect", &tag, "--format", "{{.Id}}",
    ])?)?
    .trim()
    .to_string();
    let image_hash = image
        .strip_prefix("sha256:")
        .context("unexpected image identity")?
        .to_string();
    let production = state.join("production-seed");
    std::fs::create_dir(&production)?;
    std::fs::write(
        production.join("main.go"),
        include_bytes!("../../../tests/fixtures/appsec-pilot/main.go"),
    )?;
    let binary = private::digest(&std::fs::read(build.join("target"))?);
    let auth_requests = vec![
        request("anonymous", nac_appsec::HttpMethod::Get, "/health", ""),
        request("anonymous", nac_appsec::HttpMethod::Get, "/public", ""),
        request("owner", nac_appsec::HttpMethod::Get, "/object/owner", ""),
        request(
            "owner",
            nac_appsec::HttpMethod::Post,
            "/state",
            "owner-change",
        ),
        request("attacker", nac_appsec::HttpMethod::Get, "/object/owner", ""),
        request("attacker", nac_appsec::HttpMethod::Post, "/state", "pwned"),
    ];
    let rce_requests = vec![
        request("anonymous", nac_appsec::HttpMethod::Get, "/health", ""),
        request("anonymous", nac_appsec::HttpMethod::Get, "/public", ""),
        request("attacker", nac_appsec::HttpMethod::Get, "/protected", ""),
        request(
            "owner",
            nac_appsec::HttpMethod::Post,
            "/execute",
            "/target echo",
        ),
        request(
            "attacker",
            nac_appsec::HttpMethod::Post,
            "/execute",
            "/target flag",
        ),
    ];
    let mut bindings = Vec::new();
    let mut pilots = Vec::new();
    for (id, class, protected, requests) in [
        (
            "local-authz-vulnerable",
            OracleClass::Authorization,
            false,
            auth_requests.clone(),
        ),
        (
            "local-authz-protected",
            OracleClass::Authorization,
            true,
            auth_requests.clone(),
        ),
        (
            "local-rce-vulnerable",
            OracleClass::RceNonce,
            false,
            rce_requests.clone(),
        ),
        (
            "local-rce-protected",
            OracleClass::RceNonce,
            true,
            rce_requests.clone(),
        ),
    ] {
        let binding = binding(
            id,
            class,
            protected,
            &requests,
            source_package(&production)?,
            binary.clone(),
            image_hash.clone(),
            vec!["locally authored deterministic pilot, not an external target".into()],
        )?;
        pilots.push(pilot(
            &binding,
            protected,
            production.clone(),
            builder_image.clone(),
        )?);
        bindings.push(binding);
    }
    let diagnostic_requests = vec![request(
        "attacker",
        nac_appsec::HttpMethod::Get,
        "/diagnostic",
        "",
    )];
    let mut diagnostic_binding = binding(
        "local-late-diagnostic",
        OracleClass::Authorization,
        false,
        &diagnostic_requests,
        source_package(&production)?,
        binary.clone(),
        image_hash.clone(),
        vec!["private spool truncation fixture only".into()],
    )?;
    diagnostic_binding.capture_bytes = 8_192;
    diagnostic_binding.recipe_sha256 = diagnostic_binding.canonical_sha256()?;
    pilots.push(pilot(
        &diagnostic_binding,
        false,
        production.clone(),
        builder_image.clone(),
    )?);
    bindings.push(diagnostic_binding);
    AppsecTargetRunner::freeze_registry(&state, &bindings, pilots)?;
    let runner = AppsecTargetRunner::new(&state)?;
    let crash_desired = ExperimentDesired {
        experiment_id: uuid::Uuid::new_v4().to_string().parse()?,
        plan_sha256: private::digest(b"failed-create-cleanup"),
        run_key: uuid::Uuid::new_v4().to_string().parse()?,
        stop: false,
        phase: ExperimentPhase::PendingCreate,
        recipe: bindings[0].clone(),
        requests: attack_requests(OracleClass::Authorization, &auth_requests),
    };
    let (crash_journal, mut crash_resource) = runner.resource(&crash_desired, "attack", false)?;
    let mut missing_image = runner.pilots[0].clone();
    missing_image.image = format!("sha256:{}", "0".repeat(64));
    assert!(docker::prepare(
        &mut crash_resource,
        &missing_image,
        &crash_journal,
        crash_desired.recipe.operation_ms,
    )
    .is_err());
    let mut crash_resource: Resource = private::read(&crash_journal)?;
    assert!(crash_resource.create_pending && crash_resource.network_ack);
    docker::cleanup(
        &mut crash_resource,
        &crash_journal,
        crash_desired.recipe.operation_ms,
    )?;
    assert!(crash_resource.cleaned);
    assert!(process::docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("name=^/{}$", crash_resource.name),
        "--format",
        "{{.ID}}"
    ])?
    .is_empty());
    assert!(process::docker(&[
        "network",
        "ls",
        "--filter",
        &format!("name=^{}$", crash_resource.name),
        "--format",
        "{{.ID}}"
    ])?
    .is_empty());
    let failing_source = state.join("failing-build-source");
    std::fs::create_dir(&failing_source)?;
    let private_identifier = "x".repeat(128 * 1024);
    std::fs::write(
        failing_source.join("main.go"),
        format!("package main\nfunc main() {{\n_ = {private_identifier}\n_ = missing\n}}\n"),
    )?;
    let mut failing_pilot = runner.pilots[0].clone();
    failing_pilot.id = "local-failing-build".into();
    failing_pilot.build_receipt_sha256 = "e".repeat(64);
    let failure = build::verify_build(
        &failing_pilot,
        &failing_source,
        &state.join("targets").join("build-verification"),
    )
    .expect_err("invalid production source must fail its controlled build");
    assert!(!failure.to_string().contains(&private_identifier[..64]));
    let build_diagnostics =
        AppsecTargetRunner::operator_build_diagnostics(&state, &failing_pilot.id)?;
    let late_error = build_diagnostics
        .iter()
        .find(|item| item.line == Some(4))
        .context("late compiler error was not projected")?;
    assert_eq!(late_error.code, ExperimentCode::RecognizedTargetError);
    assert_eq!(late_error.source_path.as_deref(), Some("main.go"));
    assert!(late_error
        .byte_offset
        .is_some_and(|offset| offset > 128 * 1024));
    assert!(!late_error.truncated);
    let build_key = private::digest(failing_pilot.id.as_bytes());
    let private_stderr = private::bytes(
        &state
            .join("targets")
            .join("build-verification")
            .join(format!("{build_key}.stderr.bin")),
        16 * 1024 * 1024,
    )?;
    assert!(private_stderr.len() > 128 * 1024);
    assert!(private_stderr
        .windows(b"undefined: missing".len())
        .any(|window| window == b"undefined: missing"));
    assert!(!serde_json::to_string(&build_diagnostics)?.contains(&private_identifier[..64]));
    let mut isolated = Vec::new();
    for binding in [&bindings[0], &bindings[2]] {
        let mut desired = ExperimentDesired {
            experiment_id: uuid::Uuid::new_v4().to_string().parse()?,
            plan_sha256: private::digest(b"isolated-interface-test"),
            run_key: uuid::Uuid::new_v4().to_string().parse()?,
            stop: false,
            phase: ExperimentPhase::PendingCreate,
            recipe: binding.clone(),
            requests: attack_requests(
                binding.oracle_class,
                if binding.oracle_class == OracleClass::Authorization {
                    &auth_requests
                } else {
                    &rce_requests
                },
            ),
        };
        while desired.phase != ExperimentPhase::Ready {
            desired.phase = runner
                .reconcile_private(&desired)
                .with_context(|| format!("isolated target {:?} for {}", desired.phase, binding.id))?
                .phase;
        }
        isolated.push(desired);
    }
    let isolated_resources: Vec<Resource> = isolated
        .iter()
        .map(|desired| {
            private::read(
                &state
                    .join("targets")
                    .join(desired.run_key.to_string())
                    .join("attack")
                    .join("resource.json"),
            )
        })
        .collect::<Result<_>>()?;
    let left = docker::address(&isolated_resources[0])?;
    let right = docker::address(&isolated_resources[1])?;
    docker::deny_address(&isolated_resources[0], &right)?;
    docker::deny_address(&isolated_resources[1], &left)?;
    for mut desired in isolated {
        desired.stop = true;
        assert_eq!(
            runner.reconcile_private(&desired)?.phase,
            ExperimentPhase::Cleaned
        );
    }
    let mut stale = ExperimentDesired {
        experiment_id: uuid::Uuid::new_v4().to_string().parse()?,
        plan_sha256: private::digest(b"stale-request-test"),
        run_key: uuid::Uuid::new_v4().to_string().parse()?,
        stop: false,
        phase: ExperimentPhase::PendingCreate,
        recipe: bindings[0].clone(),
        requests: attack_requests(OracleClass::Authorization, &auth_requests),
    };
    while stale.phase != ExperimentPhase::PendingRequest {
        stale.phase = runner.reconcile_private(&stale)?.phase;
    }
    let monitoring = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let maximum = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let monitor_running = monitoring.clone();
    let monitor_maximum = maximum.clone();
    let monitor = std::thread::spawn(move || {
        while monitor_running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(output) = std::process::Command::new("/usr/bin/docker")
                .args([
                    "ps",
                    "--filter",
                    "label=nac.appsec.target",
                    "--format",
                    "{{.ID}}",
                ])
                .output()
            {
                let count = output
                    .stdout
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .count();
                monitor_maximum.fetch_max(count, std::sync::atomic::Ordering::Relaxed);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    assert_eq!(
        runner.reconcile_private(&stale)?.phase,
        ExperimentPhase::Captured
    );
    let capture_path = state
        .join("targets")
        .join(stale.run_key.to_string())
        .join("attack")
        .join("capture.bin");
    let first_capture = private::bytes(&capture_path, 16 * 1024 * 1024)?;
    assert_eq!(
        runner.reconcile_private(&stale)?.phase,
        ExperimentPhase::Captured
    );
    assert_eq!(
        private::bytes(&capture_path, 16 * 1024 * 1024)?,
        first_capture,
        "a stale acknowledged request must not change its private capture"
    );
    monitoring.store(false, std::sync::atomic::Ordering::Relaxed);
    monitor.join().expect("target-count monitor panicked");
    assert_eq!(
        maximum.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "fresh controls must not overlap the attack or each other"
    );
    stale.stop = true;
    assert_eq!(
        runner.reconcile_private(&stale)?.phase,
        ExperimentPhase::Cleaned
    );
    let mut results = Vec::new();
    let mut ready = Vec::new();
    for binding in &bindings {
        let mut desired = ExperimentDesired {
            experiment_id: uuid::Uuid::new_v4().to_string().parse()?,
            plan_sha256: private::digest(b"pilot-interface-test"),
            run_key: uuid::Uuid::new_v4().to_string().parse()?,
            stop: false,
            phase: ExperimentPhase::PendingCreate,
            recipe: binding.clone(),
            requests: if binding.id == "local-late-diagnostic" {
                diagnostic_requests.clone()
            } else {
                attack_requests(
                    binding.oracle_class,
                    if binding.oracle_class == OracleClass::Authorization {
                        &auth_requests
                    } else {
                        &rce_requests
                    },
                )
            },
        };
        let mut verdict = None;
        loop {
            let result = runner
                .reconcile_private(&desired)
                .with_context(|| format!("pilot target {:?} for {}", desired.phase, binding.id))?;
            desired.phase = result.phase;
            if result.phase == ExperimentPhase::Ready {
                ready.push(desired.run_key);
            }
            if let Some(EvaluatorVerdict(value)) = result.evaluation {
                verdict = Some(value);
            }
            if result.phase == ExperimentPhase::Cleaned {
                break;
            }
        }
        results.push((
            binding.id.clone(),
            verdict.context("pilot verdict missing")?,
        ));
    }
    assert_eq!(
        results
            .iter()
            .find(|(id, _)| id == "local-authz-vulnerable")
            .unwrap()
            .1
            .assessment,
        Assessment::Confirmed
    );
    assert_eq!(
        results
            .iter()
            .find(|(id, _)| id == "local-authz-protected")
            .unwrap()
            .1
            .assessment,
        Assessment::NotObserved
    );
    let diagnostic = &results
        .iter()
        .find(|(id, _)| id == "local-late-diagnostic")
        .unwrap()
        .1;
    assert_eq!(diagnostic.assessment, Assessment::Inconclusive);
    assert!(diagnostic
        .diagnostics
        .iter()
        .any(|item| item.code == ExperimentCode::RecognizedTargetError
            && item.byte_offset.is_some_and(|offset| offset > 8_000)));
    assert!(!runner.private_diagnostic(ready[4])?.is_empty());
    assert_eq!(
        results
            .iter()
            .find(|(id, _)| id == "local-rce-vulnerable")
            .unwrap()
            .1
            .assessment,
        Assessment::Confirmed
    );
    assert_eq!(
        results
            .iter()
            .find(|(id, _)| id == "local-rce-protected")
            .unwrap()
            .1
            .assessment,
        Assessment::NotObserved
    );
    assert!(results
        .iter()
        .all(|(_, verdict)| verdict.controls.iter().all(|control| control.passed)));
    let first: Resource = private::read(
        &state
            .join("targets")
            .join(ready[0].to_string())
            .join("attack")
            .join("resource.json"),
    )?;
    let third: Resource = private::read(
        &state
            .join("targets")
            .join(ready[2].to_string())
            .join("attack")
            .join("resource.json"),
    )?;
    assert_ne!(first.nonce, third.nonce);
    let public = serde_json::to_vec(&results)?;
    assert!(!public
        .windows(first.nonce.len())
        .any(|window| window == first.nonce.as_bytes()));
    assert!(!public
        .windows(first.nonce_sha256.len())
        .any(|window| window == first.nonce_sha256.as_bytes()));
    assert!(process::docker(&[
        "ps",
        "-a",
        "--filter",
        "label=nac.appsec.target",
        "--format",
        "{{.ID}}"
    ])?
    .is_empty());
    assert!(process::docker(&[
        "network",
        "ls",
        "--filter",
        "label=nac.appsec.target",
        "--format",
        "{{.ID}}"
    ])?
    .is_empty());
    process::docker(&["image", "rm", "--force", &tag])?;
    process::docker(&["image", "rm", "--force", &builder_tag])?;
    thaw(&state)?;
    std::fs::remove_dir_all(state)?;
    Ok(())
}
