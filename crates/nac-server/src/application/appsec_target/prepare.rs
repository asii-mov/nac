use super::{docker, private, process, FrozenPilot};
use anyhow::{ensure, Context, Result};
use nac_appsec::{
    ExperimentProfile, HttpInterface, OracleClass, RecipeBinding, RepositoryInput, SourcePackage,
    TargetIdentity, TargetScope,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct LocalPilotPreparation {
    pub repository: PathBuf,
    pub commit: String,
    pub repository_id: String,
    pub includes: Vec<String>,
    pub interface: HttpInterface,
    pub oracle_class: OracleClass,
    pub output: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPilotArtifacts {
    pub schema_version: u32,
    pub profile: PathBuf,
    pub registry: PathBuf,
    pub builder_image: String,
    pub vulnerable_image: String,
    pub protected_image: String,
}

pub(super) fn prepare(input: LocalPilotPreparation) -> Result<LocalPilotArtifacts> {
    ensure!(
        input.includes == [String::from("main.go")],
        "the local pilot supports one explicitly reviewed main.go include"
    );
    ensure!(
        !input.repository_id.is_empty()
            && input.repository_id.len() <= 64
            && input
                .repository_id
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') }),
        "invalid local pilot repository identity"
    );
    ensure!(
        input.repository.is_absolute(),
        "local pilot repository must be absolute"
    );
    ensure!(!input.output.exists(), "local pilot output must be fresh");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&input.output)?;
    let result = prepare_inner(&input);
    if result.is_err() {
        let _ = std::fs::set_permissions(&input.output, std::fs::Permissions::from_mode(0o755));
    }
    result
}

fn prepare_inner(input: &LocalPilotPreparation) -> Result<LocalPilotArtifacts> {
    let repository = RepositoryInput {
        identity: input.repository_id.clone(),
        checkout: input.repository.clone(),
        commit: input.commit.clone(),
    };
    let includes: Vec<_> = input
        .includes
        .iter()
        .map(|path| (input.repository_id.clone(), path.clone()))
        .collect();
    let package = SourcePackage::freeze(std::slice::from_ref(&repository), &includes, &[])?;
    let export_root = input.output.join("source-package");
    package.export(std::slice::from_ref(&repository), &export_root)?;
    let production_export = export_root.join("main").join(&input.repository_id);
    let private_root = input.output.join("private-build");
    private::directory(&private_root)?;
    let binary = private_root.join("target");
    compile_fixture(&production_export, &binary, &private_root)?;
    let build_sha256 = private::digest(&std::fs::read(&binary)?);
    let suffix =
        &private::digest(format!("{}:{}", input.commit, package.manifest_sha256).as_bytes())[..20];
    let builder_tag = format!("nac-appsec-local-builder:{suffix}");
    let builder_image = build_builder(&private_root, &builder_tag)?;
    let vulnerable_tag = format!("nac-appsec-local-pilot-vulnerable:{suffix}");
    let protected_tag = format!("nac-appsec-local-pilot-protected:{suffix}");
    let vulnerable_image = build_target(&private_root, &binary, &vulnerable_tag, "vulnerable")?;
    let protected_image = build_target(&private_root, &binary, &protected_tag, "protected")?;
    let vulnerable_target = target(&package, &build_sha256, &vulnerable_image, false)?;
    let protected_target = target(&package, &build_sha256, &protected_image, true)?;
    let prefix = match input.oracle_class {
        OracleClass::Authorization => "local-authz",
        OracleClass::RceNonce => "local-rce",
    };
    let vulnerable = binding(
        &format!("{prefix}-vulnerable"),
        input.oracle_class,
        input.interface.clone(),
        package.clone(),
        vulnerable_target.clone(),
        TargetScope::OriginalTarget,
    )?;
    let protected = binding(
        &format!("{prefix}-protected"),
        input.oracle_class,
        input.interface.clone(),
        package.clone(),
        protected_target,
        TargetScope::ReducedDemo {
            original: vulnerable_target,
            tested: package.clone(),
            declared_changes: vec![
                "locally authored protected runtime fixture variant; not an external evaluation adaptation"
                    .into(),
            ],
        },
    )?;
    let profile = ExperimentProfile {
        schema_version: 1,
        package,
        recipes: vec![vulnerable.clone(), protected.clone()],
        dependencies: vec![],
    };
    profile.verify(std::slice::from_ref(&repository))?;
    let pilots = vec![
        pilot(
            &vulnerable,
            false,
            production_export.clone(),
            builder_image.clone(),
        )?,
        pilot(&protected, true, production_export, builder_image.clone())?,
    ];
    let profile_path = input.output.join("experiment-profile.json");
    write_public(&profile_path, &serde_json::to_vec_pretty(&profile)?)?;
    let registry_path = input.output.join("private-pilots.json");
    private::write(&registry_path, &pilots)?;
    ensure!(
        std::fs::metadata(&registry_path)?.permissions().mode() & 0o077 == 0,
        "private pilot registry must be owner-only"
    );
    std::fs::remove_dir_all(&private_root)?;
    Ok(LocalPilotArtifacts {
        schema_version: 1,
        profile: profile_path,
        registry: registry_path,
        builder_image,
        vulnerable_image,
        protected_image,
    })
}

fn compile_fixture(source: &Path, binary: &Path, root: &Path) -> Result<()> {
    let cache = root.join("go-cache");
    private::directory(&cache)?;
    let arguments = [
        OsString::from("--chdir"),
        source.as_os_str().to_owned(),
        OsString::from(format!("HOME={}", root.display())),
        OsString::from(format!("GOCACHE={}", cache.display())),
        OsString::from("GOPROXY=off"),
        OsString::from("GOSUMDB=off"),
        OsString::from("CGO_ENABLED=0"),
        OsString::from("GOOS=linux"),
        OsString::from("GOARCH=amd64"),
        OsString::from("/usr/local/go/bin/go"),
        OsString::from("build"),
        OsString::from("-trimpath"),
        OsString::from("-ldflags=-s -w -buildid="),
        OsString::from("-o"),
        binary.as_os_str().to_owned(),
        OsString::from("main.go"),
    ];
    let output = process::execute("/usr/bin/env", &arguments, vec![], 180_000, 1024 * 1024)?;
    ensure!(
        output.success && output.complete,
        "local pilot compilation failed"
    );
    std::fs::remove_dir_all(cache)?;
    Ok(())
}

fn build_builder(root: &Path, tag: &str) -> Result<String> {
    let archive = root.join("builder.tar");
    let output = process::execute(
        "/usr/bin/tar",
        &[
            OsString::from("-C"),
            OsString::from("/"),
            OsString::from("-cf"),
            archive.as_os_str().to_owned(),
            OsString::from("usr/local/go"),
        ],
        vec![],
        180_000,
        4096,
    )?;
    ensure!(
        output.success && output.complete,
        "local builder archive failed"
    );
    process::docker_bounded(
        &[
            "import",
            "--change",
            "LABEL nac.appsec.local-builder=v1",
            archive
                .to_str()
                .context("builder archive path is not UTF-8")?,
            tag,
        ],
        180_000,
    )?;
    std::fs::remove_file(archive)?;
    let inspected = docker::inspect(tag)?;
    ensure!(
        inspected["Config"]["Labels"]["nac.appsec.local-builder"] == "v1",
        "local builder label drift"
    );
    image_id(&inspected)
}

fn build_target(root: &Path, binary: &Path, tag: &str, variant: &str) -> Result<String> {
    let context = root.join(variant);
    private::directory(&context)?;
    std::fs::copy(binary, context.join("target"))?;
    std::fs::write(
        context.join("Dockerfile"),
        format!(
            "FROM scratch\nLABEL nac.appsec.local-pilot=\"v1\"\nLABEL nac.appsec.variant=\"{variant}\"\nCOPY target /target\nUSER 65534:65534\nWORKDIR /\nENTRYPOINT [\"/target\"]\n"
        ),
    )?;
    let output = process::execute(
        "/usr/bin/env",
        &[
            OsString::from(format!("HOME={}", root.display())),
            OsString::from("/usr/bin/docker"),
            OsString::from("build"),
            OsString::from("--network"),
            OsString::from("none"),
            OsString::from("--no-cache"),
            OsString::from("--provenance=false"),
            OsString::from("--tag"),
            OsString::from(tag),
            context.as_os_str().to_owned(),
        ],
        vec![],
        180_000,
        1024 * 1024,
    )?;
    ensure!(
        output.success && output.complete,
        "local target image build failed"
    );
    let inspected = docker::inspect(tag)?;
    ensure!(
        inspected["Config"]["Labels"]["nac.appsec.local-pilot"] == "v1"
            && inspected["Config"]["Labels"]["nac.appsec.variant"] == variant,
        "local target image label drift"
    );
    image_id(&inspected)
}

fn image_id(inspected: &serde_json::Value) -> Result<String> {
    let image = inspected["Id"]
        .as_str()
        .context("local image identity unavailable")?;
    ensure!(
        image.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "invalid local image identity"
    );
    Ok(image.into())
}

fn target(
    package: &SourcePackage,
    build_sha256: &str,
    image: &str,
    protected: bool,
) -> Result<TargetIdentity> {
    Ok(TargetIdentity {
        source_sha256: package.manifest_sha256.clone(),
        build_sha256: build_sha256.into(),
        image_sha256: image
            .strip_prefix("sha256:")
            .context("local image identity malformed")?
            .into(),
        environment_sha256: FrozenPilot::effective_environment_sha256(protected)?,
    })
}

fn binding(
    id: &str,
    oracle_class: OracleClass,
    interface: HttpInterface,
    production: SourcePackage,
    target: TargetIdentity,
    scope: TargetScope,
) -> Result<RecipeBinding> {
    let mut recipe = RecipeBinding {
        id: id.into(),
        recipe_sha256: String::new(),
        target,
        scope,
        oracle_class,
        interface,
        production,
        repetitions: 1,
        operation_ms: 5_000,
        capture_bytes: 262_144,
    };
    recipe.recipe_sha256 = recipe.canonical_sha256()?;
    Ok(recipe)
}

fn pilot(
    recipe: &RecipeBinding,
    protected: bool,
    production_export: PathBuf,
    builder_image: String,
) -> Result<FrozenPilot> {
    let (evaluator, rubric) = match recipe.oracle_class {
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
        id: recipe.id.clone(),
        recipe_sha256: recipe.recipe_sha256.clone(),
        target: recipe.target.clone(),
        image: format!("sha256:{}", recipe.target.image_sha256),
        source_export_sha256: recipe.production.manifest_sha256.clone(),
        build_receipt_sha256: recipe.target.build_sha256.clone(),
        builder_image,
        environment_sha256: recipe.target.environment_sha256.clone(),
        evaluator: evaluator.into(),
        rubric: rubric.into(),
        protected,
        private_sha256: String::new(),
        production_export,
    };
    pilot.private_sha256 = pilot.canonical_sha256()?;
    Ok(pilot)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
