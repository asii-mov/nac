use super::*;
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FakeBackend {
    backend_identity: Vec<u8>,
    mount_identity: Vec<u8>,
    invocations: AtomicUsize,
}

impl FakeBackend {
    fn new(backend_identity: &str, mount_identity: &str) -> Self {
        Self {
            backend_identity: backend_identity.as_bytes().to_vec(),
            mount_identity: mount_identity.as_bytes().to_vec(),
            invocations: AtomicUsize::new(0),
        }
    }
}

impl ConfinedCodingBackend for FakeBackend {
    fn backend_identity(&self) -> &[u8] {
        &self.backend_identity
    }
    fn mount_identity(&self) -> &[u8] {
        &self.mount_identity
    }
    fn command(
        &self,
        _workspace: &Path,
        _program: &str,
        _args: &[String],
        _environment: &BTreeMap<String, String>,
    ) -> Result<Command> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Command::new("true"))
    }
}

fn test_policy() -> ControlledCodingPolicy {
    ControlledCodingPolicy {
        editable_roots: vec!["internal/service".to_string()],
        required_production_path: "internal/service/handler.go".to_string(),
        go_check: ControlledGoCheck {
            args: vec!["vet".to_string(), "./...".to_string()],
        },
        environment: BTreeMap::new(),
        limits: ControlledCodingLimits {
            operation_timeout: Duration::from_secs(5),
            max_output_bytes: 4096,
            max_read_bytes: 4096,
            max_files: 16,
            max_patch_bytes: 4096,
        },
    }
}

fn test_files() -> Vec<ControlledSourceFile> {
    vec![
        ControlledSourceFile {
            path: "internal/service/handler.go".to_string(),
            bytes: b"package service\n".to_vec(),
            mode: 0o644,
        },
        ControlledSourceFile {
            path: "internal/service/helper.go".to_string(),
            bytes: b"package service\n\nfunc helper() {}\n".to_vec(),
            mode: 0o644,
        },
    ]
}

fn owner_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "nac-controlled-coding-test-{name}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn materialize(owner: &Path, backend: FakeBackend) -> ControlledCodingFacade {
    ControlledCodingFacade::materialize(owner, test_files(), test_policy(), Arc::new(backend))
        .unwrap()
}

#[test]
fn forbidden_path_flags_git_vendor_tests_module_files_and_generated_code() {
    assert!(forbidden_path(".git/config"));
    assert!(forbidden_path("vendor/pkg/pkg.go"));
    assert!(forbidden_path("internal/service/vendor/pkg.go"));
    assert!(forbidden_path("internal/service/handler_test.go"));
    assert!(forbidden_path("go.mod"));
    assert!(forbidden_path("go.sum"));
    assert!(forbidden_path("internal/service/zz_generated.deepcopy.go"));
    assert!(forbidden_path("internal/service/api.generated.go"));
    assert!(forbidden_path("internal/service/testdata/fixture.go"));
    assert!(!forbidden_path("internal/service/handler.go"));
}

#[test]
fn capture_rejects_symlinks_inside_workspace() {
    let owner = owner_root("symlink");
    let facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));
    let target = facade.root_path.join("internal/service/handler.go");
    let link = facade.root_path.join("internal/service/link.go");
    symlink(&target, &link).unwrap();

    let error = facade.capture().unwrap_err();
    assert!(error.to_string().contains("link"), "{error}");

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn capture_detects_deleted_source_file() {
    let owner = owner_root("deletion");
    let facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));
    std::fs::remove_file(facade.root_path.join("internal/service/helper.go")).unwrap();

    let error = facade.capture().unwrap_err();
    assert!(error.to_string().contains("deletion"), "{error}");

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn capture_detects_mode_change_on_existing_file() {
    let owner = owner_root("mode-change");
    let facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));
    let path = facade.root_path.join("internal/service/helper.go");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let error = facade.capture().unwrap_err();
    assert!(error.to_string().contains("mode change"), "{error}");

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn replace_rejects_identical_content_as_no_op() {
    let owner = owner_root("no-op");
    let facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));
    let current = facade.read("internal/service/helper.go").unwrap();
    let expected = hash(&current);

    let error = facade
        .replace("internal/service/helper.go", Some(&expected), &current)
        .unwrap_err();
    assert!(error.to_string().contains("no-op"), "{error}");

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn replace_rejects_path_outside_editable_roots() {
    let owner = owner_root("out-of-root");
    let mut files = test_files();
    files.push(ControlledSourceFile {
        path: "cmd/main.go".to_string(),
        bytes: b"package main\n".to_vec(),
        mode: 0o644,
    });
    let facade = ControlledCodingFacade::materialize(
        &owner,
        files,
        test_policy(),
        Arc::new(FakeBackend::new("backend-a", "mount-a")),
    )
    .unwrap();

    let error = facade
        .replace(
            "cmd/main.go",
            Some(&hash(b"package main\n")),
            b"package main\n\nfunc main() {}\n",
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("outside editable roots"),
        "{error}"
    );

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[tokio::test]
async fn go_check_runs_at_most_once() {
    let owner = owner_root("check-once");
    let mut facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));

    let first = facade.run_go_check().await.unwrap();
    assert!(first.success);

    let error = facade.run_go_check().await.unwrap_err();
    assert!(error.to_string().contains("already used"), "{error}");

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn capture_produces_deterministic_replacement_identity() {
    let owner = owner_root("capture-identity");
    let facade = materialize(&owner, FakeBackend::new("backend-a", "mount-a"));
    let original = b"package service\n".to_vec();
    let updated = b"package service\n\nfunc handler() {}\n".to_vec();
    facade
        .replace(
            "internal/service/handler.go",
            Some(&hash(&original)),
            &updated,
        )
        .unwrap();

    let first = facade.capture().unwrap();
    let second = facade.capture().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.replacements.len(), 1);

    let replacement = &first.replacements[0];
    assert_eq!(replacement.path, "internal/service/handler.go");
    assert_eq!(replacement.original.as_deref(), Some(original.as_slice()));
    assert_eq!(replacement.replacement, updated);
    assert_eq!(replacement.replacement_sha256, hash(&updated));
    assert_eq!(
        replacement.original_sha256.as_deref(),
        Some(hash(&original).as_str())
    );

    drop(facade);
    let _ = std::fs::remove_dir_all(&owner);
}

#[test]
fn authority_binds_to_backend_and_mount_identity() {
    let owner_a = owner_root("identity-a");
    let facade_a = materialize(&owner_a, FakeBackend::new("backend-a", "mount-a"));

    let owner_b = owner_root("identity-b");
    let facade_b = materialize(&owner_b, FakeBackend::new("backend-b", "mount-a"));

    let owner_c = owner_root("identity-c");
    let facade_c = materialize(&owner_c, FakeBackend::new("backend-a", "mount-b"));

    let owner_d = owner_root("identity-d");
    let facade_d = materialize(&owner_d, FakeBackend::new("backend-a", "mount-a"));

    assert_ne!(
        facade_a.authority().backend_sha256,
        facade_b.authority().backend_sha256
    );
    assert_eq!(
        facade_a.authority().mounts_sha256,
        facade_b.authority().mounts_sha256
    );

    assert_eq!(
        facade_a.authority().backend_sha256,
        facade_c.authority().backend_sha256
    );
    assert_ne!(
        facade_a.authority().mounts_sha256,
        facade_c.authority().mounts_sha256
    );

    assert_eq!(
        facade_a.authority().backend_sha256,
        facade_d.authority().backend_sha256
    );
    assert_eq!(
        facade_a.authority().mounts_sha256,
        facade_d.authority().mounts_sha256
    );

    drop(facade_a);
    drop(facade_b);
    drop(facade_c);
    drop(facade_d);
    for owner in [owner_a, owner_b, owner_c, owner_d] {
        let _ = std::fs::remove_dir_all(&owner);
    }
}
