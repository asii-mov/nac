use anyhow::Result;

use super::{AgentMode, Arc, ToolDefinition};

/// Credential source for the request-scoped first-party web capability.
/// Workers are populated only from the post-MCP delegated snapshot; eligible
/// direct agents retain the established environment/store refresh behavior.
pub(super) enum NativeWebCapabilities {
    Disabled,
    Direct,
    Worker(Option<String>),
}

impl NativeWebCapabilities {
    pub(super) fn new(mode: AgentMode, traditional_child: bool) -> Self {
        match mode {
            AgentMode::Worker => Self::Worker(None),
            AgentMode::Direct if !traditional_child => Self::Direct,
            AgentMode::Direct | AgentMode::Orchestrator => Self::Disabled,
        }
    }

    pub(super) fn is_eligible(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub(super) fn set_worker_credential(&mut self, credential: Option<String>) {
        if let Self::Worker(worker_credential) = self {
            *worker_credential = credential.filter(|value| !value.trim().is_empty());
        }
    }

    pub(super) fn resolve_credential(&self) -> Result<Option<String>> {
        match self {
            Self::Disabled => Ok(None),
            Self::Direct => match crate::worker_credentials::managed_exa_api_key() {
                Some(credential) => Ok(Some(credential)),
                None => crate::model::resolve_named_api_key(crate::model::EXA_API_KEY_ENV),
            },
            Self::Worker(credential) => Ok(credential.clone()),
        }
    }
}

impl super::Agent {
    pub(crate) fn set_worker_web_credential(&mut self, credential: Option<String>) {
        self.native_web_capabilities
            .set_worker_credential(credential);
    }

    /// Build one immutable model-request capability view. The Exa credential
    /// and the tool names are replaced together before the request and the
    /// resulting runtime is cloned into exactly that response's tool round.
    pub(super) fn refresh_model_request_capabilities(&mut self) -> Result<Vec<ToolDefinition>> {
        let credential = self.native_web_capabilities.resolve_credential()?;
        Ok(self.install_model_request_capabilities(credential))
    }

    fn install_model_request_capabilities(
        &mut self,
        credential: Option<String>,
    ) -> Vec<ToolDefinition> {
        let credential = credential
            .filter(|_| self.native_web_capabilities.is_eligible())
            .map(crate::tools::web::ExaCredential::new)
            .map(Arc::new);
        let mut definitions = self.tool_defs.clone();
        if credential.is_some() {
            definitions.extend(crate::tools::web::definitions());
        }
        self.tool_runtime.allowed_tools = Some(Arc::new(
            definitions
                .iter()
                .map(|definition| definition.function.name.clone())
                .collect(),
        ));
        self.tool_runtime.web_credential = credential;
        definitions
    }

    #[cfg(test)]
    pub(super) fn model_request_capabilities_for_test(
        &mut self,
        credential: Option<&str>,
    ) -> Vec<ToolDefinition> {
        self.install_model_request_capabilities(credential.map(str::to_string))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "managed-direct-native-web-canary";

    #[test]
    fn managed_snapshot_direct_web_helper() {
        if std::env::var_os("NAC_MANAGED_DIRECT_WEB_HELPER").is_none() {
            return;
        }
        crate::worker_credentials::capture_managed_native_credentials_from_environment().unwrap();
        assert!(std::env::var_os(crate::model::EXA_API_KEY_ENV).is_none());
        let nac_home = std::path::PathBuf::from(std::env::var_os("NAC_HOME").unwrap());
        std::fs::create_dir_all(&nac_home).unwrap();
        let credential_file = nac_home.join("credentials.json");
        let fixture = std::env::var("NAC_MANAGED_DIRECT_WEB_CREDENTIAL_FIXTURE").unwrap();
        std::fs::write(
            &credential_file,
            if fixture == "corrupt" {
                b"not valid JSON".as_slice()
            } else {
                br#"{"api_keys":{"EXA_API_KEY":"must-not-be-read"}}"#.as_slice()
            },
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &credential_file,
                std::fs::Permissions::from_mode(if fixture == "insecure" { 0o644 } else { 0o600 }),
            )
            .unwrap();
        }
        let capability = NativeWebCapabilities::new(AgentMode::Direct, false);
        assert_eq!(
            capability.resolve_credential().unwrap().as_deref(),
            Some(CANARY)
        );
        assert_eq!(
            crate::worker_credentials::ManagedWorkerNativeCredentials::from_process_environment()
                .unwrap()
                .into_exa_api_key()
                .as_deref(),
            Some(CANARY)
        );
    }

    #[test]
    fn managed_snapshot_remains_available_to_direct_native_web_only() {
        let fixtures = if cfg!(unix) {
            &["corrupt", "insecure"][..]
        } else {
            &["corrupt"][..]
        };
        for fixture in fixtures {
            let nac_home = std::env::temp_dir().join(format!(
                "nac_managed_direct_web_{fixture}_{}",
                uuid::Uuid::new_v4().simple()
            ));
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "agent::web_capabilities::tests::managed_snapshot_direct_web_helper",
                    "--nocapture",
                ])
                .env("NAC_MANAGED_DIRECT_WEB_HELPER", "1")
                .env("NAC_MANAGED_DIRECT_WEB_CREDENTIAL_FIXTURE", fixture)
                .env("NAC_HOME", &nac_home)
                .env(crate::model::EXA_API_KEY_ENV, CANARY)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "managed direct-web {fixture} helper failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
            let _ = std::fs::remove_dir_all(nac_home);
        }
    }
}
