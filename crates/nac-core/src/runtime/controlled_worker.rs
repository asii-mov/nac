use super::*;
use crate::{mcp::McpServerConfig, types::Message};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};

pub struct ControlledWorkerOptions {
    pub directory: PathBuf,
    pub model: ModelOptions,
    pub prompt: String,
    pub action: String,
    pub mcp_servers: BTreeMap<String, McpServerConfig>,
    pub allowed_tools: BTreeSet<String>,
    pub control: ManagedWorkerControl,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadedWorkerInputs {
    pub backend: String,
    pub model: String,
    pub reasoning: Option<String>,
    pub session_id: String,
    pub thread_name: String,
    pub dispatch_id: String,
    pub prompt_sha256: String,
    pub action_sha256: String,
    pub messages_sha256: String,
    pub tools: Vec<String>,
    pub source_threads: Vec<String>,
    pub ambient_inputs: Vec<String>,
}

pub async fn build_controlled_managed_worker(
    options: ControlledWorkerOptions,
) -> Result<(ManagedWorkerRunConfig, LoadedWorkerInputs)> {
    anyhow::ensure!(
        options.directory.is_absolute(),
        "controlled worker directory must be absolute"
    );
    std::fs::create_dir(&options.directory)?;
    let settings = model_resolution::managed_worker_effective_model_settings(&options.model)?;
    let client = ModelClient::from_effective_settings(settings.clone())?;
    build_with_client(options, settings, client).await
}

pub(super) async fn build_with_client(
    options: ControlledWorkerOptions,
    settings: EffectiveModelSettings,
    client: ModelClient,
) -> Result<(ManagedWorkerRunConfig, LoadedWorkerInputs)> {
    let control = options.control.clone();
    let registry = control
        .bounded(
            "mcp_initialize",
            McpRegistry::load_explicit(&options.directory, options.mcp_servers),
        )
        .await?;
    let definitions = registry.tool_definitions();
    let inventory: BTreeSet<_> = definitions
        .iter()
        .map(|tool| tool.function.name.clone())
        .collect();
    anyhow::ensure!(
        inventory == options.allowed_tools
            && inventory.iter().all(|name| name.starts_with("mcp__")),
        "effective MCP tool inventory differs from selected profile"
    );
    let session_id = Uuid::new_v4().to_string();
    let thread_name = Uuid::new_v4().to_string();
    let dispatch_id = Uuid::new_v4().to_string();
    let store_path = options.directory.join("worker.db");
    store::initialize(&store_path)?;
    let messages = vec![Message::System {
        content: options.prompt.clone(),
    }];
    let backend = settings.backend.as_str().to_string();
    let model = settings.model.clone();
    let reasoning = settings
        .reasoning_effort
        .map(|effort| effort.as_str().to_string());
    let snapshot = sessions::new_snapshot(
        session_id.clone(),
        options.directory.clone(),
        settings.model,
        settings.base_url,
        settings.backend,
        settings.reasoning_effort,
        None,
        None,
        messages.clone(),
        settings.api_key_env,
        settings.extra_headers,
    );
    sessions::create_session(&store_path, &snapshot)?;
    let mut agent = Agent::with_config(
        client,
        AgentConfig {
            mode: AgentMode::Worker,
            session_behavior: None,
            store_path: store_path.clone(),
            session_id: Some(session_id.clone()),
            orchestrator_compaction_threshold: None,
            initial_messages: Vec::new(),
            thread_name: Some(thread_name.clone()),
            dispatch_id: Some(dispatch_id.clone()),
            event_sink: EventSink::none(),
            workspace_cwd: options.directory.clone(),
            config_cwd: options.directory.clone(),
            working_directory: options.directory.display().to_string(),
            worker_executable: None,
            sandbox: None,
            ssh: None,
            mcp: Some(Arc::clone(&registry)),
            skills: None,
            extra_tool_defs: definitions.clone(),
            agents_md_message: None,
            thread_timeout_secs: 0,
            command_output_limits: crate::terminal::CommandOutputLimits::default(),
            light_client: None,
            permission_rules: Vec::new(),
        },
    )?;
    let proof = LoadedWorkerInputs {
        backend,
        model,
        reasoning,
        session_id: session_id.clone(),
        thread_name: thread_name.clone(),
        dispatch_id,
        prompt_sha256: format!("{:x}", Sha256::digest(options.prompt.as_bytes())),
        action_sha256: format!("{:x}", Sha256::digest(options.action.as_bytes())),
        messages_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(&messages)?)),
        tools: inventory.into_iter().collect(),
        source_threads: Vec::new(),
        ambient_inputs: Vec::new(),
    };
    agent.control_worker(control, messages, definitions);
    Ok((
        ManagedWorkerRunConfig {
            agent,
            store_path,
            session_id,
            thread_name,
            action: options.action,
        },
        proof,
    ))
}

pub async fn run_controlled_managed_worker(
    mut config: ManagedWorkerRunConfig,
    control: ManagedWorkerControl,
) -> Result<String> {
    tokio::select! {
        biased;
        () = control.cancelled() => anyhow::bail!("controlled worker cancelled"),
        result = config.agent.send(&config.action) => result,
    }
}
