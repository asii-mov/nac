use std::path::PathBuf;

use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DoctorConfig {
    pub schema_version: u32,
    #[serde(deserialize_with = "string_enum")]
    pub backend: Backend,
    pub model: String,
    #[serde(deserialize_with = "string_enum")]
    pub reasoning: Reasoning,
    #[serde(deserialize_with = "string_enum")]
    pub monetary_policy: MonetaryPolicy,
    pub limits: Limits,
    pub evaluation_source: Option<PathBuf>,
    #[serde(default)]
    pub tools: Vec<String>,
}

fn string_enum<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(String::deserialize(deserializer)?.into_deserializer())
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) enum Backend {
    #[serde(rename = "chatgpt-codex-responses")]
    ChatGptCodexResponses,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Reasoning {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum MonetaryPolicy {
    Uncapped,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub active_agents: u8,
    pub task_tokens: u64,
    pub task_seconds: u64,
    pub transient_retries: u32,
    pub tool_output_bytes_per_response: u64,
    pub tool_output_bytes_total: u64,
}

impl DoctorConfig {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, super::DoctorError> {
        let config: Self = serde_json::from_slice(bytes).map_err(|error| {
            super::DoctorError::InvalidConfig(format!(
                "invalid doctor JSON/schema at line {}, column {}",
                error.line(),
                error.column()
            ))
        })?;
        config
            .validate()
            .map_err(super::DoctorError::InvalidConfig)?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported doctor schema_version; expected 1".into());
        }
        if self.model.is_empty()
            || !self
                .model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("model must be an explicit bare model identifier".into());
        }
        let limits = &self.limits;
        if !(1..=4).contains(&limits.active_agents)
            || limits.task_tokens == 0
            || limits.task_seconds == 0
            || limits.tool_output_bytes_per_response == 0
            || limits.tool_output_bytes_total == 0
        {
            return Err("requested concurrency, token, time and output limits must be positive finite integers; active_agents must be at most 4".into());
        }
        if limits.tool_output_bytes_per_response > limits.tool_output_bytes_total {
            return Err("per-response tool output must not exceed aggregate tool output".into());
        }
        if self
            .evaluation_source
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err("evaluation_source must be a nonempty directory path".into());
        }
        for (index, tool) in self.tools.iter().enumerate() {
            if tool.is_empty()
                || !tool.as_bytes()[0].is_ascii_alphanumeric()
                || !tool
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err("tools must be bare executable names, not paths or arguments".into());
            }
            if self.tools[..index].contains(tool) {
                return Err("tools must not contain duplicate names".into());
            }
        }
        Ok(())
    }
}
