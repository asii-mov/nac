//! Loopback MCP transport for the remediation generator's facade-backed tool
//! surface. This is the only network endpoint the coding model can reach
//! while generating a patch: it exposes exactly
//! `application::appsec_remediation::generator::GeneratorTools`'s five tools
//! and nothing else (no controller artifact browser, validator records,
//! evaluator registry, or delegation).

#![allow(
    dead_code,
    reason = "this loopback MCP transport is wired by generator::ManagedWorkerDriver, \
    composed by a follow-up CLI/HTTP wiring task"
)]

use crate::application::appsec_remediation::generator::GeneratorTools;
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    Router,
};
use rmcp::{
    model::*,
    service::{RequestContext, RoleServer},
    transport::{
        streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
        },
        StreamableHttpServerConfig,
    },
    ErrorData, ServerHandler,
};
use serde_json::{json, Value};

pub(crate) fn router(tools: GeneratorTools, token: String, output_limit: usize) -> Router {
    let service = StreamableHttpService::new(
        move || Ok(GeneratorMcp(tools.clone(), output_limit)),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let expected = format!("Bearer {token}");
            async move {
                if request
                    .headers()
                    .get("authorization")
                    .and_then(|header| header.to_str().ok())
                    != Some(expected.as_str())
                {
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap_or_default();
                }
                let (parts, body) = request.into_parts();
                let Ok(bytes) = axum::body::to_bytes(body, output_limit.min(1024 * 1024)).await
                else {
                    return Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::empty())
                        .unwrap_or_default();
                };
                next.run(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
        }))
}

#[derive(Clone)]
struct GeneratorMcp(GeneratorTools, usize);

impl ServerHandler for GeneratorMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("nac-remediation-generator", "1"))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(
            self.0.tool_names().into_iter().map(definition).collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self
            .0
            .call(
                &request.name,
                Value::Object(request.arguments.unwrap_or_default()),
            )
            .await
            .and_then(|value| Ok(serde_json::to_string(&value)?));
        match result {
            Ok(text) if text.len() <= self.1 => {
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Ok(_) => Ok(CallToolResult::error(vec![Content::text(
                "remediation generator response exceeds operation bound",
            )])),
            Err(error) => Ok(CallToolResult::error(vec![Content::text(
                error.to_string(),
            )])),
        }
    }
}

fn definition(name: &'static str) -> Tool {
    let (description, schema) = match name {
        "read_source" => (
            "Read the exact bytes of one file already materialized in this frozen workspace.",
            json!({"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string"}}}),
        ),
        "search_source" => (
            "Search every file in this frozen workspace for a literal byte string.",
            json!({"type":"object","additionalProperties":false,"required":["needle"],"properties":{"needle":{"type":"string"}}}),
        ),
        "replace_source" => (
            "Replace one file's exact content under an editable root. expected_sha256 must match the file's current content, or be null for a new file.",
            json!({"type":"object","additionalProperties":false,"required":["path","expected_sha256","content"],"properties":{"path":{"type":"string"},"expected_sha256":{"type":["string","null"]},"content":{"type":"string"}}}),
        ),
        "format_go" => (
            "Run gofmt -w on the given editable paths inside the confined backend.",
            json!({"type":"object","additionalProperties":false,"required":["paths"],"properties":{"paths":{"type":"array","items":{"type":"string"}}}}),
        ),
        _ => (
            "Run the one bounded Go check (go vet ./...) inside the confined backend. Callable at most once.",
            json!({"type":"object","additionalProperties":false,"properties":{}}),
        ),
    };
    Tool::new(
        name,
        description,
        schema.as_object().cloned().unwrap_or_default(),
    )
}
