use crate::application::appsec_runtime::tools::ResearchTools;
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

#[path = "appsec_workflow_schema.rs"]
mod workflow_schema;

pub(crate) fn router(tools: ResearchTools, token: String, output_limit: usize) -> Router {
    let service = StreamableHttpService::new(
        move || Ok(ResearchMcp(tools.clone(), output_limit)),
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
struct ResearchMcp(ResearchTools, usize);

impl ServerHandler for ResearchMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("nac-source-review", "1"))
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
            .and_then(|value| Ok(serde_json::to_string(&value)?));
        match result {
            Ok(text) if text.len() <= self.1 => {
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Ok(_) => Ok(CallToolResult::error(vec![Content::text(
                "controller response exceeds operation bound",
            )])),
            Err(error) => Ok(CallToolResult::error(vec![Content::text(
                error.to_string(),
            )])),
        }
    }
}

fn definition(name: &'static str) -> Tool {
    let source = json!({"type":"object", "additionalProperties":false,"required":["repository","path","start_line","end_line"],"properties":{"repository":{"type":"string"},"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}}});
    let evidence = json!({"type":"array", "items":{"oneOf":[{"type":"object","additionalProperties":false,"required":["kind","bytes"],"properties":{"kind":{"const":"upload"},"bytes":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255}}}},{"type":"object","additionalProperties":false,"required":["kind","artifact"],"properties":{"kind":{"const":"stored"},"artifact":{"type":"object","required":["sha256","bytes"],"additionalProperties":false,"properties":{"sha256":{"type":"string"},"bytes":{"type":"integer"}}}}}]}});
    let experiment_ids =
        json!({"type":"array","maxItems":8,"items":{"type":"string","format":"uuid"}});
    let (description, schema) = match name {
        "read_work_record" => ("Read a bounded byte range of a canonical accepted record from query_work. Verify sha256 when assembling pages. Validators cannot read discoverer records or notes.", json!({"type":"object","additionalProperties":false,"required":["record_id","offset","length"],"properties":{"record_id":{"type":"string"},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":1}}})),
        "query_work" => ("Read bounded canonical task/result/family pages and the revision. Validators see only their blinded assignment and own records.", json!({"type":"object","additionalProperties":false,"required":["offset","limit"],"properties":{"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32}}})),
        "submit_workflow" => ("Submit a typed map, source question/resolution, approach, followup, validate or synthesize action. Role, task and fence are server-bound. Revision must come from query_work. Only the assigned validator can submit its verdict.", workflow_schema::submission(evidence)),
        "list_source_files" => ("List a bounded page of regular UTF-8 source paths at the declared pinned commit. Use next_after as the next cursor. No working tree, symlinks, Git internals or other revisions.", json!({"type":"object","additionalProperties":false,"required":["repository","after","limit"],"properties":{"repository":{"type":"string"},"after":{"type":["string","null"]},"limit":{"type":"integer","minimum":1,"maximum":256}}})),
        "read_source" => ("Read an existing regular file only at the declared repository commit. Returns validated SourceRef and trusted source receipt. No Git history or network fetch.", source),
        "read_dependency_source" => ("Read a bounded range from one exact prefetched dependency archive. Package, version, source ref and archive hash must match the frozen profile.", json!({"type":"object","additionalProperties":false,"required":["package","version","source_ref","archive_sha256","path","offset","length"],"properties":{"package":{"type":"string"},"version":{"type":"string"},"source_ref":{"type":"string"},"archive_sha256":{"type":"string"},"path":{"type":"string"},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":1,"maximum":262144}}})),
        "search_source" => ("Search a bounded pinned source range for a literal string.", json!({"type":"object","additionalProperties":false,"required":["source","literal"],"properties":{"source":source,"literal":{"type":"string"}}})),
        "submit_candidate" => ("Propose a candidate, not a validated finding. Use SourceRef from read_source. Link only settled experiments whose hypothesis and source exactly match the claim. Authority is bound to this connection, never arguments.", json!({"type":"object","additionalProperties":false,"required":["key","candidate","evidence"],"properties":{"key":{"type":"string"},"candidate":{"type":"object","additionalProperties":false,"required":["claim","prerequisites","unresolved_assumptions","source"],"properties":{"claim":{"type":"string"},"prerequisites":{"type":"array","items":{"type":"string"}},"unresolved_assumptions":{"type":"array","items":{"type":"string"}},"source":{"type":"object","required":["repository","commit","path","start_line","end_line","content_sha256"],"additionalProperties":false,"properties":{"repository":{"type":"string"},"commit":{"type":"string"},"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"},"content_sha256":{"type":"string"}}},"experiments":experiment_ids}},"evidence":evidence}})),
        "submit_stage_result" => ("Submit a typed stage checkpoint with structured evidence. Completion covers the exact assigned scope, not security assurance.", json!({"type":"object","additionalProperties":false,"required":["key","result","evidence"],"properties":{"key":{"type":"string"},"result":{"oneOf":[{"type":"object","additionalProperties":false,"required":["status","scope"],"properties":{"status":{"const":"completed"},"scope":{"type":"string"}}},{"type":"object","additionalProperties":false,"required":["status","reason"],"properties":{"status":{"enum":["partial","blocked","failed"]},"reason":{"type":"string"}}}]},"evidence":evidence}})),
        "run_experiment" => ("Reserve a frozen bounded HTTP experiment for this task. The controller supplies the lease, role, runner, target, actor credentials and evaluator. Returns a ticket, never raw target output.", json!({"type":"object","additionalProperties":false,"required":["schema_version","key","recipe_id","hypothesis","sources","requests"],"properties":{"schema_version":{"const":1},"key":{"type":"string","minLength":1,"maxLength":128},"recipe_id":{"type":"string","minLength":1,"maxLength":128},"hypothesis":{"type":"string","minLength":1,"maxLength":4096},"sources":{"type":"array","minItems":1,"maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["repository","commit","path","start_line","end_line","content_sha256"],"properties":{"repository":{"type":"string"},"commit":{"type":"string"},"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1},"content_sha256":{"type":"string"}}}},"requests":{"type":"array","minItems":1,"maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["actor","method","path","body"],"properties":{"actor":{"type":"string"},"method":{"enum":["get","post"]},"path":{"type":"string"},"body":{"type":"string"}}}}}})),
        "read_experiment" => ("Read this task's safe experiment state, closed assessment and approved diagnostic codes. Raw responses, captures, secrets and evaluator rules are unavailable.", json!({"type":"object","additionalProperties":false,"required":["experiment_id"],"properties":{"experiment_id":{"type":"string","format":"uuid"}}})),
        "cancel_experiment" => ("Commit a stop tombstone for this task's experiment. Cleanup remains separate and capacity stays occupied until the controller proves no live or pending target.", json!({"type":"object","additionalProperties":false,"required":["experiment_id"],"properties":{"experiment_id":{"type":"string","format":"uuid"}}})),
        "record_blocker" => ("Record an explicit environment or input blocker with evidence.", json!({"type":"object","additionalProperties":false,"required":["key","reason","evidence"],"properties":{"key":{"type":"string"},"reason":{"type":"string"},"evidence":evidence}})),
        _ => ("Read a bounded byte range of an artifact already accepted for this task.", json!({"type":"object","additionalProperties":false,"required":["artifact","offset","length"],"properties":{"artifact":{"type":"object","additionalProperties":false,"required":["sha256","bytes"],"properties":{"sha256":{"type":"string"},"bytes":{"type":"integer"}}},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":1}}})),
    };
    Tool::new(
        name,
        description,
        schema.as_object().cloned().unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn appsec_mcp_auth_body_bound_and_connection_fence_are_not_model_arguments(
    ) -> anyhow::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("nac-mcp-boundary-{}", uuid::Uuid::new_v4()));
        let id = uuid::Uuid::new_v4().to_string().parse()?;
        let tools = ResearchTools::new(
            &directory,
            nac_appsec::Lease {
                run_id: id,
                task_id: id,
                attempt_id: id,
                generation: 1,
                token: id,
            },
        )?;
        assert!(!tools.tool_names().contains(&"run_experiment"));
        assert_eq!(
            tools
                .call("run_experiment", json!({}))
                .unwrap_err()
                .to_string(),
            "experiment_error:unauthorized"
        );
        let app = router(tools.clone(), "scripted-connection-token".into(), 128);
        let unauthenticated = Request::builder()
            .uri("/mcp")
            .method("POST")
            .body(Body::from("{}"))?;
        assert_eq!(
            app.clone().oneshot(unauthenticated).await?.status(),
            StatusCode::UNAUTHORIZED
        );
        let oversized = Request::builder()
            .uri("/mcp")
            .method("POST")
            .header("authorization", "Bearer scripted-connection-token")
            .body(Body::from(vec![b'x'; 129]))?;
        assert_eq!(
            app.oneshot(oversized).await?.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let forged = tools.call("read_source", json!({"repository":"fixture","path":"Cargo.toml","start_line":1,"end_line":1,"attempt_id":id,"token":id}));
        assert!(
            forged.unwrap_err().to_string().contains("unknown field"),
            "model cannot supply its own attempt or fence"
        );
        drop(tools);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
