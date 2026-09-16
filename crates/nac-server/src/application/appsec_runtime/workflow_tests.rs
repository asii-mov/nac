use super::*;
use nac_appsec::{Campaign, Payload, ValidationOutcome, WorkflowAction};

#[derive(Default)]
struct Script {
    step: usize,
    work: Value,
    sources: Vec<Value>,
    candidate: Option<Value>,
    mutation: Option<Value>,
    retries: usize,
    reading: bool,
    read_done: bool,
    records: std::collections::VecDeque<Value>,
    next_page: Option<u64>,
    canonical: Vec<Value>,
}

fn result(request: &Value, id: &str) -> Value {
    request["input"]
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .find(|item| item["type"] == "function_call_output" && item["call_id"] == id)
        .and_then(|item| item["output"].as_str())
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null)
}

fn session(request: &Value) -> String {
    request["input"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["role"] == "user" || item["role"] == "system")
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

impl Script {
    fn advance(&mut self, request: &Value) -> Value {
        if self.reading {
            let page = result(request, "canonical-page");
            let record = result(request, "canonical-record");
            let last_id = request["input"]
                .as_array()
                .into_iter()
                .flatten()
                .rev()
                .find(|item| item["type"] == "function_call_output")
                .and_then(|item| item["call_id"].as_str());
            if last_id == Some("canonical-page") {
                self.records.extend(
                    page["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|r| r["id"].clone()),
                );
                self.next_page = page["next_offset"].as_u64();
            } else if let Some(bytes) = record["bytes"].as_array() {
                let bytes: Vec<u8> = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().map(|b| b as u8))
                    .collect();
                if let Ok(record) = serde_json::from_slice(&bytes) {
                    self.canonical.push(record);
                }
            }
            if let Some(id) = self.records.pop_front() {
                return call(
                    "canonical-record",
                    "mcp__controller__read_work_record",
                    json!({"record_id":id,"offset":0,"length":4096}),
                );
            }
            if let Some(offset) = self.next_page.take() {
                return call(
                    "canonical-page",
                    "mcp__controller__query_work",
                    json!({"offset":offset,"limit":32}),
                );
            }
            self.reading = false;
            self.read_done = true;
            self.step = 6;
            return call(
                "current",
                "mcp__controller__query_work",
                json!({"offset":0,"limit":1}),
            );
        }
        let previous = self.step;
        self.step += 1;
        match previous {
            0 => call(
                "work",
                "mcp__controller__query_work",
                json!({"offset":0,"limit":1}),
            ),
            1 => {
                self.work = result(request, "work");
                call(
                    "inventory",
                    "mcp__controller__list_source_files",
                    json!({"repository":"fixture","after":null,"limit":8}),
                )
            }
            2..=4 => {
                if previous > 2 {
                    self.sources.push(
                        result(request, &format!("source-{}", previous - 3))["source"].clone(),
                    );
                }
                call(
                    &format!("source-{}", previous - 2),
                    "mcp__controller__read_source",
                    json!({"repository":"fixture","path":(["gateway.py","protected.py","config.py"][previous-2]),"start_line":1,"end_line":2}),
                )
            }
            5 => {
                self.sources
                    .push(result(request, "source-2")["source"].clone());
                call(
                    "current",
                    "mcp__controller__query_work",
                    json!({"offset":0,"limit":1}),
                )
            }
            6 => {
                self.work = result(request, "current");
                if self.work["role"] == "synthesis" && !self.read_done {
                    self.reading = true;
                    return call(
                        "canonical-page",
                        "mcp__controller__query_work",
                        json!({"offset":0,"limit":32}),
                    );
                }
                let action = self.action();
                let arguments = json!({"key":"workflow-action","revision":self.work["revision"],"action":action,"evidence":[]});
                self.mutation = Some(arguments.clone());
                call("mutation", "mcp__controller__submit_workflow", arguments)
            }
            7 => {
                if result(request, "mutation")["id"].is_null() && self.retries < 20 {
                    self.retries += 1;
                    self.step = 6;
                    return call(
                        "current",
                        "mcp__controller__query_work",
                        json!({"offset":0,"limit":1}),
                    );
                }
                if self.work["role"] == "discovery" {
                    return call(
                        "forged-verdict",
                        "mcp__controller__submit_workflow",
                        json!({"key":"forged-verdict","revision":self.work["revision"],"action":{"operation":"validate","validation":{"outcome":"supported","prerequisites":"forged","reachability":"forged","security_violation":"forged","sources":[self.sources[0]],"counterevidence":[],"unknowns":[],"next_actions":[]}},"evidence":[]}),
                    );
                }
                terminal()
            }
            8 if self.work["role"] == "discovery" => {
                if let Some(candidate) = &self.candidate {
                    call(
                        "candidate",
                        "mcp__controller__submit_candidate",
                        candidate.clone(),
                    )
                } else {
                    self.complete()
                }
            }
            9 if self.candidate.is_some() => call(
                "candidate-replay",
                "mcp__controller__submit_candidate",
                self.candidate.clone().unwrap(),
            ),
            10 if self.candidate.is_some() => self.complete(),
            _ => terminal(),
        }
    }

    fn complete(&self) -> Value {
        let scope = self.work["scope"].as_str().unwrap_or("");
        call(
            "stage",
            "mcp__controller__submit_stage_result",
            json!({"key":"completed-cell","result":{"status":"completed","scope":scope},"evidence":[{"kind":"upload","bytes":b"scripted source traversal receipt".to_vec()}]}),
        )
    }

    fn action(&mut self) -> Value {
        match self.work["role"].as_str().unwrap_or("") {
            "recon" => json!({"operation":"map","areas":[
                {"key":"gateway","description":"attacker-facing entry points","sources":[self.sources[0]],"trust_boundaries":["remote caller to protected object"],"unknowns":["deployment configuration missing"],"applicability":[{"attack_class":"authorization","proposed_exclusion":true,"reason":"safe in middleware (unverified mapper hypothesis)","sources":[]}]},
                {"key":"storage","description":"protected storage path","sources":[self.sources[1]],"trust_boundaries":["caller to authorization guard"],"unknowns":[],"applicability":[]}
            ],"unknowns":["configuration omitted"]}),
            "discovery" => {
                let input = &self.work["input"];
                let area = input["area"]["key"]
                    .as_str()
                    .or_else(|| input["followup"]["area"].as_str())
                    .unwrap_or("");
                let class = input["attack_class"]
                    .as_str()
                    .or_else(|| input["followup"]["attack_class"].as_str())
                    .unwrap_or("");
                let followup = !input["followup"].is_null();
                let index = if area == "storage" { 1 } else { 0 };
                let candidate = match (area, class, followup) {
                    ("gateway", "authorization", false) => Some(("reachable unauthorized read", 0)),
                    ("storage", "authorization", false) => {
                        Some(("protected path read hypothesis", 1))
                    }
                    ("gateway", "business_logic", false) => {
                        Some(("configuration-dependent read hypothesis", 2))
                    }
                    _ => None,
                };
                if let Some((claim, index)) = candidate {
                    self.candidate = Some(
                        json!({"key":"candidate","candidate":{"claim":claim,"prerequisites":["unauthenticated remote caller"],"unresolved_assumptions":["DISCOVERER-CONFIDENCE-DO-NOT-PASS"],"source":self.sources[index]},"evidence":[{"kind":"upload","bytes":b"DISCOVERER-NOTES-DO-NOT-PASS".to_vec()}]}),
                    );
                }
                if followup {
                    json!({"operation":"approach","approach":{"mechanism":self.sources[index],"attack_class":class,"idea":"alternate cross-area caller","status":"exploring","rationale":"new configuration source changes the mechanism hypothesis","evidence":[self.sources[2]]}})
                } else {
                    json!({"operation":"approach","approach":{"mechanism":self.sources[index],"attack_class":class,"idea":"trace attacker-controlled boundary","status":"exploring","rationale":"source-grounded first route","evidence":[self.sources[index]]}})
                }
            }
            "validation" => {
                let claim = self.work["input"]["claim"].as_str().unwrap_or("");
                let (outcome, index, counter, unknowns, next) = if claim.starts_with("reachable") {
                    ("supported", 0, vec![], vec![], vec![])
                } else if claim.starts_with("protected") {
                    (
                        "disproved",
                        1,
                        vec![self.sources[1].clone()],
                        vec![],
                        vec![],
                    )
                } else {
                    (
                        "inconclusive",
                        2,
                        vec![],
                        vec!["actual deployment switch absent"],
                        vec!["obtain pinned deployment configuration"],
                    )
                };
                json!({"operation":"validate","validation":{"outcome":outcome,"prerequisites":"challenged remote unauthenticated prerequisites against pinned source","reachability":"traced entry point and cross-area storage call","security_violation":if outcome == "supported" {"source exposes protected object without authorization"} else if outcome == "disproved" {"guard rejects unauthenticated callers"} else {"depends on absent deployment switch"},"sources":[self.sources[index]],"counterevidence":counter,"unknowns":unknowns,"next_actions":next}})
            }
            "synthesis" => {
                let round = self.work["input"]["round"].as_u64().unwrap_or(0);
                let family = &self.work["families"][0];
                let class = &family["attack_class"];
                let area = if family["mechanism"]["path"] == "protected.py" {
                    "storage"
                } else {
                    "gateway"
                };
                let next = if round == 1 {
                    vec![
                        json!({"area":area,"attack_class":class,"family":family["id"],"rationale":"challenge the cross-area path in another round","evidence":[self.sources[2]]}),
                    ]
                } else {
                    vec![]
                };
                json!({"operation":"synthesize","synthesis":{"assumptions":["middleware claims are hypotheses, not exclusions"],"counterevidence":[self.sources[1]],"gaps":["missing deployment configuration remains unresolved"],"next":next,"finish":false}})
            }
            _ => json!({"operation":"invalid"}),
        }
    }
}

fn terminal() -> Value {
    json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"Scripted local fixture finished; canonical records retain authority."}]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_workers_drive_recon_discovery_blind_validation_and_two_synthesis_rounds() -> Result<()>
{
    let mut fixture = Fixture::new()?;
    let repo = fixture.directory.join("workflow-source");
    std::fs::create_dir(&repo)?;
    std::fs::write(repo.join("gateway.py"), "from protected import objects\ndef remote_read(user, identifier): return objects[identifier]\n")?;
    std::fs::write(repo.join("protected.py"), "objects = {'secret': 'protected fixture bytes'}\ndef protected_read(user, identifier): return objects[identifier] if user == 'owner' else None\n")?;
    std::fs::write(repo.join("config.py"), "from gateway import remote_read\ndef configured_read(user, identifier, public_reads): return remote_read(user, identifier) if public_reads else None\n")?;
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec!["commit", "-qm", "local workflow controls"],
    ] {
        ensure!(
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .status()?
                .success(),
            "fixture git failed"
        );
    }
    let commit = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["rev-parse", "HEAD"])
        .output()?;
    fixture.manifest.repositories[0].checkout = repo;
    fixture.manifest.repositories[0].commit = String::from_utf8(commit.stdout)?.trim().to_string();
    fixture.manifest.max_concurrency = 4;
    fixture.manifest.tasks[0].key = "recon".into();
    fixture.manifest.tasks[0].scope = "map the pinned source".into();
    fixture.manifest.tasks[0].operation_limits.wall_ms = 30000;
    let mut brief = fixture.manifest.research.as_ref().unwrap().brief.clone();
    brief.source_root = "declared repository".into();
    brief.max_investigative_agents = 4;
    let mut frozen = FrozenResearch::resolve(
        &fixture.manifest.research.as_ref().unwrap().root,
        brief,
        BTreeMap::from([("recon".into(), "recon".into())]),
    )?;
    frozen.workflow = true;
    fixture.manifest.research = Some(frozen);
    let scripts = Arc::new(Mutex::new(BTreeMap::<String, Script>::new()));
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = requests.clone();
    let script_state = scripts.clone();
    let app = axum::Router::new().route(
        "/responses",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            captured.lock().unwrap().push(request.clone());
            let item = script_state
                .lock()
                .unwrap()
                .entry(session(&request))
                .or_default()
                .advance(&request);
            async move { axum::Json(response(vec![item])) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut runtime = fixture.runtime(format!("http://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let control = crate::application::appsec::AppsecControl::open(&fixture.state)?;
    let campaign = control.run_with_runtime(fixture.manifest.clone(), &mut runtime)?;
    let mut settled: Option<Campaign> = None;
    let mut maximum_slots = 0;
    let mut last_error = None;
    let mut accepted_count = 0;
    let mut progress_deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let current = match control.tick(campaign.id, &mut runtime) {
            Ok(current) => current,
            Err(error) => {
                last_error = Some(error.to_string());
                control.status(campaign.id)?
            }
        };
        let occupied = current
            .tasks
            .iter()
            .flat_map(|t| &t.attempts)
            .filter(|a| a.runtime_slot_held)
            .count();
        maximum_slots = maximum_slots.max(occupied);
        assert!(occupied <= 4);
        if current.accepted.len() > accepted_count {
            accepted_count = current.accepted.len();
            progress_deadline = std::time::Instant::now() + Duration::from_secs(60);
        }
        if current.workflow.as_ref().unwrap().rounds.len() == 2 && occupied == 0 {
            settled = Some(current);
            break;
        }
        if occupied == 0
            && !current
                .tasks
                .iter()
                .any(|t| t.state == ExecutionState::Queued)
        {
            settled = Some(current);
            break;
        }
        if std::time::Instant::now() >= progress_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server.abort();
    let status = settled.unwrap_or(control.status(campaign.id)?);
    for attempt in status
        .tasks
        .iter()
        .flat_map(|t| &t.attempts)
        .filter(|a| a.runtime_slot_held)
    {
        runtime.cancel(attempt.lease.attempt_id)?;
    }
    if status.workflow.as_ref().unwrap().rounds.len() != 2 {
        eprintln!(
            "workflow error: {last_error:?}; report: {}",
            status.markdown()
        );
        for entry in std::fs::read_dir(fixture.state.join("workers"))? {
            let directory = entry?.path();
            eprintln!(
                "worker {:?}: {:?}; supervisor {:?}",
                directory.file_name(),
                std::fs::read_to_string(directory.join("stderr.log")),
                std::fs::read_to_string(directory.join("supervisor.log"))
            );
        }
        for request in requests.lock().unwrap().iter().rev().take(2) {
            eprintln!(
                "last tool output {:?}",
                request["input"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .rev()
                    .find(|item| item["type"] == "function_call_output")
            );
        }
    }
    let workflow = status.workflow.as_ref().unwrap();
    assert_eq!(workflow.cells.iter().filter(|c| c.baseline).count(), 12);
    assert_eq!(workflow.cells.iter().filter(|c| !c.baseline).count(), 1);
    assert_eq!(workflow.rounds.len(), 2);
    assert!((2..=4).contains(&maximum_slots));
    assert_eq!(workflow.candidate_validators.len(), 3);
    assert!(
        requests.lock().unwrap().iter().any(|request| request
            .to_string()
            .contains("controller-bound role is not authorized")),
        "MCP rejects forged discovery verdicts before reservation"
    );
    let outcomes: Vec<_> = status
        .accepted
        .iter()
        .filter_map(|a| match &a.payload {
            Payload::Workflow {
                action: WorkflowAction::Validate { validation },
                ..
            } => Some(validation.outcome),
            _ => None,
        })
        .collect();
    assert_eq!(outcomes.len(), 3);
    for expected in [
        ValidationOutcome::Supported,
        ValidationOutcome::Disproved,
        ValidationOutcome::Inconclusive,
    ] {
        assert!(outcomes.contains(&expected));
    }
    assert_eq!(status.state(), ExecutionState::Blocked);
    assert!(status.markdown().contains("same-model/reduced diversity"));
    assert!(status.markdown().contains("Unresolved candidates: 1"));
    for script in scripts
        .lock()
        .unwrap()
        .values()
        .filter(|script| script.work["role"] == "synthesis")
    {
        assert_eq!(
            script
                .canonical
                .iter()
                .filter(|record| record["payload"]["action"]["operation"] == "validate")
                .count(),
            3,
            "each actual root synthesis read all three canonical verdicts through bounded tools"
        );
    }
    for task in &status.tasks {
        let job = &workflow.jobs[&task.id];
        assert!(!job.effective_inputs.is_empty());
        for attempt in &task.attempts {
            let observation = runtime.observation(attempt.lease.attempt_id)?;
            let proof = observation.loaded.unwrap();
            assert_eq!(proof.model, "gpt-4.1");
            assert!(proof.source_threads.is_empty());
            assert!(proof.ambient_inputs.is_empty());
            assert_eq!(
                job.effective_inputs[&attempt.lease.attempt_id].prompt_sha256,
                proof.prompt_sha256
            );
            assert!(runtime
                .directory(attempt.lease.attempt_id)
                .join("context")
                .is_dir());
        }
        if job.role == nac_appsec::ResearchRole::Validation {
            assert!(!job.input.to_string().contains("DISCOVERER-"));
            let launch: Launch = read_json(
                &runtime
                    .directory(task.attempts[0].lease.attempt_id)
                    .join("launch.json"),
            )?;
            assert!(!launch
                .assignment
                .research
                .unwrap()
                .prompt
                .contains("DISCOVERER-"));
        }
    }
    let receipt = fixture.directory.join("workflow-receipt.json");
    std::fs::write(&receipt, serde_json::to_vec_pretty(&status)?)?;
    if let Some(path) = std::env::var_os("NAC_APPSEC_WORKFLOW_EVIDENCE") {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        std::fs::copy(receipt, Path::new(&path).join("workflow-receipt.json"))?;
        std::fs::copy(
            fixture.state.join("control.sqlite"),
            Path::new(&path).join("control.sqlite"),
        )?;
        std::fs::write(Path::new(&path).join("report.md"), status.markdown())?;
        for file in std::fs::read_dir(&fixture.state)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with("evidence-") {
                let target = Path::new(&path).join(file.file_name());
                if target.exists() {
                    ensure!(
                        std::fs::read(&target)? == std::fs::read(file.path())?,
                        "exported evidence hash collision"
                    );
                } else {
                    std::fs::copy(file.path(), target)?;
                }
            }
        }
        std::fs::write(
            Path::new(&path).join("provider-requests.json"),
            serde_json::to_vec_pretty(&*requests.lock().unwrap())?,
        )?;
    }
    Ok(())
}
