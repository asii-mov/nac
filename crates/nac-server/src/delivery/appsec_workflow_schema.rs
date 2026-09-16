use serde_json::{json, Value};

fn object(properties: Value) -> Value {
    let required: Vec<_> = properties
        .as_object()
        .into_iter()
        .flat_map(|properties| properties.keys().cloned())
        .collect();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}

fn array(items: &Value) -> Value {
    json!({"type":"array","items":items})
}

fn action(operation: &str, name: &str, value: Value) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("operation".into(), json!({"const":operation}));
    properties.insert(name.into(), value);
    object(Value::Object(properties))
}

pub(super) fn submission(evidence: Value) -> Value {
    let text = json!({"type":"string"});
    let texts = array(&text);
    let fixed_unknowns = json!({"type":"array","items":text,"description":"Fixed required-input blockers. Use ask_source instead for ordinary questions answerable from the same pinned source."});
    let source = object(
        json!({"repository":text,"commit":text,"path":text,"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1},"content_sha256":text}),
    );
    let sources = array(&source);
    let question = object(json!({"key":text,"question":text,"sources":sources}));
    let resolution = object(json!({"key":text,"answer":text,"sources":sources}));
    let class = json!({"enum":nac_appsec::BASELINE_CLASSES});
    let proposal = object(
        json!({"attack_class":class,"proposed_exclusion":{"type":"boolean"},"reason":text,"sources":sources}),
    );
    let area = object(
        json!({"key":text,"description":text,"sources":sources,"trust_boundaries":texts,"unknowns":fixed_unknowns,"applicability":array(&proposal)}),
    );
    let map =
        object(json!({"operation":{"const":"map"},"areas":array(&area),"unknowns":fixed_unknowns}));
    let approach = object(
        json!({"mechanism":source,"attack_class":class,"idea":text,"status":{"enum":["exploring","blocked","exhausted","supported"]},"rationale":text,"evidence":sources}),
    );
    let followup = object(
        json!({"area":text,"attack_class":class,"family":text,"rationale":text,"evidence":sources}),
    );
    let experiment_ids =
        json!({"type":"array","maxItems":8,"items":{"type":"string","format":"uuid"}});
    let validation = object(
        json!({"outcome":{"enum":["supported","disproved","inconclusive"]},"prerequisites":text,"reachability":text,"security_violation":text,"sources":sources,"counterevidence":sources,"unknowns":{"type":"array","items":text,"description":"Material unresolved prerequisites for this verdict. Must be empty for supported or disproved; unrelated manifest-level unknown context stays in the manifest."},"next_actions":texts,"experiments":experiment_ids}),
    );
    let synthesis = object(
        json!({"assumptions":texts,"counterevidence":sources,"gaps":texts,"next":array(&followup),"finish":{"type":"boolean"}}),
    );
    object(
        json!({"key":text,"revision":{"type":"integer","minimum":0},"action":{"oneOf":[map,action("ask_source","question",question),action("resolve_source","resolution",resolution),action("approach","approach",approach),action("followup","request",followup),action("validate","validation",validation),action("synthesize","synthesis",synthesis)]},"evidence":evidence}),
    )
}
