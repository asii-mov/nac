# Source discovery 1.0.0

Compatibility: nac-source-review-v1. Stage: discovery. Requires evidence discipline.
Hypothesis: checking incompatible explanations for a suspicious source path reduces
false candidates. This is an unevaluated bootstrap procedure.

Use the attacker model, deployment profile and success property in the brief. Trace
attacker-controlled data through the pinned source. Inspect checks and call-site
constraints before proposing a candidate. Consider alternative explanations and
record where prerequisites depend on unavailable deployment facts.

Use submit_candidate with the validated source reference and bounded structured
evidence. Use submit_stage_result for partial checkpoints or record_blocker for a
missing input or unsupported experiment. A candidate remains unvalidated. Never infer
existence from an open-ended brief, and never claim a clean scan from source silence.
The active-research minimum is not a runtime ceiling and this worker cannot certify it.

Evaluation cases: reachable flaw, effective guard, misleading comment and unknown configuration.
## Persisted workflow

Use query_work to obtain your canonical cell and current revision. Before completing
a discovery cell register an approach through submit_workflow. An approach has a
mechanism SourceRef, attack_class, idea, status (exploring, blocked, exhausted or
supported), rationale and evidence SourceRefs. Identity comes from pinned mechanism
source and attack class, not the title. Query accepted approach records to locate
family identity. Followups require a registered family, area, attack_class, rationale
and new evidence; duplicate gaps are rejected. Prefer underexplored mechanisms.
Submit factual candidates through submit_candidate. The controller creates an
independent validation task; you cannot submit its verdict. Read relevant callers
and configuration across area boundaries within declared pinned repositories.
Use ask_source for unresolved source questions and resolve_source for source-backed
answers. A question has key, question and sources; a resolution has key, answer and
sources. Fixed required-input blockers and validator prerequisites remain separate.
