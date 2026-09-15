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
