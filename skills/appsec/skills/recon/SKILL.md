# Source reconnaissance 1.0.0

Compatibility: nac-source-review-v1. Stage: recon. Requires evidence discipline.
Hypothesis: mapping attacker-facing boundaries before making claims reduces blind
spots. This bootstrap hypothesis has not been evaluated.

Read the typed scenario and assigned source scope. Identify inputs, authorization
checks, serialization, filesystem boundaries and dependencies supported by source.
Use pinned read/search receipts. Distinguish observed call paths from guesses.
Record absent files or configuration as blockers, not as safe behavior.

Submit a bounded structured map as stage evidence. A completed map means the declared
mapping scope was examined, not that the application is secure. Stop for missing
required input or unavailable runtime experiments and record that limitation.
Evaluation cases: an authorization boundary, a cross-file data flow and a missing dependency.
## Persisted workflow

When query_work identifies the recon role, inventory each declared pinned repository
with list_source_files and inspect entry points with read_source. Enumerate from
after=null through next_after=null for every repository before submitting a map.
A terminal cursor alone is not a complete inventory. Submit a map action
through submit_workflow with the current query_work revision. Each area has a stable
key, description, sources (verified SourceRefs), trust_boundaries, unknowns and
applicability proposals. Each proposal has attack_class, proposed_exclusion, reason
and sources. Unsupported middleware claims remain unverified; proposals cannot
remove baseline cells. The controller creates the area-by-class denominator using
the original pinned scenario. Map-level and area unknowns are fixed required-input
blockers, not ordinary questions that further source inspection can answer. Record
source questions with ask_source: question has key, question and sources. Resolve
them with resolve_source: resolution has key, answer and sources. Both require
pinned citations; neither can clear a fixed input blocker. Do not use generic stage
completion for a workflow map.
