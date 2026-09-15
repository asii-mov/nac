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
