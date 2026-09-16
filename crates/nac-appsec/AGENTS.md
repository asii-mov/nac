# nac-appsec guide

`nac-appsec` owns runtime-neutral security campaign control. It does not depend
on `nac-core`, `nac-server`, Axum, or provider wire types. The security database
is canonical; runtime episodes and final prose cannot authorize acceptance.

## Owners

- `records.rs` owns strict version-1 manifests and durable campaign records.
  Execution state, candidate evidence state, and remediation state are separate.
  Candidate evidence remains immutable. Independent source verdicts append as
  separate accepted records. Remediation remains not-started.
- `controller.rs` owns admission, cancellation, resumption and reconciliation.
  Tokens and money have no ceilings. Separate liveness, meaningful progress,
  warning/diagnostic state and failed-recovery streaks drive the watchdog.
- `submission.rs` owns one public reserve/upload/verify/accept operation.
  Idempotency keys are scoped to tasks, not attempts. A new generation still
  needs an active fence before replaying any previous accepted submission.
- `repository.rs` owns the narrow repository port and SQLite adapter. One
  campaign is an atomic aggregate; immediate transactions also count host-wide
  occupied slots across campaigns. The JSON aggregate is not a transcript.
- `artifacts.rs` owns capability-relative no-follow immutable evidence files.
  `source.rs` reads Git blobs at full declared commits, not checkout contents.
- `runtime.rs` owns the scheduler port. A runtime's capability declaration is
  a trusted adapter contract, not proof that a provider implements it.
- `workflow_records.rs` owns consumed recon, coverage, family, synthesis and
  validation contracts. `workflow_admission.rs` applies them in the existing
  acceptance transaction. `workflow.rs` owns role-scoped queries, prepared
  contexts, observed input provenance, effort accounting and workflow reports.
  These modules do not own a second database or model loop.
- `workflow_questions.rs` validates append-only source questions and their cited
  resolutions. These are not the frozen map's fixed required-input blockers.
- `tests/cases/` owns real repository/filesystem/concurrency/crash fixtures.
  The child worker entry point exists only inside the integration-test binary.

## Runtime contract

`start` uses the service-issued attempt ID as a durable idempotent launch key.
`cancel` must tombstone that key and stop all descendants, including a launch
that races cancellation. `Terminated` means no live or pending launch for that
key can later consume a slot. An absent process by itself is insufficient when
a launch may still be pending. Uncertain launch/termination keeps the slot.

`Live.oldest_active_operation` identifies the oldest currently active bounded
operation, using a stable adapter-owned ID and its original trusted Unix start
time in milliseconds. NAC can run concurrent tools; a newer neighboring call
must not replace an older active call in this observation. When the oldest call
finishes, the next oldest can take its place without an intervening idle poll.
The controller persists the last identity/time across restarts and rejects a
changed start time for the same ID. Progress never extends that operation's limit.

The runtime must bound individual operations and each inserted tool response, while
allowing productive work to continue without token, call-count or total-duration
ceilings. Usage is cumulative and its completeness flag includes descendants and
interrupted provider requests. Missing values are unknown, never zero.

Only trusted source/tool/stage observations may populate `Live.progress`.
Heartbeats, logs and model prose are not meaningful progress. Artifact hashes
are verified and deduplicated across all task generations. Candidate submission
progress is keyed by verified source content, so arbitrary new attachment bytes
cannot reset the watchdog. Warning and a successful diagnostic request precede
suspected stall; suspected stall alone does not terminate a quiet process.

`Terminated.progress` uses the same trusted, bounded artifact receipt as live
progress. Stage acceptance atomically records `StopIntent::AcceptedResultCleanup`;
watchdog recovery, lease expiry, operation timeout, launch failure and operator
cancellation have distinct canonical intents. The observed physical exit is
persisted separately in `Attempt.runtime_exit`.

An accepted partial result with new meaningful progress and accepted-result
cleanup is a productive checkpoint when the physical exit is `Success` or
`Cancelled`. Killing a still-live runtime to clean up that checkpoint must not
consume the failed-recovery allowance. This does not exempt provider failures,
revoked recovery attempts, duplicate progress or cancellation without an accepted
stage. Operator cancellation remains cancelled, not a productive checkpoint.
Only confirmed termination releases the slot. Lease expiry does not replace a
cleanup intent already recorded by an accepted result; the individual physical
operation limit still applies while cleanup remains live.

Pinned Git source reads set both `GIT_NO_LAZY_FETCH=1` and an empty
`GIT_ALLOW_PROTOCOL`. Missing local objects are repairable input failures, not
permission to fetch from a promisor remote or mutate the source repository.

The server consumes this contract through its opt-in, Linux source-only managed
worker adapter. Frozen campaigns may dispatch; legacy manifests without frozen
skills and typed briefs remain blocked before admission. The scripted local
process/MCP/SQLite tests do not establish live native-subscription conformance.
Native hard-token ceilings are neither supported nor required by the current
owner policy. The original specification's total-budget requirement is overridden,
not reported as passing. Controlled experiments remain unsupported.

`brief.rs` renders typed assurance metadata and exact hashes. `skills.rs` resolves
the versioned registry and transitive resource lock without following paths;
`retrieval.rs` owns lease-checked pinned source and task-owned artifact ranges.
Inventory receipts track the union of delivered file-index ranges, an explicit
start marker and the pinned listing identity. A partial or hash-only receipt is
not map coverage; only complete enumeration can be frozen into a baseline.
Frozen research inputs are additive manifest data. Active campaigns reject drift
and must not silently re-resolve to a newer skill release.

Workflow mode is explicit (`appsec freeze --workflow`). It starts with one recon
root and captures registered stage templates from the original frozen lock, not
placeholder tasks. Legacy manual and source-only manifests remain supported and
do not acquire workflow authority on read. See `docs/appsec-workflow.md` for the
additive storage migration, decision revisions and conservative effort rule.

The workflow decision revision is the accepted-record count, checked at reservation
and final acceptance. Heartbeat-only aggregate revisions must not starve model
decisions. The SQLite aggregate still has its own transaction revision. Workflow
idempotency hashes omit the decision revision so a refreshed, identical decision
can retry its reserved key. Changed semantic content cannot reuse that key.

Parent topology never doubles as a completion dependency. Synthesis waits for
settled same-round work, including validation and physical cleanup. The existing
host-wide slot reservation counts every admitted role and retained cleanup slot.
Validator queries must remain blind to discoverer records and artifacts.

## Verification

Run `make setup` after lockfile changes, then:

```sh
cargo test --locked -p nac-appsec
cargo test --locked -p nac-server appsec
make crate-check CRATE=nac-appsec
make crate-check CRATE=nac-server
make format-check
make test-source-size
```

Keep private owner modules around 500 lines. Add behavioral tests when changing
transaction ordering, filesystem safety, generation fencing or budgets. Never
expose the deterministic workers as a production scan mode.
