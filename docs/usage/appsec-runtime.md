# Source-only application-security runtime

The Linux adapter runs controller-owned managed workers through NAC's existing
Agent loop. It does not add a session behavior. The selected model route is native
OpenAI subscription, `chatgpt-codex-responses`, with `gpt-5.6-sol` and `high`
reasoning by default. There is no paid-API or Daybreak fallback. Local scripted
provider tests are test-binary fixtures, not a production scanner mode. Live
subscription conformance still requires the final authorized device phase.

## Capability boundary

This is a tool-mediated source-review profile, not an arbitrary-code sandbox.
The worker sees only seven attempt-bound MCP tools:

- `list_source_files` pages through regular source paths at a declared commit.
- `read_source` reads a bounded line range of a regular blob at a declared commit.
- `search_source` searches a bounded pinned range for a literal string.
- `submit_candidate` calls canonical controller submission validation.
- `submit_stage_result` records a structured scope checkpoint through that same authority.
- `record_blocker` records a typed blocked result.
- `read_artifact_range` reads a bounded range of evidence accepted for the same task.

Native filesystem, shell, web and delegation tools are absent from the request
inventory and denied at invocation. Capability refresh cannot restore native web
tools. The worker cannot select another backend or launch investigative children.
The controller's four-slot admission limit includes a root investigator when one
is represented as a task. The supervising processes are not model actors.

Only declared source blobs are exposed. Source retrieval rejects `.git`, traversal,
symlinks and undeclared repositories; it cannot select another commit or fetch Git
objects. The serialized requested range must fit the tool-response limit; the
complete original blob supplies its content hash. A short range from a file larger
than the tool-response limit is supported. The controller's Git lookups have a
separate 10-second, 16-MiB infrastructure bound. Streaming beyond that blob limit
and repository-wide content indexing are not implemented. Inventory pages expose
only safe UTF-8 regular-file paths, with a bounded count, serialized-size limit and
`next_after` cursor. The worker receives declared repository identities and pinned
commits, never host checkout paths, so a neutral brief can start with inventory.
Provider networking and the loopback authenticated MCP connection are runtime
networking, not model-visible web tools.

The process retains ordinary host privileges for its trusted runtime and provider
authentication. This profile does not claim protection against a compromised NAC
binary, controller, operator account or arbitrary code execution. It does not mount
an OS sandbox. SSH/Podman execution, controlled experiments, reproduction,
remediation, dependency downloads and deployment verification are unsupported;
the adapter does not silently substitute local execution for an existing backend.

## Freeze inputs

Start with the [controller manifest](appsec-controller.md). Write a version-1 brief:

```json
{
  "schema_version": 1,
  "assurance": { "mode": "open_ended" },
  "source_root": "service/",
  "attacker_model": "Unauthenticated remote attacker",
  "deployment_profile": "Describe the concrete deployment and pinned dependencies",
  "impact_goal": "Describe the security impact being sought",
  "success_property": "Describe the observable needed to confirm success",
  "minimum_active_research_ms": 21600000,
  "max_investigative_agents": 4
}
```

Only `known_solvable` includes the evaluator-established existence statement. It
requires an operator-supplied `evaluator_approval` reference in the assurance object.
The adapter does not read evaluator answers or grading data. An open-ended brief
explicitly says that the repository may or may not contain a qualifying flaw.

```sh
python3 scripts/appsec-skill-lock.py --check
nac-web appsec freeze --manifest campaign.json \
  --skills /absolute/nac/skills/appsec --brief brief.json --output frozen.json
nac-web appsec run --manifest frozen.json --state /private/parent/security-state
```

`freeze` selects the discovery stage for each declared task. The Rust
`FrozenResearch::resolve` API also supports explicit per-task recon or source
validation selection. It reads `skills.md`, verifies `skills.lock.json`, resolves
transitive dependencies and loads the selected resource bytes. Missing helpers,
incompatible locks, symlink paths and hash drift fail before model execution.
`scripts/appsec-skill-lock.py` is the sole writer of the bootstrap lock. Regeneration
is a release proposal, not evidence that a skill is better.

The manifest stores the exact lock, selected bytes and selection reasons. Each
dispatch rechecks the frozen inputs instead of absorbing edits. The actual worker
reports fresh session/thread/dispatch identities, an empty source-thread list,
empty ambient-input list, the exact effective prompt/action/message hashes and the
effective tool inventory over the trusted control channel. It uses a new empty
diagnostic store and loads no ambient AGENTS, MCP configuration, skills or history.
The provider's native authentication remains separate from those model inputs.

## Watch, cancel and recover

`run` prints the campaign identity, dispatches admitted work and watches it. After
a controller-process restart, reopen the same state directory:

```sh
nac-web appsec watch --state /private/parent/security-state --run-id RUN_ID
nac-web appsec status --state /private/parent/security-state --run-id RUN_ID
nac-web appsec cancel --state /private/parent/security-state --run-id RUN_ID --revision REVISION
```

`watch` writes a stderr notice when an active attempt enters Warning or
SuspectedStall, or when verified meaningful progress returns it to Healthy.
Unchanged polls do not repeat notices. A warning requests a diagnostic; suspected
stall requires that diagnostic and its configured grace period. Neither notice
automatically stops a quiet worker.

`cancel` first revokes canonical submission authority, then tombstones every held
attempt and reconciles cleanup. It signals the runtime even without a watcher.
If cleanup remains uncertain, the command reports an error after recording the
cancellation. It attempts to signal all held keys even if one signal fails, before
observation starts.
A separate supervisor survives the controller connection and owns `nac-process`
descendant cleanup. It gives cooperative cancellation a short grace, then forces
cleanup. A final runtime receipt is written only after cleanup succeeds. Run
`watch` to reconcile that eventual receipt and release the canonical reservation.

To stop a diagnosed suspected stall explicitly, inspect the latest revision and
task identity, then request recovery:

```sh
nac-web appsec status --state /private/parent/security-state --run-id RUN_ID
nac-web appsec recover --state /private/parent/security-state \
  --run-id RUN_ID --task-id TASK_ID --revision REVISION
```

`recover` rejects stale revisions and attempts that have not reached a diagnosed
suspected stall. It calls the canonical recovery transition, revokes the attempt
and reconciles the runtime; it does not launch a replacement. A retained slot
still prevents resumption until termination is confirmed. After `watch` reconciles
cleanup, use a fresh revision and a nonempty handoff of at most 4096 bytes:

```sh
nac-web appsec resume --state /private/parent/security-state \
  --run-id RUN_ID --task-id TASK_ID --revision REVISION \
  --handoff "Describe the verified checkpoint and the next investigation step"
```

The existing consecutive failed-recovery limit still applies. `resume` only queues
the task; a subsequent `watch` admits its next attempt. A concurrently running
watcher can change the revision, so reread status if the mutation rejects it.
The new worker receives the explicit handoff as JSON continuation data in its user
action, under the unchanged frozen research instructions. Its action hash includes
that data. Resumption does not load prior worker episodes or ambient history.

Every attempt ID is a durable launch key. Launch and cancellation share a file
lock, and cancellation writes a durable tombstone. A supervisor arriving after
cancellation checks the tombstone before constructing a worker. Process absence
alone never releases a slot. If the supervisor itself is lost before it writes
a terminal cleanup receipt, the attempt remains uncertain and retains its slot.
`child-admission.json` starts as `pending`. Under the launch gate, the original
supervisor durably changes it to `child_may_exist` before `nac-process` can fork
either the process-group leader or the worker. A replacement supervisor refuses
that phase even when a tombstone exists. Only an explicitly pending, unadmitted
launch can be acknowledged as cancelled without process cleanup. Missing phase
records are uncertain. Terminal receipts are final: later supervisor invocations
return without changing the receipt, connection or worker context.
Automatic recovery from supervisor loss or host reboot is not implemented in this
layer. Do not delete its records or infer cleanup from a missing PID.
Live observations require a held supervisor ownership lock and a snapshot no more
than five seconds old. Missing ownership, missing timestamps, backward clock
movement or stale snapshots report unavailable observations and do not renew the
controller lease. They do not produce a terminal cleanup receipt.

The trusted channel uses a separate Unix socket with Linux peer-PID checks. MCP
stderr and worker stdout/stderr are diagnostics only. They cannot forge progress,
usage, cancel acknowledgements or cleanup. Bounded diagnostic logs, the loaded
inventory and runtime observations live under `state/workers/ATTEMPT_ID` outside
the model tools' authority. The authenticated MCP connection supplies the service
lease/fence; model arguments cannot choose it. SQLite and immutable accepted
artifacts remain canonical, not worker episodes or final prose.

## Progress and incomplete assurance

There are no token, money, total-call or worker-lifetime ceilings. Each model or
tool operation has an adapter-owned identity and its original start time. Parallel
calls retain separate identities, and observation reports the oldest active call.
Each model/tool operation uses the task's wall-time bound. The response-byte bound
applies to tool results inserted into context and to controller submissions, not
to model reasoning or encrypted reasoning replay. Provider parser and transport
resource safeguards remain unchanged. Controller
watchdog warnings, diagnostics, leases and failed-recovery limits remain in force.
The watcher reconciles diagnostics but does not automatically recover a suspected
stall. Diagnostic facts alone do not establish a stalled model or authorize recovery.

Only controller-verified source/tool/stage receipts count as meaningful progress.
Repeated ranges from the same source blob produce the same progress artifact.
Logs, heartbeat snapshots and model claims do not extend the progress clock.
Accepted-result cleanup is a canonical stop intent distinct from physical process
cancellation. A partial accepted checkpoint does not become a failed recovery
merely because cleanup terminated the worker.

Observed tokens and tool-response bytes are retained, but usage completeness remains
false: provider retries and interrupted requests are not fully observable. Missing
usage is unknown, not zero, and no dollar estimate is invented. The six-hour deep
profile minimum remains a minimum in the typed brief, not a lifetime ceiling.
This layer does not implement or certify active-research accounting, dynamic
portfolio scheduling, independent security review, exploit validation or a clean
no-finding conclusion. A completed source scope is not security assurance.
