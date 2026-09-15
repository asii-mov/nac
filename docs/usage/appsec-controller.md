# Durable application-security controller

This layer persists security campaign inputs, task dependencies, attempts and
accepted evidence. A frozen campaign can run the source-only managed-worker
adapter described in [source-only runtime](appsec-runtime.md). An unfrozen
manifest still records a blocked campaign and exits with code 3 without a model
call. Scripted local adapter conformance is separate from live native-subscription
conformance, which remains pending. Offline `appsec doctor` is unchanged.

The current owner policy has no token, monetary, total-call or campaign-duration
ceiling. Tokens are observations only. Productive work may continue; a progress
watchdog diagnoses possible stalls. Individual operations, response sizes,
concurrent investigative agents and consecutive failed recoveries remain bounded.
This overrides the original specification's total-budget stop policy.

## Create and inspect a campaign

Use a full commit object ID and an absolute local checkout path. Source references
are checked against blobs at that commit, not the working tree. Declare unavailable
inputs as `null`; reports show them as unknown. The example configures controller
state, not a resolved model runtime or frozen skill bundle.

Source validation never fetches missing objects from a partial clone. It disables
lazy fetching and all Git protocol transports. Provision required commits, trees
and blobs explicitly before running the controller; missing local objects produce
an input error without changing the repository's object store.

```json
{
  "schema_version": 1,
  "repositories": [
    {
      "identity": "service",
      "checkout": "/absolute/path/to/service",
      "commit": "REPLACE_WITH_FULL_LOWERCASE_COMMIT_ID"
    }
  ],
  "declared_inputs": {
    "environment": null,
    "dependencies": null,
    "fixtures": null,
    "deployment": null,
    "harness_commit": null,
    "runtime_version": null,
    "model_configuration": null,
    "skill_bundle": null
  },
  "monetary_policy": "uncapped",
  "token_policy": "observe_only",
  "watchdog": {
    "warn_after_ms": 300000,
    "stall_after_ms": 600000,
    "diagnostic_grace_ms": 30000,
    "lease_ms": 120000,
    "max_failed_recoveries": 3
  },
  "max_concurrency": 4,
  "tasks": [
    {
      "key": "baseline-cell",
      "scope": "Inspect the declared service entry points",
      "dependencies": [],
      "operation_limits": { "wall_ms": 1200000, "output_bytes": 16384 }
    }
  ]
}
```

```sh
nac-web appsec run --manifest campaign.json --state /private/parent/security-state
nac-web appsec status --state /private/parent/security-state --run-id RUN_ID
nac-web appsec report --state /private/parent/security-state --run-id RUN_ID --output new-report
nac-web appsec cancel --state /private/parent/security-state --run-id RUN_ID --revision REVISION
nac-web appsec resume --state /private/parent/security-state --run-id RUN_ID --task-id TASK_ID --revision REVISION --handoff 'Reason for resuming unfinished scope'
```

The state directory is created with mode 0700 and must remain owner-only.
Parent directories must exist. Symlink path components are rejected. JSON output
supplies service-assigned IDs and the current revision. Cancellation and resumption
require that revision; stale commands fail. Resumption queues a task without
dispatching a model. It refuses a task with an unreconciled runtime slot or an
exhausted consecutive-failure allowance.

Reports contain JSON and Markdown and require a new output directory. Status and
reports recheck accepted artifact hashes. Missing or corrupt evidence produces an
error instead of silently dropping the evidence. Reports expose incomplete scope,
unknown inputs, pending uploads, usage uncertainty and watchdog state.

## Durable control

`Controller::dispatch_next` atomically reserves a runtime slot before adapter
launch. SQLite counts occupied slots across campaigns in one state directory;
the CLI persists a host capacity of four. A runtime must include its root and
runtime-created investigative children in that authority. Separate state
directories are separate controllers, not a way to bypass host admission.

`Controller::submit` validates a typed payload and source reference, records a
pending submission, writes immutable content-addressed artifacts, then accepts
the result in a fenced SQLite transaction. A crash before acceptance may leave
an orphan artifact and pending submission, but no accepted result. Identical
task-scoped keys return the original accepted ID; different content conflicts.
An old generation cannot submit or replay after resumption. Staging files left
by crashes are diagnostic orphans, not accepted evidence. Automatic orphan
retention/garbage collection is not implemented.

Candidates are accepted incrementally and survive failure or cancellation.
Completion requires a typed result for exactly the declared task scope plus
evidence. That records execution completion, not independent security assurance.
Arbitrary final prose never completes a task; zero findings never proves safety.
This layer cannot advance evidence beyond candidate or remediation beyond
not-started.

## Progress and recovery

The runtime adapter reports liveness separately from meaningful progress.
Polling a responsive runtime renews an unexpired lease but does not refresh
semantic progress. Trusted source/tool/stage observations reference hash-verified
artifacts. Their content hashes are deduplicated across task generations.
Heartbeats, log chatter and model claims of continued work must not be classified
as meaningful observations. New candidate progress uses its verified source
content hash, not arbitrary attachment text.

After the warning interval, the controller requests runtime diagnostics. Only a
later observation, after diagnostics and the stall interval, can mark a suspected
stall. A suspected stall stays running; a quiet legitimate operation is not
declared dead. The runtime watcher prints transition-only notices. An operator can
invoke revision-checked `appsec recover` after examining that state; see the
[runtime operator commands](appsec-runtime.md#watch-cancel-and-recover).
Recovery revokes the lease and requests cancellation, preserves evidence,
and requires confirmed termination before `resume` can queue another generation.
New meaningful progress resets the failed-recovery streak, not total attempt count.

Trusted progress receipts can arrive with termination as well as during polling.
The controller records accepted-result cleanup intent atomically with a structured
stage result, separately from watchdog/lease/operator interruption and from the
observed physical exit. A productive partial checkpoint can end with `Success` or
`Cancelled`: cancelling a still-live runtime for normal checkpoint cleanup does
not consume the failed-recovery allowance. Provider failures and revoked recovery
attempts are not normal cleanup. Duplicate receipts do not reset the allowance,
and cancellation/progress without an accepted stage result cannot create a
checkpoint or make a task complete. Status exposes both stop intent and physical
exit, without freeing a runtime slot before confirmed termination.

An individual operation's original start time is bounded separately. The runtime
reports `oldest_active_operation` with a stable ID and trusted start time. With
concurrent tools, it must report the oldest still-active call, not the latest call
or latest output. Distinct adjacent operations can replace each other without an
idle poll. The controller persists the last identity/time across restart and
rejects a timestamp change for the same identity; progress cannot extend that
operation's deadline.
Controller observation of its timeout requests cancellation; the runtime adapter
must enforce the actual operation boundary, including children. Polling alone is
not a hard execution guarantee. Lease expiry also revokes submission rights and
requests termination but keeps the slot until the runtime confirms no current or
pending launch can consume it. An absent process is not sufficient if launch may
still be pending. Runtime cancellation must tombstone the service-issued launch
key and cover descendants.

## Current acceptance scope

- T03 controller crash windows use actual SIGKILL workers before upload, after
  upload, after database commit and before acknowledgment.
- T04 covers stale generations, identical/conflicting submissions and retention
  across retries through independent SQLite connections.
- T05 covers zero findings, partial scope, blockers, provider failure and
  cancellation without treating runtime prose as completion.
- T06 covers strict schemas, invalid source identity/commit/path/line/hash,
  missing/corrupt artifacts and unsafe symlink rejection.
- T07 is partially superseded by the owner's no-ceiling policy. Controller tests
  cover concurrency, individual response limits, liveness/progress separation,
  diagnostic-before-stall ordering and bounded failed recoveries. Original
  total-token/time/call exhaustion is intentionally not enforced or claimed.

This is not full T02 conformance or a pilot release. Native descendant control,
watchdog event classification, operation enforcement, frozen skills, independent
validation, experiments, remediation, evaluator equivalence and release
demonstrations remain later-layer work.
