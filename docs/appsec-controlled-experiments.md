# Controlled appsec experiments

Controlled experiments are an opt-in pilot for locally reviewed HTTP targets. They
do not change ordinary orchestrator, direct, direct-with-orchestrator, manual appsec
or source-only behavior. They do not support arbitrary drivers, shell access, live
dependency retrieval, memory-safety grading, non-HTTP protocols or model-selected
targets.

The pilot has two supported oracle classes. The authorization oracle requires owner,
intentionally public, legitimate-use and health controls, then confirms only actual
forbidden object delivery or state change. State-change confirmation requires a
private successful pre-read, an attacker write, and a successful post-read that
differs from the pre-state and exactly matches the submitted value. The RCE nonce oracle requires benign,
no-prerequisite, legitimate-use and health controls, then confirms only exact current
target nonce disclosure. Missing service health, failed controls, incomplete capture,
uncertain delivery or identity drift cannot produce `not_observed`. A reduced demo
stays a reduced demo regardless of its result.

## Prepare local inputs

Use `prepare-local-pilot` for the checked-in Go pilot. The command accepts one
reviewed `main.go` from a full local Git commit and an explicit attacker interface.
It does not adapt external evaluation recipes.

Create `interface.json` for the authorization pilot:

```json
{
  "max_requests": 4,
  "routes": [
    {
      "actor": "attacker",
      "method": "get",
      "path_prefix": "/object/owner",
      "max_body_bytes": 0
    },
    {
      "actor": "attacker",
      "method": "post",
      "path_prefix": "/state",
      "max_body_bytes": 8192
    }
  ]
}
```

Run the preparation command from a machine with `/usr/local/go/bin/go` and Docker:

```sh
nac-web appsec prepare-local-pilot \
  --repository /absolute/path/to/local-pilot \
  --commit FULL_LOWERCASE_COMMIT \
  --repository-id local-pilot \
  --include main.go \
  --interface interface.json \
  --oracle authorization \
  --output prepared-pilot
```

The command writes `prepared-pilot/experiment-profile.json` with mode `0644` and
`prepared-pilot/private-pilots.json` with mode `0600`. It creates pinned local
builder, vulnerable, and protected image digests. The two target images carry
`nac.appsec.variant` labels. Keep the images available until all runs finish.

The command uses `SourcePackage::freeze` and `SourcePackage::export`. These methods
read local pinned regular Git blobs and write a fresh immutable package. They reject
Git metadata, hidden paths, answer paths, symlinks, gitlinks, special files, excluded
paths, and source drift. All source operations use that package while the profile is
active.

Dependencies must already exist as regular local archive files staged under
`appsec-state/dependencies/<archive_sha256>.tar`. Record package,
version, HTTPS source URL, source ref and SHA-256, then materialize them through
the controller-mediated `read_dependency_source` operation or
`PrefetchedDependency::materialize`. It accepts strict POSIX ustar regular files and
directories only. Missing bytes, credential-bearing URLs, content drift, traversal,
links and special files block setup. NAC does not fetch, redirect, browse history or
claim cache-download conformance.

Campaign admission validates dependency provenance before any profile enters a
model prompt. Empty identities, non-HTTPS URLs, credentials, ambiguous URL syntax,
and malformed archive hashes fail admission.

Each `FrozenPilot` record pins the public recipe and target identities. It also pins
the local Docker image, the builder image, the source export, the build receipt, the
environment, the evaluator identity, and the rubric. Registration copies the source
into a second immutable export. The Go builder recompiles `main.go` without network
access. The builder runs as a non-root user with a read-only root, no capabilities,
no new privileges, a seccomp profile, and finite process, memory, CPU, cache, and
output limits. Registration compares the binary with both the build receipt and
`/target` in the pinned image. It then removes the builder and inspector containers
and writes an immutable private receipt. The fixture uses a scratch image with one
fixed `/target` entry point and no build-time `RUN`. Registration never pulls an
image or falls back to a checkout. The local fixtures under
`crates/nac-server/tests/fixtures/appsec-pilot/` are test-only and are not an external
evaluation adaptation.

## Freeze and run

Freeze skills, the brief and the public profile together:

```sh
nac-web appsec freeze \
  --manifest manifest.json \
  --skills skills/appsec \
  --brief brief.json \
  --experiment-profile prepared-pilot/experiment-profile.json \
  --output frozen-manifest.json
```

Register the private pilots and create the campaign with a finite, host-wide target
capacity:

```sh
nac-web appsec run \
  --manifest frozen-manifest.json \
  --state appsec-state \
  --experiment-registry prepared-pilot/private-pilots.json \
  --target-capacity 2
```

The registry bytes become immutable state. Editing either source registry file cannot
change an active campaign. Omitting the experiment profile, registry and target
capacity preserves source-only operation.

Discovery and validation receive bounded experiment operations plus pinned dependency
source reads. The run request contains only a task-scoped key, recipe ID, hypothesis,
pinned source citations and requests inside the declared public interface; mandatory
controls and evaluator routes remain private. The model cannot supply a lease, role, engine, host,
target, actor credential, oracle, expected nonce or secret. Recon and synthesis have
no experiment authority. Discovery may run an experiment before candidate submission.

To link an experiment to a candidate or validation, use the exact candidate claim as
the experiment hypothesis and include the exact candidate `SourceRef`. Accepted links
make the experiment immutable. A later validator experiment that conflicts with
reproduced candidate evidence produces an inconclusive evidence state rather than
silently replacing the earlier record.

## Operate and inspect

The normal watcher reconciles investigator and experiment cleanup. Operators can run
one target reconciliation step, inspect a safe experiment projection, commit a stop
tombstone or drive only local pilot cleanup:

```sh
nac-web appsec experiment-reconcile --state appsec-state --run-id RUN
nac-web appsec experiment-read --state appsec-state --run-id RUN --experiment-id EXPERIMENT
nac-web appsec experiment-cancel --state appsec-state --run-id RUN --experiment-id EXPERIMENT
nac-web appsec experiment-recover --state appsec-state --run-id RUN --experiment-id EXPERIMENT
nac-web appsec experiment-demo --state appsec-state --run-id RUN
```

The adapter creates one internal isolated Docker network per trial and publishes no
host ports. It verifies the exact image and launch configuration, non-root identity,
read-only root, dropped capabilities, no-new-privileges, explicit default seccomp,
PID/memory/CPU limits, no mounts or host namespaces, disabled engine logging and the
internal IPv4-only isolated network. A fixed privileged host broker pins the target
process identity, enters only its network namespace, drops to UID/GID 65534, sends
the registered HTTP request to loopback and refuses alternate authority, redirects,
proxies and CONNECT. Missing Docker, seccomp, namespace access or isolation is
unsupported. It never translates Podman configuration or uses an ordinary NAC
execution backend.

The adapter-owned network probe rejects routes to metadata, public test addresses,
IPv6, and every other running controlled target address. Connection refusal does not
count as isolation. The adapter also rejects extra effective network attachments.

Raw exchanges, paths, capture IDs, bytes, canary plaintext/hash, actor credentials and
evaluator rules stay in the owner-only target spool. `read_experiment`, status,
reports, MCP errors and artifact-range APIs expose only closed assessment, control and
diagnostic codes. The fixed sanitizer may publish a recognized code and byte offset;
unknown text remains withheld. Operators who already own the private state can use
the narrow `AppsecTargetRunner::private_diagnostic` method. Models have no route to it.
Component captures remain in their owner-only spools. If their combined projection
would exceed the aggregate private bound, evaluation records a bounded marker and
closes inconclusively instead of entering adapter recovery.

Builder stdout and stderr use a separate 16 MiB cap per stream. Docker attaches to
the live builder while the engine log driver remains disabled. NAC stores complete
output under the owner-only build-verification directory when it fits. On overflow,
NAC stores bounded head and tail ranges and marks the capture incomplete. The
operator-only `AppsecTargetRunner::operator_build_diagnostics` projection exposes
only a fixed diagnostic code, the validated `main.go` path, a valid line and column,
the stream offset, and truncation state. It never exposes compiler text to a model.

Intent and target capacity commit before Docker effects. Unique run keys are never
reused. Pending create, start or request operations remain explicit; the adapter does
not replay an uncertain request in the same trial. Cancellation commits before
cleanup, and confirmed cleanup requires no live target, no network and no pending
create. Assessment and cleanup are separate. Parent exit, lease expiry, recovery and
campaign cancellation fence experiments, while an accepted assessment survives a
later cleanup request. A fresh reset is allowed only after old cleanup is proved and
uses a new epoch, run key and target-only secrets.

This pilot does not establish full scanner readiness, external evaluation adaptation,
live-subscription conformance, reproduction on an original target, remediation or
security assurance.
