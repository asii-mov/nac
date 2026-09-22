# 0004 — Appsec remediation acceptance

Status: proposed

## Context

The appsec controller durably discovers, validates, and reproduces findings, but
it does not change source. A fix must not mutate accepted finding evidence or
turn successful patch generation into proof of remediation. The patch author
must not see evaluator-private assertions, fixtures, secrets, or reference
answers, and the evaluator must not trust the patch author's workspace or test
claims.

The generic session worktree is not an appsec boundary. It starts from the
current checkout, shares Git objects and refs, may preserve changed branches,
and can fall back to the live workspace. The source-only appsec worker also has
no write or terminal authority. Widening either existing path would weaken
unrelated campaigns.

## Decision

NAC uses a sealed-pair remediation journal for the first checked-in Go
authorization pilot.

### Durable ownership

`nac-appsec` owns an optional frozen remediation profile and append-only
remediation cases inside the existing campaign aggregate. Missing fields default
to no remediation, preserving stored and source-only campaigns. A remediation
case is not a research task and does not change campaign execution or workflow
completion.

Each case binds one immutable provenance triple:

1. The accepted candidate and exact accepted supporting validation, including
   both payload hashes and the workflow decision revision.
2. The pinned repository commit, source-package manifest, dependencies,
   declared inputs, configuration, environment, skill bundle, model, runtime,
   extractor, prompt, and effective worker input identities.
3. The evaluator-owned assertion version, recipe, oracle, rubric, fixture, and
   required-check identities.

For reproduced findings, the assertion must use the experiment recipe and
oracle that established reproduction or record an explicit version-bound
operator review of the substitution. Every replacement assertion version needs
the same explicit review and reruns both targets; prior versions and results
remain historical. Static-supported findings additionally require an operator
review record and cannot claim reproduced acceptance.

The journal records desired effects before execution and appends observations
afterward. Current remediation state is derived from journal history. Accepted
candidate and validation records remain byte-for-byte immutable. A later
validation, input drift, or assertion revision supersedes the case rather than
rewriting it.

The controller re-derives the latest finding and validation state and verifies
the assertion version and complete effective-input fingerprint before every
effect, before reporting a package as currently accepted, and before authorizing
publication. Historical package bytes remain reproducible after drift, but the
package is marked superseded and loses publication readiness.

Every effect has a service-issued ID, case generation, phase, plan hash, and,
after generation, patch hash. A revision-checked transaction appends its intent
before any launch. Only one effect may be pending for a case. Observations must
echo those identities. Success and evaluation observations are rejected after
cancellation, supersession, or a new generation. Cleanup-only observations for
the tombstoned effect ID remain admissible until cleanup settles. An adapter
must reconcile the same effect ID rather than replay an uncertain action under
a new identity.

Cancellation appends a tombstone before signaling adapters. A late cleanup
observation may release reservations but cannot advance patch or evaluation
state. Cleanup is settled only after the adapter proves that no process descendant, delayed launch,
workspace, target container, or network can reappear. Late observations cannot
advance a tombstoned case. Generator and evaluator reservations are admitted in
the same SQLite transaction as intent and remain occupied through uncertain
cleanup.

### Deep controller interface

The runtime-neutral controller surface is deliberately small:

```rust,ignore
fn request_remediation(
    run: Id,
    expected_revision: u64,
    request: StartRemediation,
) -> Result<RemediationCase>;

fn reconcile_remediation<G: PatchGenerator, E: PatchEvaluator>(
    run: Id,
    remediation: Id,
    generator: &mut G,
    evaluator: &mut E,
) -> Result<RemediationCase>;

fn materialize_package(
    run: Id,
    package: Id,
    destination: &Path,
) -> Result<RemediationPackage>;

fn cancel_remediation(
    run: Id,
    remediation: Id,
    expected_revision: u64,
) -> Result<RemediationCase>;

fn recover_remediation(
    run: Id,
    remediation: Id,
    expected_revision: u64,
) -> Result<RemediationCase>;
```

One reconcile call owns generation, capture, cleanup, independent evaluation,
and package settlement. Callers do not coordinate internal phases. Optional
draft publication uses a separate request/reconcile pair and is absent when no
publisher is configured. The publisher port has no merge operation.

### Patch-author boundary

The generator is a separate coding profile. It receives only the frozen public
finding projection, exact source package, public dependencies, edit policy, and
finite limits. It receives no controller artifact browser, validator records,
evaluator registry, private fixture, network tool, delegation tool, or live
checkout.

`nac-core` exposes a narrow controlled-coding facade rather than a filesystem
path. For this pilot its immutable capability snapshot contains scoped read,
search, edit, Go formatting, and one bounded Go-check operation. Each operation
resolves relative paths beneath the prepared workspace, rejects links and
special files, and uses the construction-selected confined backend. The facade
returns an effective tool, mount, environment, backend, process-supervision, and
workspace receipt. Missing confinement fails launch; it never substitutes local
execution or another backend. Commands run under `nac-process` supervision and
cannot address ambient controller, evaluator, checkout, credential, or home
paths even when processes share an operating-system user.

The writable workspace is materialized from verified `SourcePackage` blobs into
a fresh owner-only directory. It contains no `.git`, remotes, refs, alternates,
credentials, parent history, solution history, or evaluator files. This avoids
the generic worktree's shared-object and fallback behavior. Trusted code derives
a canonical exact-preimage replacement set by comparing the workspace with the
frozen manifest. A human-readable unified diff is a projection of that record.

The first pilot permits bounded modifications and creations of production Go
files under frozen editable roots. It rejects deletions, renames, mode changes,
links, special files, generated checks, tests, module files, vendor content, an
empty change set, and a change set that does not include the finding's production
path. This narrow policy makes common no-op and grading-weakening patches
unrepresentable without pretending to be a general remediation framework.

### Independent paired evaluation

The evaluator never runs the generator workspace. It materializes two fresh
private trees from the same frozen source package, applies the canonical
replacement set to only the patched tree after exact preimage checks, and uses
one checked-in evaluator contract for both.

Acceptance is a closed conjunction:

1. Both reconstructed trees and the effective build/runtime environment match
   their frozen identities.
2. The original target fails the security assertion for the expected reason and
   the patched target passes it.
3. The same frozen legitimate-use suite passes on both targets. For the Go
   authorization pilot it checks health and public access, owner object access,
   owner state write followed by an exact readback, and the protected route
   bindings. Missing, skipped, truncated, or vacuous checks fail acceptance.
4. The same required existing checks run on both. The patched result introduces
   no failure relative to the recorded original result, and the first pilot
   requires a clean original baseline.
5. Structural review confirms a non-empty bounded production change, preserved
   protected symbols and route bindings, and unchanged tests, assertions,
   fixtures, dependencies, and check configuration.
6. Generator workspace, evaluator trees, target containers, and networks all
   have confirmed cleanup receipts.

The evaluator records `fixed`, `not_fixed`, `no_op`, `regressed`, `weakened`,
`drift`, or `inconclusive`. Adapter failure, nondeterminism, missing inputs,
superseded validation, capacity exhaustion, or uncertain cleanup is
inconclusive or blocked, never accepted.

The generator and evaluator use separate host-wide reservations. Evaluator
target reservations compose with the existing target-capacity counter, and the
generator has a finite remediation-worker reservation. Reconciliation retains
reservations until cleanup is confirmed.

The evaluator runs original and patched targets sequentially so one remediation
case consumes one target slot at a time. The repository's transactional host
resource accounting includes experiment targets, remediation targets, and a
separate bounded remediation-worker count. It rejects admission when the actual
simultaneous resources do not fit; no in-memory counter can authorize launch.

Raw generator and evaluator output, assertion bodies, fixtures, credentials,
canaries, and reference answers are owner-only artifacts. Public status,
reports, model feedback, and packages expose only a closed diagnostic enum,
validated source location or byte offset, completeness flag, and artifact hash.
Missing or truncated verdict-bearing evidence is inconclusive. The generator
never receives raw evaluator output.

### Package and publication

An accepted local package is the default terminal output. Its identifier hashes
a versioned tuple of the finding revision, plan, replacement set, evaluation,
receipts, and artifact hashes. Timestamps and event IDs are excluded. Repeating
materialization verifies identical bytes and succeeds; conflicting bytes fail.

The versioned package contains `manifest.json` plus canonically ordered UTF-8
payload files: `finding.json`, `patch.json`, `patch.diff`, `evaluation.json`,
and `report.md`. Canonical JSON uses sorted object keys and no insignificant
whitespace; text uses LF and mode `0644`. The manifest records the byte length
and SHA-256 of each payload file but does not inventory or hash itself. The
package ID hashes the canonical manifest bytes. The readable report includes finding evidence,
original and patched identities, reproduction and test instructions,
limitations, owner, reviewer outcome, and remaining rollout work. It references
private artifacts by hash and never embeds private bytes.

Optional publication is explicit, idempotent, and draft-only. Its stable finding
key hashes the provider, remote repository, and accepted candidate identity;
package ID is the revision applied to that finding. A transaction serializes
create or update intent, and uncertain create remains occupied until lookup by
the stable marker resolves it. The adapter checks the remote base SHA before any
write, verifies the base again after creation, and never merges. A stale base
records an inconclusive publication and requires renewed acceptance against the
new pinned base rather than retargeting the accepted package.

### Operator lifecycle and status

CLI operations cover request, watch/reconcile, read, cancel, explicit recovery,
package materialization, human approval, and optional draft publication. The
normal watcher drives internal phases; operators do not run generate or verify
steps directly. Recovery requires a diagnosed stopped effect and revision check
before minting a new case generation.

Reports derive remediation status without changing immutable accepted records:
`not_started`, `proposed`, `tests_passed`, `review_required`, `approved`,
`published`, or `rejected`. A `fixed` evaluator result advances only to
`tests_passed` and `review_required`; it never implies human approval. An
explicit operator review advances to `approved`, and publication requires that
state. Blocked and inconclusive attempts remain visible alongside the last
settled status. Documentation supplies setup, request, resume/recovery, report,
package, and rollback instructions for every enabled operation.

## Module ownership

- `nac-appsec::remediation_records` owns the frozen profile, finding revision,
  journal, patch, evaluation, package, and publication contracts.
- `nac-appsec::remediation` owns eligibility, derived state, effect reservation,
  receipt verification, reconciliation, and package authorization.
- `nac-appsec::remediation_package` owns canonical encoding and deterministic
  materialization.
- `nac-server::application::appsec_remediation` implements the distinct coding
  profile, history-free workspace, checked-in Go evaluator, and composition.
- `nac-core` may expose narrow generic controlled-coding and supervised-process
  primitives, but it does not learn appsec records or policy.
- A configured publisher adapter owns provider transport. Publication policy and
  stable keys remain inward contracts.

## Synthesis decision

Three independent designs were scored on safety, durability, interface depth,
behavioral completeness, compatibility, and implementability. The sealed-pair
journal was selected as the base because it preserves research completion and
hides all phase sequencing behind one reconcile method.

The synthesis adopts these ideas from the task-led alternative: explicit
`fixed`/`not_fixed`/`no_op`/`regressed`/`weakened`/`drift`/`inconclusive`
assessments, a stable provenance-triple key, and re-derivation of finding
evidence at every append. It adopts from the step-oriented alternative only
conflict-safe package materialization and the requirement that the finding's
production path appear in the change set. It rejects remediation research tasks,
model-submitted verdicts, patched-target extensions to the experiment adapter,
caller-driven generate/verify phases, path-bearing worktree handles, and
provider-shaped domain APIs.

The synthesis additionally reserves host capacity, binds reproduced acceptance
to the reproducing oracle, and gives the generator no artifact-retrieval route.
These gaps were absent from all three initial designs.

## Consequences

- Research completion remains stable while remediation proceeds independently.
- Patch generation cannot represent an evaluator verdict, and evaluator-private
  inputs have no route into the generator.
- Two fresh reconstructions and duplicate checks cost more than trusting the
  generator workspace, but they make original-versus-patched behavior evidence.
- The first patch policy is intentionally narrow. Multi-repository fixes,
  dependency updates, test edits, arbitrary languages, and post-publication
  deployment state remain unsupported.
- A dirty original check baseline is inconclusive in the first pilot instead of
  introducing flaky-test attribution policy.

## Rejected alternatives

- Adding a remediation research role would change campaign completion and mix
  patch failures with investigation execution state.
- Widening the source-only worker would grant write and terminal authority to
  campaigns that did not opt in and leave evaluator separation to prompts.
- Reusing the session worktree would expose shared history and permit a live
  checkout fallback.
- Mutating `Accepted.remediation_state` would erase attempt and supersession
  history.
- A five-command plan/generate/verify/package pipeline would expose temporal
  internals and make the caller responsible for correctness.
- A generic language/check DSL is premature before a second concrete adapter
  proves a shared shape.
