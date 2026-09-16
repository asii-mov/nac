# Application-security workflow contract

Workflow mode adds persisted reconnaissance, discovery, independent source review
and repeated root synthesis to the existing controller. It does not reproduce
exploits, remediate findings, grade evaluations or certify security assurance.

## Entry points and compatibility

`nac-web appsec freeze --workflow --manifest INPUT --skills SKILLS --brief BRIEF
--output OUTPUT` freezes a single initial manifest task as the recon root. The
brief uses the existing typed scenario fields. The skill registry must contain
recon, discovery, validation and synthesis stages. No dormant tasks preload skills.

`run`, `watch`, `status`, `report`, `cancel`, `recover` and `resume` use the same
canonical campaign. `run` uses the native controlled runtime. Local scripted
providers exist only in test builds, not as a production scanner mode.

The additive version-1 JSON migration has these defaults:

| Missing field | Meaning |
| --- | --- |
| `Campaign.workflow` | Existing manual or source-only campaign. |
| `FrozenResearch.workflow` | `false`; no automatic workflow conversion. |
| `FrozenResearch.templates` | Legacy task-key selection only. Dynamic workflow admission is unavailable. |

New freezes capture all registered stage closures and exact resource bytes from
the original lock. Dynamic jobs use those templates without changing the manifest.
Dispatch verifies the frozen lock and rejects filesystem drift. Updating active
skills does not upgrade an existing campaign. A new campaign is required to adopt
new skills or source, configuration, dependency or scenario inputs.

## Canonical stages

Recon must enumerate every declared repository from the beginning through bounded
pages before submitting source-cited area proposals. The controller persists the
pinned commit, listing hash and union of actually delivered file-index ranges.
Skipped pages and arbitrary terminal cursors cannot establish complete coverage.
Out-of-order pages, retries and restarts preserve coverage only for the same listing
identity. Hash-only legacy inventory receipts remain readable but do not establish
enumeration. A previously frozen map without that proof needs a new campaign.
The controller verifies Git object identities,
regular-file paths, content hashes and line ranges. The map's descriptions, trust
boundaries and applicability remain model hypotheses. Verified citations establish
the source bytes, not the truth of every interpretation.

Each area receives six baseline classes: authentication, authorization, injection,
data exposure, resource exhaustion and business logic. The third cell coordinate
is the frozen attacker and deployment brief hash. Baseline identity and denominator
never change. Applicability exclusions remain visible but cannot remove cells,
including unsupported claims that middleware makes a path safe. Cross-area reads
are permitted within all declared pinned repositories.

Discovery registers source-grounded families and submits candidates. A family
identity conservatively groups one pinned repository, path and attack class.
Changing its title or citation ordering does not create another family. Different
mechanisms in the same file refine that family's history rather than manufacturing
new capacity. Blocking or exhausting an assigned family records a status change.
Reopening requires a changed rationale and a source range not covered by its
previous evidence. Follow-ups need a registered exploring family and a known area
and class. Additional cells have a separate denominator and no lifetime count
ceiling. The four-actor limit and per-operation and failed-recovery bounds still
apply. Duplicate area, class, scenario, family and approved exploration
requests are rejected. A settled exploration may admit another follow-up after a
new source-grounded approach is accepted. The exploration identity references that
accepted approach, not the follow-up title or rationale. Source novelty accounts
for the union of previously cited ranges, so widening an already covered citation
does not reopen a family.
Scheduling favors fewer prior attempts within a family or an unassigned class.

Candidate acceptance and creation of its unique validation job commit together.
Exact candidate identity uses the allegation, cited source range and normalized
prerequisite set, not the discovery cell. Different allegations sharing a citation
remain separate for validation; a shared citation does not prove root-cause
equivalence. Exact-repeat detection also reads immutable accepted candidates, so
older stored fingerprints cannot create duplicate validators after an upgrade.
The initial validator input contains the claim,
prerequisites, pinned source and scenario, plus observed input provenance. It omits
discoverer assumptions, confidence and attachment prose. Each attempt has a fresh
session, thread and dispatch. Same-model review is reported as reduced diversity;
freshness does not establish independent reasoning.

Only the assigned validator may append a verdict. It must address prerequisites,
reachability and the security violation. Disproof requires source counterevidence.
An inconclusive verdict requires unknowns and next actions. Validation `unknowns`
means material unresolved prerequisites; supported and disproved verdicts require
that list to be empty. Unknown but irrelevant manifest context is separate and does
not prevent a resolved source verdict. Missing required configuration is not
disproof. Source-supported findings are not reproduced findings. Resuming
an inconclusive validator retains its job and original evidence, starts a new
attempt, and appends another verdict. The latest verdict determines unresolved
status; earlier verdicts remain available.

Synthesis waits for settled same-round jobs and confirmed physical cleanup. Parent
links are separate from completion dependencies, so children do not wait for their
own parent to finish. Each synthesis records assumptions, source counterevidence,
gaps and proposed next families. It can admit another nonduplicate round or retain
an explicit blocked synthesis with unresolved gaps. Clean completion requires at
least two synthesis records, completed scope, resolved validation and no frozen
map unknowns, unanswered source questions or remaining coverage gaps. Map and area
`unknowns` specifically record fixed required-input blockers. They cannot disappear
because a root omits them from its last response. Ordinary source-resolvable
questions instead use `ask_source` with a stable key, question and pinned citations.
Recon, discovery or synthesis can later submit `resolve_source` with that key,
an answer and supporting pinned citations. Both records remain in the accepted
history; resolution cannot clear a fixed input blocker or a validator prerequisite.
Unsupported legacy completion flags are downgraded on read without changing
accepted evidence. The corrected flag persists on the next revision-checked write.

## Mutation and retrieval boundaries

`submit_workflow` consumes map, source-question, source-resolution, approach,
follow-up, validation and synthesis
actions. `submit_candidate` and typed stage checkpoints retain their existing
roles. Authorization comes from the server-bound task and attempt fence, not a
role argument or tool visibility. Native delegation remains unavailable.

`query_work` returns at most 32 summaries per page and the accepted-record sequence
as its decision revision. `campaign_revision` is the separate operator revision.
Watchdog polling changes the latter without invalidating model decisions. Decision
revisions are checked at reservation and acceptance; current admission policy is
checked atomically again before creating jobs. An identical decision can retry its
idempotency key with a refreshed revision. Semantic changes require another key.

`read_work_record` returns bounded byte ranges with the full record's SHA-256.
Validators can read only their own accepted records and task-owned artifacts,
not discoverer notes. Large initial inputs may be omitted from query pages with
an explicit notice; their exact bytes remain in the initial frozen task context.
Handoffs are bounded continuation data, never imported episode history.

## Effective inputs and effort

The trusted loaded-worker receipt supplies actual model, backend, reasoning,
session, thread, dispatch, prompt, action and message hashes. The adapter also
records the executing binary hash and extractor identity. These observations
extend the attempt fingerprint. Declared configuration values do not substitute
for loaded inputs. Missing dependency, environment or configuration observations
remain unknown. This layer does not reuse prior conclusions as a cache.

Active-research credit is a conservative lower bound. Only a successful bounded
pinned-source extraction with a previously unseen repository, commit, path and
content hash can add an interval. Its duration cannot exceed either trusted
monotonic elapsed time or the corresponding wall-clock interval. Database lock
waiting and artifact publication are outside that interval. Intervals are unioned
across all workers, so overlapping work cannot multiply elapsed credit. Repeated
source ranges within the same blob, idle time, heartbeats, model prose and model
thinking with unproved boundaries add no credit. A backward clock interval is
excluded.

The controller rejects clean completion below the configured minimum, including
the six-hour deep profile. Minimum time alone is insufficient. Native model
thinking intervals are currently unknown, so a small repository may never earn
six hours from source extraction alone. The result remains incomplete, not a
fabricated clean scan. A source-supported verdict does not implement the later
independently confirmed end-to-end success exception. Provider, infrastructure
and operator stops retain their explicit incomplete states.

Money, tokens, aggregate calls and overall productive elapsed time have no ceiling.
Individual operations, tool responses, context handoffs and consecutive failed
recoveries remain bounded. Host-wide admission counts at most four actors across
all roles, including root cleanup and uncertain launches.
