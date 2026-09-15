# Offline appsec doctor

The doctor inspects a small doctor config before a security campaign. It does
not run a campaign, launch a model, tool executable, target or evaluator, load
skills, read an external answer key, or load credentials. It does not log in or
import authentication. JSON and Markdown are diagnostics, not canonical
security state. This diagnostic does not implement campaigns or prove runtime
or security controls.

From the repository root, with a built `nac-web` on PATH:

```sh
nac-web appsec doctor \
  --config docs/security/appsec-doctor.example.json \
  --output ./appsec-doctor-result
```

The output directory must not exist, and its parent must exist. The command
writes `doctor.json` and `doctor.md` without replacing existing files. An I/O
failure can leave a new directory with partial diagnostics. Preserve it for
inspection and use a different new directory to retry; two-file publication is
not atomic.

Exit codes are `0` for ready, `3` for blocked readiness with reports written,
`2` for malformed or unsupported config or CLI arguments, and `1` for I/O
failure. The initial implementation always exits `3` for a valid config with
successful output because required runtime capabilities are not verified.
Existing commands and the no-command web-server default are unchanged.

## Doctor config

The [example](appsec-doctor.example.json) requests native OpenAI subscription
access through `chatgpt-codex-responses`, model `gpt-5.6-sol`, reasoning `high`.
No Daybreak or API-key backend is accepted. The explicit model and reasoning
are preserved, not resolved through the catalog or tested against a provider.
This is a doctor config, not the full future campaign manifest.

- `schema_version` must be `1`. Unknown and duplicate fields are rejected.
- `backend`, `model`, `reasoning`, `monetary_policy` and `limits` are required.
  Model identifiers use ASCII letters, digits, periods, hyphens and underscores.
  Reasoning accepts `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max`.
  Parsing these values does not prove that the requested model supports them.
- `monetary_policy` must explicitly be `uncapped`. Missing configuration or
  zero observed usage never implies that policy. No monetary cap is imposed.
- Concurrency, token, time and output limits must be positive finite integers.
  `active_agents` is at most `4`, including the root and all investigative
  agents. `task_tokens` and `task_seconds` request per-task ceilings.
  `transient_retries` is a finite nonnegative integer; `0` requests no retries.
  `tool_output_bytes_total`
  requests an aggregate task-tree ceiling and must be at least
  `tool_output_bytes_per_response`. These values are requests, not proof that
  current runtime enforces any of them.
- Optional `evaluation_source` names a directory, relative to the config file
  unless absolute. The doctor checks only whether it is a directory, without
  listing or reading its contents. Omit it when not needed.
- Optional `tools` lists bare executable names, without paths or arguments.
  Each requested tool is required for readiness. On Unix, availability means
  that a regular file with executable mode bits exists on PATH. The doctor
  does not test effective execution permission, versions or suitability. Other
  platforms report this check as not tested. An empty or omitted list requests
  no tools; CodeQL is not a universal prerequisite.

There are no credential, account ID, arbitrary header or provider URL fields.
Do not put secrets into paths or identifiers; configured paths appear in reports.

## Reading the report

Both formats contain report schema version, compile-time product/build/source
provenance, effective requested settings and check records with `id`, `status`,
`required`, `scope` and `reason`. Markdown includes the exact JSON with HTML
escaping. `ready` is true only when every required check is `verified`.

`verified` covers strict parsing, directory existence or executable availability
only. Missing requested prerequisites are `not_tested` and block readiness.
Omitted evaluation input is a non-required `not_tested` check. None of these
statuses certifies runtime security.

Required checks initially block readiness because:

- Direct primaries and resume do not bind controller MCP tools.
- There is no shared full-task-tree budget, admission and cancellation contract,
  or controller hard-admission hook for these limits.
- Effective source-only containment is not proved, and skills lock is not
  implemented.
- Original evaluation equivalence, model execution, actual skill loading and
  provider generation bounds are not tested by the offline doctor.

The report does not incorporate live experiments as static guarantees.
Context-window metadata is not a generation hard cap. A separate live check is
needed to test provider behavior; this command deliberately cannot perform one.
