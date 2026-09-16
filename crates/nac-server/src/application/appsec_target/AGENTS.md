# Controlled target adapter guide

This directory owns the opt-in Docker adapter for controlled appsec experiments.
The adapter accepts frozen recipes from `nac-appsec`. Models cannot select a Docker
image, a builder, an evaluator, an actor credential, or a host execution backend.

## Module ownership

- `mod.rs` owns the durable target state machine, fixed control plans, capture
  sequencing, execution receipts, and the two fixed oracle evaluators. This file is
  over 800 lines because the ordering between request uncertainty, attack cleanup,
  fresh controls, evaluation, and final cleanup is one audit unit. Keep transport,
  build, process, filesystem, and preparation code in the modules below.
- `docker.rs` owns target and network construction, verification, and cleanup.
- `http.rs` and the Python brokers own the fixed private network request path.
- `build.rs` owns isolated build verification and safe build diagnostics.
- `prepare.rs` owns the local fixture preparation command. It does not adapt
  external evaluations.
- `private.rs` owns no-follow owner-only files. `process.rs` owns bounded process
  output and process-tree cleanup.
- `export.rs` owns immutable production-source copies.

## Safety rules

- Commit desired state and capacity before Docker effects.
- Treat an uncertain request as delivered. Never replay it in the same trial.
- Stop the attack target before starting a fresh control target.
- Keep raw captures, compiler output, nonces, credentials, and evaluator rules out
  of model-visible results.
- Verify ownership labels and effective Docker configuration before cleanup.
- Preserve a captured verdict while cleanup remains pending.

Run the focused unit tests and the real Docker pilot after any state, receipt,
capture, build, or cleanup change. Then run `cargo test --locked -p nac-server appsec`.
