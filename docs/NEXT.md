# ghidra-cli next architecture

Future direction, not implemented guarantees. See [bridge](../src/ghidra/README.md)
and [runtime](runtime.md) for current behavior; [PLAN.md](PLAN.md) owns proposed
CLI/module contracts, implementation requirements, and acceptance criteria.

## Architectural invariants

- Keep one coordinated Ghidra program-execution lane per open project. Do not infer that apparently read-only `Program` operations are safe to run concurrently.
- Scale throughput across independent, content-isolated projects/JVMs before considering same-project parallel reads.
- Distinct binary hashes must not silently share mutable project state.
- Treat in-memory success as insufficient for durable writes or analysis. Important write/analysis workflows should close/reopen in a fresh process and verify identity plus invariants before declaring success.
- Large collections should stream or page; avoid one giant Java `JsonArray` -> socket line -> Rust `Vec<Value>` -> formatted string pipeline.
- Arbitrary Java scripts/modules are trusted code with the user's privileges, not a sandbox.
- Persist provenance needed to reproduce or validate generated artifacts: binary identity, project/program, Ghidra/tool version, and script/module identity where applicable.

## Next slices

See [verification](PLAN.md#1-fresh-process-verification),
[modules](PLAN.md#2-multi-source-module-runtime),
[corpus scheduling](PLAN.md#3-durable-corpus-scheduler),
[queries/streaming](PLAN.md#4-server-side-query-and-streaming),
[bulk edits](PLAN.md#5-transactional-bulk-apply), and
[capabilities](PLAN.md#6-protocol-capabilities) for contracts and acceptance.
Scheduler state/protocol must not depend on eventual CLI-versus-service packaging.

## Open design questions

- Scheduler packaging: in-process CLI vs small local service.
- Exact database ownership/recovery semantics if a scheduler client disappears mid-job.
- Which verification invariants are universal versus profile-specific.
- Whether cancelled analysis preserves partial analyzer results or always requires quarantine/retry.
- Which supported Ghidra versions have sufficiently stable bundle APIs for the module runtime.
- Whether same-project read parallelism is worth the complexity after streaming/server-side queries and cross-project parallelism exist.
- Module dependency trust/allowlisting policy for autonomous-agent use.
