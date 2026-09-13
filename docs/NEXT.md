# ghidra-cli next architecture

Future direction, not implemented guarantees. Current behavior is documented in
[the bridge map](../src/ghidra/README.md) and [runtime reference](usage.md);
[PLAN.md](PLAN.md) owns implementation requirements and acceptance criteria.

## Current baseline

Per-project persistent JVMs, responsive controls with bounded serialized jobs and
cooperative cancellation, single-file scripts (args, absolute paths/stdin,
captured stdout, artifact validation), and explicit save already exist. Do not
re-plan them as future work.

## Architectural invariants

- Keep one coordinated Ghidra program-execution lane per open project. Do not infer that apparently read-only `Program` operations are safe to run concurrently.
- Scale throughput across independent, content-isolated projects/JVMs before considering same-project parallel reads.
- Distinct binary hashes must not silently share mutable project state.
- Treat in-memory success as insufficient for durable writes or analysis. Important write/analysis workflows should close/reopen in a fresh process and verify identity plus invariants before declaring success.
- Large collections should stream or page; avoid one giant Java `JsonArray` -> socket line -> Rust `Vec<Value>` -> formatted string pipeline.
- Arbitrary Java scripts/modules are trusted code with the user's privileges, not a sandbox.
- Persist provenance needed to reproduce or validate generated artifacts: binary identity, project/program, Ghidra/tool version, and script/module identity where applicable.

## Next slices

| Slice | Purpose and dependency |
|---|---|
| Fresh-process verification | Identity/invariant checks before durable success; enables verified writes and corpus scheduling |
| Multi-source modules | Checked-in sibling sources/JARs, content-addressed cache, structured diagnostics, read/write policy |
| Durable corpus scheduler | Content-isolated projects with transactional state, resume/dedup, budgets, and quarantine; separate from `batch` |
| RE-native bulk data | Server-side queries, streaming, per-function export, and verified bulk mutations |
| Capability negotiation | Versioned feature/identity handshake; explicit mismatch errors |

The contracts and suggested CLI/module surfaces live in [PLAN.md](PLAN.md).
Scheduler state/protocol must not depend on eventual CLI-versus-service packaging.

## Open design questions

- Scheduler packaging: in-process CLI vs small local service.
- Exact database ownership/recovery semantics if a scheduler client disappears mid-job.
- Which verification invariants are universal versus profile-specific.
- Whether cancelled analysis preserves partial analyzer results or always requires quarantine/retry.
- Which supported Ghidra versions have sufficiently stable bundle APIs for the module runtime.
- Whether same-project read parallelism is worth the complexity after streaming/server-side queries and cross-project parallelism exist.
- Module dependency trust/allowlisting policy for autonomous-agent use.
