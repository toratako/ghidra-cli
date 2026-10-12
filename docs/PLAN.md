# ghidra-cli implementation plan

Unfinished work only; code and module READMEs describe implemented behavior.

## Architectural invariants

- Keep one coordinated Ghidra program-execution lane per open project. Do not infer that apparently read-only `Program` operations are safe to run concurrently.
- Scale throughput across independent, content-isolated projects/JVMs before considering same-project parallel reads.
- Distinct binary hashes must not silently share mutable project state.
- Persist provenance needed to reproduce or validate generated artifacts: binary identity, project/program, Ghidra/tool version, and script identity where applicable.

## 1. Server-side query and streaming

Extend the [conservative list-query implementation](../src/query/README.md)
only as workloads justify the added query semantics and wire state.

The following are intentionally outside that implementation:

| Deferred work                                                                          | Reason and remaining cost                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Equality, prefix/suffix, regex, numeric/address, array and compound predicates in Java | Keep one authoritative evaluator for these operations. Moving them requires differential tests for missing/null values, array membership, integer precision and regex/Unicode semantics. These queries still fetch full rows for Rust. |
| Candidate-only substring prefilters for `=`, `^`, `$`                                  | Avoid a second, inexact pushdown mode whose remaining predicate prevents early paging. Add it only with evidence of useful transfer reduction.                                                                                         |
| Server-side count                                                                      | Requires an aggregate response path and preservation of explicit offset/limit semantics. Counts currently transfer matching rows and are computed in Rust.                                                                             |
| Server-side field projection                                                           | Must retain fields needed by any Rust filter/sort and preserve missing-field behavior. The conservative change reduces rows, not columns.                                                                                              |
| Arbitrary server-side sort/top-k                                                       | Requires identical comparison, tie order and missing-value semantics plus memory/cancellation policy. Sorting still transfers the necessary row set to Rust.                                                                           |
| Additional list/graph/search handlers                                                  | Their row and traversal boundaries differ; expand only with handler-specific acceptance tests. Their offset processing remains in Rust.                                                                                                |
| General serialized query AST                                                           | A literal contains value suffices for the current subset. Introduce an AST when more operators move, while keeping DSL parsing in Rust.                                                                                                |
| Cursors, streaming and snapshots                                                       | Require program/query identity, stable ordering, mutation invalidation and resource lifetime rules. Deep offsets currently rescan; unlimited responses still materialize as one payload.                                               |
| Query indexes and large-program performance benchmarks                                 | No index ownership/invalidation design or representative performance corpus is included. Reduced transferred rows is tested, but million-row speedups and memory reductions are not measured.                                          |
| Old-bridge query compatibility/negotiation                                             | Explicitly excluded: deploy CLI and bridge together. Do not add silent fallback, feature probes or query-triggered restarts for this change.                                                                                           |

Full server query execution should eventually avoid materializing the whole
dataset client-side. This does not imply every predicate or ordering can avoid
a complete server scan.

Add a structured per-function JSONL export that can optionally include decompile output, addresses, signature/calling convention, direct calls/references, p-code/basic blocks, elapsed time, and per-function failures. Reuse one `DecompInterface` per executor/program. Explicitly distinguish direct
call edges from incomplete indirect-call/reference coverage.

## 2. Transactional bulk apply

For bulk rename/comment/type/signature/patch operations add:

- dry-run/plan output;
- exclusive write execution;
- idempotency/provenance metadata;
- bounded/staged transactions where practical;
- rollback or explicit backup restoration;
- save;
- result counts and invariant checks.

## 3. Protocol capabilities

Extend `bridge_info` into a versioned capability contract covering protocol version, Ghidra/Java versions, command/features, job control, script/bundle support, streaming/frame limits, server-side query support, and current project/program identity.

Report capability mismatches explicitly; never silently fall back to different semantics.

## Build order

1. [Protocol capability contract](#3-protocol-capabilities) needed by query/streaming work.
2. [Server-side query/streaming and structured bulk export](#1-server-side-query-and-streaming).
3. [Transactional bulk apply](#2-transactional-bulk-apply).

## Open design questions

- Whether cancelled analysis preserves partial analyzer results or always requires quarantine/retry.
- Whether same-project read parallelism is worth the complexity after streaming/server-side queries and cross-project parallelism exist.
