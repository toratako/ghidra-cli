# ghidra-cli implementation plan

Unfinished work only. [NEXT.md](NEXT.md) owns architectural invariants and open
decisions; code and module READMEs describe implemented behavior.

## 1. Fresh-process verification

For analysis/writes, add reusable `project verify` or equivalent: reopen the project
in a fresh Ghidra process and check project/program/binary identity plus caller invariants
(e.g. minimum function/symbol counts). Distinguish verification from execution
failure; unverifiable work cannot be complete. Publish artifacts atomically with
partial/failure counts and consistent structured lifecycle/result envelopes for
corpus scheduling.

Acceptance:

- a deliberately invalid/unreopenable project fails verification;
- a valid analyzed fixture passes after process restart;
- write workflows can call the same primitive before reporting durable success.

## 2. Multi-source module runtime

Extend the [single-file `script run` implementation](../src/ghidra/scripts/ghidracli/script/ScriptCommands.java).

Add a checked-in module root, for example:

```text
module/
  module.toml
  src/Entry.java
  src/... sibling sources ...
  lib/... optional JARs ...
```

Metadata: entry source, `effect = read|write`, supported Ghidra range, declared
dependencies, and expected artifacts.

Implementation constraints:

- resolve module roots absolutely;
- hash all sources/metadata/dependencies and include Ghidra/JDK versions in the compile-cache key;
- reload on hash change so stale classes cannot execute;
- surface compile diagnostics structurally;
- keep direct imports of problematic `ghidra.app.plugin.core.osgi` classes out of the bridge script bundle where they cause OSGi resolution failure; use the known reflection path or isolate the loader elsewhere;
- run read modules on the existing serialized program lane;
- run write modules exclusively and require the verification primitive from section 1;
- allow a one-shot headless execution mode for dependency/classpath-sensitive writes.

Acceptance:

- sibling-package module compiles and runs without building a Ghidra extension;
- external JAR dependency is resolved and represented in module identity;
- editing a source invalidates cached code;
- long module jobs remain observable/cancellable through the existing job control plane;
- write module is not reported complete until fresh-process verification passes.

## 3. Durable corpus scheduler

This is separate from `batch`, which is only a sequential CLI command macro.

Suggested modules:

```text
src/corpus/
  manifest.rs
  db.rs
  scheduler.rs
```

Suggested commands:

```text
ghidra-cli corpus plan MANIFEST
ghidra-cli corpus analyze MANIFEST [--jobs auto|N] [--cpu-budget N] [--mem-budget GB]
ghidra-cli corpus status [RUN_ID]
ghidra-cli corpus logs RUN_ID [--follow]
ghidra-cli corpus cancel RUN_ID|JOB_ID
ghidra-cli corpus retry RUN_ID|JOB_ID
ghidra-cli corpus resume RUN_ID
```

Manifest: binary path/expected SHA-256, analysis profile/options, optional
loader/language/compiler overrides and pre/post scripts/modules, verification
invariants, and per-job resource limits. Persist state in a transactional local
database; derive project identity from binary content hash.

Dedup identity includes binary SHA-256, Ghidra version, loader/language/compiler,
analyzer profile/options, and script/module hashes.

State machine must persist at least queued, running, saving, verifying, complete, failed, cancelled, and quarantined states. An exact verified key may be skipped on resume; an unverified or corrupted project must be quarantined, never silently reused.

Scheduling constraints:

- parallelism is across independent projects/JVMs;
- never schedule two program executors for one project identity;
- enforce CPU and memory token budgets;
- execution timeout excludes queue wait;
- scheduler restart must not lose ownership/result state.

Acceptance:

- a small multi-binary fixture run survives restart/resume;
- exact verified jobs deduplicate;
- corrupt state is quarantined;
- CPU/memory budgets are respected;
- success requires section 1 verification.

## 4. Server-side query and streaming

Extend the [conservative list-query implementation](../src/query/README.md)
only as workloads justify the added query semantics and wire state.

The following are intentionally outside that implementation:

| Deferred work | Reason and remaining cost |
|---|---|
| Equality, prefix/suffix, regex, numeric/address, array and compound predicates in Java | Keep one authoritative evaluator for these operations. Moving them requires differential tests for missing/null values, array membership, integer precision and regex/Unicode semantics. These queries still fetch full rows for Rust. |
| Candidate-only substring prefilters for `=`, `^`, `$` | Avoid a second, inexact pushdown mode whose remaining predicate prevents early paging. Add it only with evidence of useful transfer reduction. |
| Server-side count | Requires an aggregate response path and preservation of explicit offset/limit semantics. Counts currently transfer matching rows and are computed in Rust. |
| Server-side field projection | Must retain fields needed by any Rust filter/sort and preserve missing-field behavior. The conservative change reduces rows, not columns. |
| Arbitrary server-side sort/top-k | Requires identical comparison, tie order and missing-value semantics plus memory/cancellation policy. Sorting still transfers the necessary row set to Rust. |
| Additional list/graph/search handlers | Their row and traversal boundaries differ; expand only with handler-specific acceptance tests. Their offset processing remains in Rust. |
| General serialized query AST | A literal contains value suffices for the current subset. Introduce an AST when more operators move, while keeping DSL parsing in Rust. |
| Cursors, streaming and snapshots | Require program/query identity, stable ordering, mutation invalidation and resource lifetime rules. Deep offsets currently rescan; unlimited responses still materialize as one payload. |
| Query indexes and large-program performance benchmarks | No index ownership/invalidation design or representative performance corpus is included. Reduced transferred rows is tested, but million-row speedups and memory reductions are not measured. |
| Old-bridge query compatibility/negotiation | Explicitly excluded: deploy CLI and bridge together. Do not add silent fallback, feature probes or query-triggered restarts for this change. |

Full server query execution should eventually avoid materializing the whole
dataset client-side. This does not imply every predicate or ordering can avoid
a complete server scan.

Add a structured per-function JSONL export that can optionally include decompile output, addresses, signature/calling convention, direct calls/references, p-code/basic blocks, elapsed time, and per-function failures. Reuse one `DecompInterface` per executor/program. Explicitly distinguish direct
call edges from incomplete indirect-call/reference coverage.

## 5. Transactional bulk apply

For bulk rename/comment/type/signature/patch operations add:

- dry-run/plan output;
- exclusive write execution;
- idempotency/provenance metadata;
- bounded/staged transactions where practical;
- rollback or explicit backup restoration;
- save plus fresh-process verification;
- result counts and invariant checks.

## 6. Protocol capabilities

Extend `bridge_info` into a versioned capability contract covering protocol version, Ghidra/Java versions, command/features, job control, module/bundle support, streaming/frame limits, server-side query support, and current project/program identity.

Report capability mismatches explicitly; never silently fall back to different semantics.

## Build order

1. Fresh-process verification.
2. Module runtime and verified write policy.
3. Protocol capability contract needed by compatibility-sensitive module/query work.
4. Durable corpus scheduler.
5. Server-side query/streaming and structured bulk export.
6. Transactional bulk apply.
