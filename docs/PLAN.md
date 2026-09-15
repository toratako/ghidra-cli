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

Extend the existing single-file `script run` path; see [current baseline](NEXT.md#current-baseline).

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

For large collections, replace full-dataset fetches for Rust-side filtering with
server-side evaluation of supported filter/query semantics or a versioned bridge query AST.

Requirements:

- projection, filter, count, sort, offset, and limit without materializing the entire dataset client-side;
- paged or streaming wire format for large results;
- compatibility fallback only when the connected bridge lacks the capability;
- explicit protocol capability advertisement.

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
