# ghidra-cli implementation plan

Status: first-pass pruning candidate. This is the active implementation plan for unfinished work only. Architectural rationale and invariants are in `NEXT.md`; current implementation details are authoritative in code and module READMEs.

## 1. Fresh-process verification

Goal: make durable success testable rather than inferred from an in-memory command result.

Implement a reusable verification primitive used by analysis and write workflows.

Requirements:

- reopen the project/program in a fresh Ghidra process;
- verify expected program/binary identity;
- support caller-supplied invariants such as minimum function/symbol counts;
- distinguish verification failure from execution failure;
- never mark an unverifiable write/analysis as complete;
- expose structured counts/errors suitable for corpus scheduling.

Acceptance:

- a deliberately invalid/unreopenable project fails verification;
- a valid analyzed fixture passes after process restart;
- write workflows can call the same primitive before reporting durable success.

## 2. Multi-source module runtime

Single-file `script run` already supports positional args, absolute paths/stdin source, captured stdout, cancellation, and expected-artifact validation. Do not duplicate that path.

Add a checked-in module root, for example:

```text
module/
  module.toml
  src/Entry.java
  src/... sibling sources ...
  lib/... optional JARs ...
```

Minimum metadata:

- entry source;
- `effect = read|write`;
- supported Ghidra range;
- declared dependencies;
- expected artifacts.

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
ghidra corpus plan MANIFEST
ghidra corpus analyze MANIFEST [--jobs auto|N] [--cpu-budget N] [--mem-budget GB]
ghidra corpus status [RUN_ID]
ghidra corpus logs RUN_ID [--follow]
ghidra corpus cancel RUN_ID|JOB_ID
ghidra corpus retry RUN_ID|JOB_ID
ghidra corpus resume RUN_ID
```

Manifest requirements:

- binary path and expected SHA-256;
- analysis profile/options;
- optional loader/language/compiler overrides;
- optional pre/post scripts or modules;
- verification invariants;
- per-job resource limits.

Identity/dedup key must include:

```text
binary SHA-256
Ghidra version
loader/language/compiler
analyzer profile/options
script/module hashes
```

State machine must persist at least queued, running, saving, verifying, complete, failed, cancelled, and quarantined states. An exact verified key may be skipped on resume; an unverified or corrupted project may not.

Scheduling constraints:

- parallelism is across independent projects/JVMs;
- never schedule two program executors for one project identity;
- enforce CPU and memory budgets;
- execution timeout excludes queue wait;
- scheduler restart must not lose ownership/result state.

Acceptance:

- a small multi-binary fixture run survives restart/resume;
- exact verified jobs deduplicate;
- corrupt state is quarantined;
- CPU/memory budgets are respected;
- success requires section 1 verification.

## 4. Server-side query and streaming

Current Rust-side filtering can require fetching a complete bridge dataset. Replace that for large collections with either server-side evaluation of the supported filter/query semantics or a versioned bridge query AST.

Requirements:

- projection, filter, count, sort, offset, and limit without materializing the entire dataset client-side;
- paged or streaming wire format for large results;
- compatibility fallback only when the connected bridge lacks the capability;
- explicit protocol capability advertisement.

Add a structured per-function JSONL export that can optionally include decompile output, addresses, signature/calling convention, direct calls/references, p-code/basic blocks, elapsed time, and per-function failures. Reuse one `DecompInterface` per executor/program.

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

Extend `bridge_info` into a versioned capability contract covering protocol version, Ghidra/Java versions, command/features, job control, module support, streaming/query support, and current project/program identity.

Client behavior on capability mismatch must be explicit; do not silently fall back to a semantically different path.

## Build order

1. Fresh-process verification.
2. Module runtime and verified write policy.
3. Protocol capability contract needed by compatibility-sensitive module/query work.
4. Durable corpus scheduler.
5. Server-side query/streaming and structured bulk export.
6. Transactional bulk apply.

Slices should land independently with focused tests; no big-bang migration is required.
