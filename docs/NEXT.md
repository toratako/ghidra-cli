# ghidra-cli next architecture

Status: first-pass pruning candidate. This keeps only active architectural direction and non-obvious constraints. Implemented bridge details live in `AGENTS.md`, `src/ghidra/README.md`, and the code.

## Current baseline

The current system already has:

- one persistent Java bridge per project;
- a responsive control plane (`ping`, status, jobs, cancel, shutdown) separated from the serialized Ghidra program-execution lane;
- bounded program-job queuing and cooperative cancellation;
- checked-in Java script execution with real args, absolute paths/stdin source, captured stdout, and expected-artifact validation;
- explicit save support and selected durability fixes.

Do not re-plan these as future work.

## Architectural invariants

- Keep one coordinated Ghidra program-execution lane per open project. Do not infer that apparently read-only `Program` operations are safe to run concurrently.
- Scale throughput across independent, content-isolated projects/JVMs before considering same-project parallel reads.
- Distinct binary hashes must not silently share mutable project state.
- Treat in-memory success as insufficient for durable writes or analysis. Important write/analysis workflows should close/reopen in a fresh process and verify identity plus invariants before declaring success.
- Large collections should stream or page; avoid one giant Java `JsonArray` -> socket line -> Rust `Vec<Value>` -> formatted string pipeline.
- Arbitrary Java scripts/modules are trusted code with the user's privileges, not a sandbox.
- Persist provenance needed to reproduce or validate generated artifacts: binary identity, project/program, Ghidra/tool version, and script/module identity where applicable.

## Next slices

### 1. Lifecycle and data correctness

Add a first-class verification boundary for analysis and writes:

- `project verify` or an equivalent internal fresh-process verification primitive;
- identity checks (binary/program/project) plus caller-supplied invariants;
- verification as a required terminal state for workflows that claim durable success;
- atomic artifact publication and explicit partial/failure counts;
- consistent structured lifecycle/result envelopes.

This is the dependency for durable corpus scheduling and verified write modules.

### 2. Script/module runtime

Single-file `script run` and expected-artifact validation already exist. The remaining gap is a multi-source checked-in module model.

Desired properties:

- module root resolved absolutely, never from bridge CWD;
- sibling Java sources and declared JAR dependencies;
- content-addressed compilation/cache identity including source/dependency hashes, Ghidra version, and JDK version;
- cache invalidation when content changes;
- structured compile diagnostics;
- explicit `effect=read|write` policy;
- write modules run exclusively and pass the durability verification gate;
- dependency/classpath-sensitive work may use a one-shot headless process for stronger isolation.

Keep reflection-based access to Ghidra OSGi bundle APIs where direct imports would make the bridge script bundle fail to resolve. This is an observed compatibility boundary, not stylistic preference.

### 3. Durable corpus scheduler

Provide a subsystem for many independent binaries rather than extending `batch`.

Core contract:

- manifest-driven inputs with expected SHA-256 and analysis profile;
- project identity derived from content hash;
- dedup key includes binary hash, Ghidra version, loader/language/compiler choices, analyzer profile/options, and script/module hashes;
- durable state in a transactional local database;
- states distinguish queued/running/saving/verifying/complete/failed/cancelled/quarantined;
- restart/resume without redoing already verified exact jobs;
- CPU and memory token budgets across independent Ghidra JVMs;
- corrupted or unverifiable project state is quarantined, never silently reused;
- success only after fresh-process verification.

Suggested surface remains `ghidra corpus plan|analyze|status|logs|cancel|retry|resume`, but state/protocol should not depend on whether the scheduler ultimately lives in the CLI process or a small service.

### 4. RE-native bulk data operations

Move expensive full-dataset work closer to Ghidra:

- server-side filter/projection/count/sort/offset/limit, or a bridge query AST with equivalent semantics;
- paged/streaming result framing;
- structured per-function JSONL export with decompile text, addresses, signatures, calls/references, optional p-code/basic-block data, timing, and per-function failures;
- reuse `DecompInterface` rather than reconstructing it for every function;
- make indirect-call/reference limitations explicit instead of presenting direct call edges as complete control flow.

For bulk mutations (rename/comment/type/signature/patch), require dry-run/plan output, exclusive writes, idempotency/provenance, rollback or backup recovery, and post-save verification.

### 5. Protocol/capability negotiation

`bridge_info` exposes some bridge metadata today, but clients still assume too much about feature compatibility.

Add a versioned capability handshake covering at least:

- bridge protocol version;
- Ghidra and Java versions;
- supported commands/features;
- job/status/cancel support;
- module/bundle support;
- streaming/frame limits;
- server-side query capabilities;
- current project/program identity.

Older bridges should fail with a clear capability error rather than ambiguous restart/fallback behavior.

## Open design questions

- Scheduler packaging: in-process CLI vs small local service.
- Exact database ownership/recovery semantics if a scheduler client disappears mid-job.
- Which verification invariants are universal versus profile-specific.
- Whether cancelled analysis preserves partial analyzer results or always requires quarantine/retry.
- Which supported Ghidra versions have sufficiently stable bundle APIs for the module runtime.
- Whether same-project read parallelism is worth the complexity after streaming/server-side queries and cross-project parallelism exist.
- Module dependency trust/allowlisting policy for autonomous-agent use.
