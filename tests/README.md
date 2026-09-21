# Tests

## Run

```bash
cargo xtask test --no-fail-fast
cargo test -p xtask
cargo xtask gen-tree --check
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

Ghidra-dependent tests must fail if Ghidra is unavailable. `require_ghidra!()`
checks `ghidra-cli doctor` once per test executable and retains failures with their
diagnostics; never turn a failed prerequisite into a skip. The parent test
process must keep its Ghidra/JDK configuration fixed. Tests of doctor itself or
changed child environments invoke doctor directly.
Set `GHIDRA_INSTALL_DIR` to the installation and provide a suitable full JDK;
see [runtime installation](../docs/runtime.md#installation).

`cargo xtask test` shares a fresh temporary fixture across suites for one
invocation; plain `cargo test` limits reuse to each test executable. Use the runner
when selecting several Ghidra suites:

```bash
cargo xtask test --test comment_tests --test type_tests
```

At the workspace root, the root package's tests run unless packages are selected
explicitly. `cargo test -p xtask` checks the developer tasks without Ghidra; see
[task commands and implementation](../xtask/README.md).

For a targeted run:

```bash
cargo test --lib --bin ghidra-cli
cargo test --test daemon_tests
# These suites do not require Ghidra or a JDK installation:
cargo test --test e2e --test output_format_integration --test routing_tests --test harness_tests
```

Doctor success belongs to `command_tests` in CI's `readonly-integration` job;
missing-installation failures and project-file preservation belong to
`output_format_integration`. Successful project deletion requires Ghidra's lock
API and belongs to `project_tests`.

Five `readonly_tests` Insta tests remain `#[ignore]` pending snapshot bootstrapping;
reference `.snap` files are not tracked. To run without accepting snapshots:

```bash
INSTA_UPDATE=no cargo test --test readonly_tests -- --ignored
```

These fail until reviewed snapshots are added; normal schema tests need no
snapshots. CI unit coverage runs both `--lib` and `--bin ghidra-cli`, the `xtask`
tests, and the generated command tree check on Linux, Windows, and macOS 26 ARM64.
See [the test workflow](../.github/workflows/test.yml) for suite groupings.

Markdown-only changes skip Ghidra setup and integration jobs; unit/CLI tests,
the command tree check, and lint still run. Other changes run every suite on
Linux, Windows, and macOS 26 ARM64. Infrastructure tests run in two parallel groups
per OS: `daemon_tests`, and the project/bootstrap/reliability/fixture suites.

Suite roots own their fixtures and serial locks; domain modules remain in the
original test executables. `routing_tests.rs` owns the recorded bridge shared by
`routing/`, and `output_format_integration.rs` keeps presentation tests alongside
the configuration, installation, project, and validation modules in `output/`.
Keep snapshot assertions at their original source/module path to preserve Insta
identity. Filter a domain with, for example,
`cargo test --test daemon_tests program_session::`.

## Coverage and fixtures

| Suite/source | Scope |
|---|---|
| `daemon_tests` | Lifecycle/jobs, program sessions/persistence, deletion, and output contracts |
| `reliability_tests`, `project_tests` | Restart/stale-state recovery and project management |
| `readonly_tests` | Functions/instructions, program metadata, relationships, search, batch queries, and response schemas |
| `memory_tests` | Pointer decoding, original file bytes versus edits, source mappings and reopen persistence |
| `data_tests` | Applied data values, interior components, exact scalars and bounded aggregate expansion |
| `stack_purge_tests` | Explicit stack metadata, caller decompilation, thunk ownership and saved/reopened edits |
| `export_coverage_tests` | Export artifacts, C declaration limits, initialized binary ranges and XML sidecars |
| `address_tests` | Strict address syntax, exact-name collisions, rejected mutations, and address output round trips |
| `comment_tests`, `symbol_tests`, `patch_tests`, `tag_tests`, `type_tests`, `script_tests` | Domain mutations and scripts |
| `fixture_tests` | Relocated analyzed projects, durable edits, and isolation between copies |
| `command_tests` | Version flags, doctor, config |
| `bootstrap_tests` | Named imports across startup routes, durable import failure checkpoints, doctor runtime lifecycle |
| `e2e`, `output_format_integration`, `harness_tests` | CLI smoke/output behavior and test infrastructure |
| `routing_tests` | Recorded bridge requests: management/jobs, batch targets, list pagination, and client file paths without Ghidra |
| `src/ghidra/bridge/sources.rs` | Embedded Java inventory and source publication |

For narrower regression work, these modules cover the non-obvious boundaries:

| Source | Scope |
|---|---|
| [daemon/program_session.rs](daemon/program_session.rs), [daemon/deletion.rs](daemon/deletion.rs) | Live versus saved state, program switching, recursive counts excluding type archives, deletion without wrong-target changes |
| [daemon/transaction.rs](daemon/transaction.rs) | Late-error/cancellation rollback, pending edits after save failure, foreign/leaked transactions, preview isolation; test-owned Java failure probes, no production hooks |
| [daemon/decompiler.rs](daemon/decompiler.rs) | Native process reuse, invalidation after save/rollback, cancellation/timeout recovery, monitor isolation and release |
| [readonly/decompile.rs](readonly/decompile.rs) | Warning-comment provenance, API-message extraction, entry block permissions, external/unmapped functions, and unchanged function-list scope |
| [readonly/decompile_details.rs](readonly/decompile_details.rs), [readonly/function_details.rs](readonly/function_details.rs) | Recovered jump tables, decompiler block counts, disjoint body ranges, calling conventions, and Program signature/storage reads including auto-parameters and thunks |
| [readonly/bookmarks.rs](readonly/bookmarks.rs), [readonly/memory_info.rs](readonly/memory_info.rs), [readonly/program_metadata.rs](readonly/program_metadata.rs) | Bookmark preservation, address classification, relocation evidence, and original executable hashes |
| [daemon/analysis.rs](daemon/analysis.rs) | Native option types/defaults/choices, settings-only edits versus full reanalysis, rollback and reopen persistence |
| [bootstrap/imports.rs](bootstrap/imports.rs), [bootstrap/analysis.rs](bootstrap/analysis.rs) | Import names, collisions and durable failure checkpoints; analysis settings and completion flags across startup routes |
| [readonly/functions.rs](readonly/functions.rs), [readonly/decompile_cli.rs](readonly/decompile_cli.rs), [readonly/disassembly.rs](readonly/disassembly.rs) | Function-list schemas and filters, decompiler targets/timeouts, and whole-body/ranged disassembly with query and output options |
| [patch/define_code.rs](patch/define_code.rs) | Bounded code definitions, rollback/persistence, Thumb context and MIPS delay slots |
| [patch/memory_write.rs](patch/memory_write.rs) | Preserved component settings and instructions, pointer references across widths/byte orders, string storage, shared memory, overlays and delay slots |
| [symbols/targets.rs](symbols/targets.rs), [symbols/deletion.rs](symbols/deletion.rs) | Exact mutation targets and namespace revalidation; thunk/dynamic symbols and transactional deletion |
| [scripts/source.rs](scripts/source.rs), [scripts/artifacts.rs](scripts/artifacts.rs) | Java source/package resolution from files and stdin; artifact validation and failure diagnostics |
| [types/](types/) | Field layouts/settings, union ordinals and packing, enum aliases, signed-char semantics, immutable types and alias-safe deletion; return edits preserving inferred/explicit parameters and ABI storage, compiler-specific calling convention validation |
| [readonly/calls.rs](readonly/calls.rs), [readonly/relationships.rs](readonly/relationships.rs) | Call resolution through thunks/pointers, undefined endpoints and reference evidence; real graph nodes/edges |
| [readonly/query.rs](readonly/query.rs) | Server pages versus full rows, Unicode/Turkish locale, tags/comments, bounds beyond Java `int` |
| [readonly/strings.rs](readonly/strings.rs), [readonly/search.rs](readonly/search.rs) | Code-point versus occupied-byte lengths, defined strings versus encoded text, overlaps and encoding errors |
| [readonly/constants.rs](readonly/constants.rs) | Scalar signedness/widths, exact 64-bit boundaries, overlays, address/data exclusion and cancellation |
| [readonly/search_limits.rs](readonly/search_limits.rs), [readonly/byte_regex.rs](readonly/byte_regex.rs) | Search pagination/cancellation, native byte regex semantics and initialized-memory boundaries |

Keep paired checks where one layer cannot prove the other: routing tests record
standalone/batch requests and client query processing; real bridge tests exercise
OSGi loading and native behavior. Persistence tests inspect saved databases or
reopen projects rather than relying only on live responses. Project deletion tests
hold an external Ghidra owner and retry after lock release. Batch tests verify
that save/transaction failures and timeouts stop later commands, including nested
batches.

Batch restart coverage lives in `tests/routing/batch.rs` (selected ranges,
target preservation, nested/continued execution, and lost replies) and
`tests/types/signatures.rs` (44 saved edits followed by a rejected signature,
correction at line 45, and persisted results without replay).

`common::test_project()` gives each test executable a fresh project. Read-only
suites reuse a bridge to amortize JVM startup; lifecycle/mutation suites may
create and drop harnesses. Follow the owning suite's pattern and use `#[serial]`
for shared-state tests. Never share projects across suites/runs or assume fixed
function addresses; look them up by name.

`fixture_binary()` compiles [sample_binary.rs](fixtures/sample_binary.rs) with
`rustc` once per runner invocation. The host-native binary (`.exe` on Windows)
retains function symbols and exercises exports, but strips debug information to
avoid standard-library DWARF analysis. No binary fixture or manual build is needed.
The first suite needing analysis uses the one-shot importer and waits for save/exit;
each suite receives an isolated copy. Setup starts no bridge; suite harnesses own startup.
Fixture symbols can have platform prefixes; use the common fixture lookup helpers
and preserve the discovered name when checking renames or rollback.
CLI import/analysis tests still use new projects and real commands. Setup/import
failures fail the tests; see [publication and lifecycle boundaries](common/README.md#lifecycle-boundaries).

With `-- --nocapture`, `[test setup]` lines report doctor, fixture compilation,
analysis, copy, and bridge startup times. Harness teardown reports shutdown time;
the runner reports total elapsed time after Cargo exits.

See [common helpers and a test example](common/README.md) when adding tests.
Cleanup is best effort; forced termination can leave processes/projects behind.
For slow startup, run `ghidra-cli doctor`; inspect the owning project/process
before cleaning stale discovery files.
CLI import/analysis tests currently have a 300s budget that can be tight under load;
see the [open TODO](../docs/TODO.md). Reducing parallel suites can reduce pressure.

## Cross-platform changes

Use `tempfile` for test artifacts; never assume `/tmp` exists. Follow the shared
[path/lifecycle helpers](../src/ghidra/README.md#cross-platform-paths).
Validate path/lifecycle changes on Linux and Windows, including separators,
case/alias variants, spaces, apostrophes, and backslashes. Cross-compilation or
Wine does not replace native Windows CI.
