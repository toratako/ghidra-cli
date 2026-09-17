# Tests

## Run

```bash
cargo test-run --no-fail-fast
cargo fmt --all -- --check
cargo clippy -- -D warnings
```

Ghidra-dependent tests must fail if Ghidra is unavailable. `require_ghidra!()`
checks `ghidra-cli doctor` once per test executable and retains failures with their
diagnostics; never turn a failed prerequisite into a skip. The parent test
process must keep its Ghidra/JDK configuration fixed. Tests of doctor itself or
changed child environments invoke doctor directly.
Set `GHIDRA_INSTALL_DIR` to the installation and provide a suitable full JDK.

`cargo test-run` forwards arguments (including `--help`) to `cargo test`, preserves
its order and failure status, and shares a fresh temporary fixture across suites
for one invocation. Plain `cargo test` limits fixture reuse to each test executable.
Use `test-run` when selecting several Ghidra suites:

```bash
cargo test-run --test comment_tests --test type_tests
```

For a targeted run:

```bash
cargo test --lib --bin ghidra-cli
cargo test --test daemon_tests
# These suites do not require Ghidra or a JDK installation:
cargo test --test e2e --test output_format_integration --test routing_tests --test harness_tests
```

`command_tests::test_doctor` checks a working installation in CI's
`readonly-integration` job; `output_format_integration` checks doctor's failure
output/exit status with a missing installation path.
It also checks project listing, exclusion of bare directories, and preservation of
project files when Ghidra is unavailable. Successful `.gpr`/`.rep` deletion uses
Ghidra's lock API and belongs in `project_tests`, including directory overrides
and preservation of unrelated source files.

Five `readonly_tests` Insta tests remain `#[ignore]` pending snapshot bootstrapping;
reference `.snap` files are not tracked. To run without accepting snapshots:

```bash
INSTA_UPDATE=no cargo test --test readonly_tests -- --ignored
```

These fail until reviewed snapshots are added; normal schema tests need no
snapshots. CI unit coverage runs both `--lib` and `--bin ghidra-cli`. Suite groupings are in
[the test workflow](../.github/workflows/test.yml).

`readonly_tests.rs` and `daemon_tests.rs` own their suite fixtures and serial
locks; domain modules under `readonly/` and `daemon/` remain in those executables.
Keep snapshot assertions at their original source/module path to preserve Insta
identity. Filter a domain with, for example,
`cargo test --test daemon_tests program_session::`.

## Coverage and fixtures

| Suite/source | Scope |
|---|---|
| `daemon_tests` | Lifecycle/jobs, program sessions/persistence, deletion, and output contracts |
| `reliability_tests`, `project_tests` | Restart/stale-state recovery and project management |
| `readonly_tests` | Functions/instructions, program metadata, relationships, search, batch queries, and response schemas |
| `memory_tests` | Pointer decoding across target widths, byte orders, and address spaces |
| `comment_tests`, `symbol_tests`, `patch_tests`, `tag_tests`, `type_tests`, `script_tests` | Domain mutations and scripts |
| `fixture_tests` | Relocated analyzed projects, durable edits, and isolation between copies |
| `command_tests` | Version flags, doctor, config |
| `bootstrap_tests` | Named imports across startup routes, durable import failure checkpoints, doctor runtime lifecycle |
| `e2e`, `output_format_integration`, `harness_tests` | CLI smoke/output behavior and test infrastructure |
| `routing_tests` | Recorded bridge requests: batch targets, list pagination, and client file paths without Ghidra |
| `src/ghidra/bridge/sources.rs` | Embedded Java inventory and source publication |

`daemon_tests` also checks cancellation does not poison the next job, handlers
follow program switch/close, automatic saves are visible in a separate database
object before shutdown, and failed mutations cannot erase earlier edits. Save
failures retain the editing result and program for recovery; explicit save keeps
the same JVM. Stop/restart/project deletion also preserve unsaved state on final
save failure; recovered edits survive shutdown and reopening. Project tests hold
an external Ghidra owner to verify refusal and deletion after lock release.
Bootstrap tests reject unknown loader options without saving a program.
They also verify analysis-completion flags for raw imports, reanalysis and
cancelled jobs. Program-session tests compare live and saved flags independently
of function count and check recursive status counts across restart and deletion.
Real bridge tests cover OSGi loading of the whole source bundle.
Script tests exercise JDK parsing of stdin declarations through that OSGi path.
Symbol tests cover generated-label rejection and deletion failures retaining
partial results through successful and failed saves; type tests verify that
explicit field sizes are either honored or rejected before layout changes.
Type tests also inspect saved component format/byte-order settings after metadata
and layout edits.
Program-session tests exclude root and nested data type archives from program lists
and status counts.
Formatter tests cover requested decompiler details in compact and full text output.
`readonly/query.rs` compares server-filtered pages with full rows for the five
supported list handlers and query aliases, including Unicode under a Turkish
locale, function tags, multiple comment types, unlimited/empty pages and bounds
beyond Java `int`. Planner and routing tests separately verify residual processing
and standalone/batch equivalence.
Batch coverage checks nonzero failure exits, preservation of per-command results
and save errors, and stopping subsequent commands after a save failure or timeout.
Program deletion coverage includes the initial program, closed files with matching
internal names, a stopped bridge, empty projects, batch deletion, and failures
that must preserve other consumers or unsaved changes.

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
