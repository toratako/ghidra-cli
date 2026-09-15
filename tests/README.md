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

`cargo test-run` forwards all arguments to `cargo test` and owns a temporary
fixture directory for that invocation. It preserves Cargo's test execution order
and returns its failure status. Each invocation gets a fresh source; nothing is
reused from a previous run. `--help` shows Cargo's test options.

Plain `cargo test` remains supported, with fixture reuse limited to each test
executable. Use `test-run` when selecting several Ghidra suites:

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

`command_tests::test_doctor` verifies a working Ghidra/JDK installation in CI's
`readonly-integration` job. `output_format_integration` checks doctor's failure
output and exit status using a missing installation path; its other tests cover
local CLI behavior without Ghidra prerequisites.

Five `readonly_tests` Insta tests remain `#[ignore]` pending snapshot bootstrapping;
reference `.snap` files are not tracked. To run without accepting snapshots:

```bash
INSTA_UPDATE=no cargo test --test readonly_tests -- --ignored
```

These fail until reviewed snapshots are added. The normal suite also validates
response schemas without snapshots. CI suite groupings are in
[the test workflow](../.github/workflows/test.yml).

`readonly_tests.rs` owns the shared bridge and keeps the snapshot assertions at
their original source/module path. Its `readonly/` modules cover functions and
instructions, program metadata, relationships, search, and batch queries.
`daemon_tests.rs` keeps one suite fixture while its `daemon/` modules cover
lifecycle, jobs, program sessions/persistence, deletion, and output contracts.
These modules remain part of their owning test executable and use the same
serial lock. Filter a domain with, for example,
`cargo test --test daemon_tests program_session::`.

## Coverage and fixtures

| Suite/source | Scope |
|---|---|
| `daemon_tests`, `reliability_tests`, `project_tests` | Lifecycle, restart/stale-state recovery, project management |
| `readonly_tests` | Read queries and response schemas |
| `memory_tests` | Pointer decoding across target widths, byte orders, and address spaces |
| `comment_tests`, `symbol_tests`, `patch_tests`, `tag_tests`, `type_tests`, `script_tests` | Domain mutations and scripts |
| `fixture_tests` | Relocated analyzed projects, durable edits, and isolation between copies |
| `command_tests` | Version, doctor, config, init |
| `e2e`, `output_format_integration`, `harness_tests` | CLI smoke/output behavior and test infrastructure |
| `routing_tests` | Recorded bridge requests: batch targets, list pagination, and client file paths without Ghidra |
| `src/ghidra/bridge/sources.rs` | Embedded Java inventory and source publication |

`daemon_tests` also checks cancellation does not poison the next job, handlers
follow program switch/close, automatic saves are visible in a separate database
object before shutdown, and failed mutations cannot erase earlier edits. Save
failures retain the editing result and program for recovery; explicit save keeps
the same JVM. Real bridge tests cover OSGi loading of the whole source bundle.
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
`rustc` once per runner invocation into temporary storage. It keeps function symbols,
exercises exports, and strips debug information to avoid expensive standard-library
DWARF analysis. It uses the host format (`.exe` on Windows); no binary fixture
or manual build is needed. The first suite that needs analysis runs the one-shot
importer and waits for Ghidra to save and exit. Each suite receives ordinary file
copies of that closed project in its own directory. Setup never starts a bridge;
the suite's harness starts it when needed. CLI import/analysis tests still create
new projects and exercise the real commands. Setup/import failures fail the tests.

With `-- --nocapture`, `[test setup]` lines report doctor, fixture compilation,
analysis, copy, and bridge startup times. Harness teardown reports shutdown time;
the runner reports total elapsed time after Cargo exits.

See [common helpers and a test example](common/README.md) when adding tests.
Harness Drop and suite-exit cleanup are best effort; forced termination can leave
processes/projects behind. For slow startup, start with `ghidra-cli doctor`; for
stale discovery files, inspect the owning project/process before cleanup.
CLI import/analysis tests currently have a 300s budget that can be tight under load;
see the [open TODO](../docs/TODO.md). Reducing parallel suites can reduce pressure.
