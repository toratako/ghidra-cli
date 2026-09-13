# Tests

## Run

```bash
cargo test --no-fail-fast
cargo fmt --all -- --check
cargo clippy -- -D warnings
```

Ghidra-dependent tests must fail if Ghidra is unavailable. `require_ghidra!()`
checks `ghidra doctor` and panics with its output; never turn that into a skip.
Set `GHIDRA_INSTALL_DIR` to the installation and provide a suitable full JDK.

For a targeted run:

```bash
cargo test --lib --bin ghidra
cargo test --test daemon_tests
# These suites do not require Ghidra:
cargo test --test e2e --test output_format_integration --test harness_tests
```

Five `readonly_tests` Insta tests remain `#[ignore]` pending snapshot bootstrapping;
reference `.snap` files are not tracked. To run without accepting snapshots:

```bash
INSTA_UPDATE=no cargo test --test readonly_tests -- --ignored
```

These fail until reviewed snapshots are added. The normal suite also validates
response schemas without snapshots. CI suite groupings are in
[the test workflow](../.github/workflows/test.yml).

## Coverage and fixtures

| Suite/source | Scope |
|---|---|
| `daemon_tests`, `reliability_tests`, `project_tests` | Lifecycle, restart/stale-state recovery, project management |
| `readonly_tests` | Read queries and response schemas |
| `comment_tests`, `symbol_tests`, `patch_tests`, `tag_tests`, `type_tests`, `script_tests` | Domain mutations and scripts |
| `command_tests` | Version, doctor, config, init |
| `e2e`, `output_format_integration`, `harness_tests` | CLI smoke/output behavior and test infrastructure |
| `src/ghidra/bridge/sources.rs` | Embedded Java inventory and source publication |

`daemon_tests` also checks cancellation does not poison the next job, handlers
follow program switch/close, and a failed mutation cannot erase earlier edits
on restart. Real bridge tests cover OSGi loading of the whole source bundle.

`common::test_project()` gives each test executable a fresh project. Read-only
suites reuse a bridge to amortize JVM startup; lifecycle/mutation suites may
create and drop harnesses. Follow the owning suite's pattern and use `#[serial]`
for shared-state tests. Never share projects across suites/runs or assume fixed
function addresses; look them up by name.

`fixture_binary()` compiles [sample_binary.rs](fixtures/sample_binary.rs) with
`rustc` once per executable into temporary storage. It keeps function symbols,
exercises exports, and strips debug information to avoid expensive standard-library
DWARF analysis. It uses the host format (`.exe` on Windows); no binary fixture
or manual build is needed. Setup/import failures fail the tests.

See [common helpers and a test example](common/README.md) when adding tests.
Harness Drop and suite-exit cleanup are best effort; forced termination can leave
processes/projects behind. For slow startup, start with `ghidra doctor`; for
stale discovery files, inspect the owning project/process before cleanup.
Import/analysis setup currently has a 300s budget that can be tight under load;
see the [open TODO](../docs/TODO.md). Reducing parallel suites can reduce pressure.
