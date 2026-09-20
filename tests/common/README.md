# Common test utilities

| Source | Responsibility |
|---|---|
| [mod.rs](mod.rs) | `DaemonTestHarness`, per-executable project ownership, availability checks, cleanup |
| [fixture.rs](fixture.rs) | Run-scoped binary and analyzed source, publication locking, isolated copies |
| [helpers.rs](helpers.rs) | `GhidraCommand`, `GhidraResult`, name matching and assertions |
| [schemas.rs](schemas.rs) | Response validation |

## Adding a bridge test

Reuse the owning suite's harness where available. For a test that owns its bridge:

```rust
#[test]
#[serial]
fn test_function_list() {
    require_ghidra!();
    let project = common::test_project();
    let program = common::FIXTURE_PROGRAM;
    common::ensure_test_project(project, program);
    let harness = common::DaemonTestHarness::new(project, program)
        .expect("Failed to start bridge");
    let result = common::helpers::ghidra(&harness)
        .arg("function").arg("list")
        .with_project(project, program)
        .json_format().run();
    result.assert_success();
}
```

`ghidra(&harness)` supplies the project; `timeout` sets the command budget.
Use response schemas/domain assertions. See [suite guidance](../README.md) for
fixture compilation, serial execution, commands, and unbootstrapped snapshots.

## Lifecycle boundaries

`test_project()` allocates a fresh directory per test executable, keeping the
source project basename `project`. `ensure_test_project()` copies the run's closed,
analyzed source into it once. Never open or mutate the source with a bridge.

[`xtask/src/test.rs`](../../xtask/src/test.rs) supplies `GHIDRA_TEST_RUN_DIR` for
`cargo xtask test` and removes it after Cargo exits, including on failure.
Without the runner, executables own local storage. This internal variable must
not point to a persistent cache; parent configuration and source files must stay
fixed during an invocation.

`fixture.rs` locks each preparation stage with an OS file lock and publishes by
directory rename only on success; interrupted builders cannot publish partial
sources. Later suites fail with the original diagnostic; the next invocation
starts fresh. Copies use ordinary files, preserve the project
basename, omit sibling lock/discovery files, and reject existing destinations.

`require_ghidra!()` delegates to this module's shared `DoctorCheck`, avoiding a
cache per macro expansion. Every caller checks the retained output/spawn failure.
For prerequisite policy and direct doctor tests, see [suite guidance](../README.md#run).

`DaemonTestHarness::new()` calls the lifecycle API directly, preserving startup
errors, and records the PID and port. Drop calls `stop_bridge()` to drain/force
termination, then waits for original and current PIDs (restart may change them)
to release locks: up to 15s per PID, or 30s on Windows, after stop. Only then are stale
discovery files removed. Statics do not receive Rust Drop; suite-exit cleanup
stops the bridge and removes its project/local fixture. Shared sources belong to
the runner. Cleanup is best effort under forced termination.

For CLI commands that start or restart a persistent bridge, use
`run_command_with_output()` when asserting stdout/stderr. It captures to temporary
files and bounds the CLI process wait; the harness still owns bridge cleanup.
On Windows, descendants can inherit output pipe handles, so `assert_cmd::output()`
may wait for EOF even after its process timeout. `run_cli_with_timeout()` remains
available when output assertions are unnecessary.
