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

`ghidra(&harness)` supplies the project; builder options include `with_project`,
`json_format`, and `timeout`. Use response schemas/domain assertions for the
behavior under test. [Suite guidance](../README.md) covers fixture compilation,
serial execution, test commands, and unbootstrapped snapshots.

## Lifecycle boundaries

`test_project()` allocates a fresh directory per test executable, keeping the
source project basename `project`. `ensure_test_project()` copies the run's closed,
analyzed source into it once. Never open or mutate the source with a bridge.

`tests/support/test_runner.rs` supplies `GHIDRA_TEST_RUN_DIR` and removes it after Cargo
exits, including on test failure. Without the runner, each executable owns local
fixture storage. The environment variable is internal to the runner and test
helpers; it must not point to a persistent cache. Parent configuration and source
files must remain fixed during an invocation.

`fixture.rs` uses an OS file lock for each preparation stage and publishes by
directory rename only after successful completion. Failed preparation is recorded
for the rest of the invocation; later suites fail with the original diagnostic.
An interrupted builder cannot publish a partial source. A subsequent runner
invocation always starts fresh. Copies use ordinary files, preserve the project
basename, and omit sibling lock/discovery files. Existing destinations are rejected.

`require_ghidra!()` delegates to a shared `DoctorCheck` in this module, so macro
expansion does not create one cache per test. The output or spawn failure is
retained and checked by every caller. Direct doctor calls remain available for
tests of changed environments and doctor itself.

`DaemonTestHarness::new()` calls the bridge lifecycle API directly so startup
errors reach callers intact. It records the PID as well as the discovered port.
Drop calls `stop_bridge()` for drain/force termination, then waits for both the
original and current PIDs (restart may change them) to release project locks:
up to 15s per PID, or 30s on Windows, after stop. It removes stale discovery files
after waiting. Suite-exit cleanup also stops the bridge and removes the suite
project and any locally owned fixture; shared sources belong
to the runner. Statics do not receive normal Rust Drop.
Cleanup remains best effort under forced process termination.

For CLI commands that start or restart a persistent bridge, use
`run_command_with_output()` when asserting stdout/stderr. It captures to temporary
files and bounds the CLI process wait; the harness still owns bridge cleanup.
On Windows, descendants can inherit output pipe handles, so `assert_cmd::output()`
may wait for EOF even after its process timeout. `run_cli_with_timeout()` remains
available when output assertions are unnecessary.
