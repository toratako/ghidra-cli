# Common test utilities

| Source | Responsibility |
|---|---|
| [mod.rs](mod.rs) | `DaemonTestHarness`, per-executable project/fixture setup, availability checks, cleanup |
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

`test_project()` allocates a fresh absolute project path per test executable.
`ensure_test_project()` imports/analyzes the fixture once; import and stop failures
fail setup immediately. Projects from previous runs or other suites are not reused.

`DaemonTestHarness::new()` calls the bridge lifecycle API directly so startup
errors reach callers intact. It records the PID as well as the discovered port.
Drop calls `stop_bridge()` for drain/force termination, then waits for both the
original and current PIDs (restart may change them) to release project locks:
up to 15s per PID, or 30s on Windows, after stop. It removes stale discovery files
and the harness data directory. Suite-exit cleanup also stops the bridge and
removes the generated project/fixture; statics do not receive normal Rust Drop.
Cleanup remains best effort under forced process termination.
