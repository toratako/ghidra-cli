//! End-to-end smoke tests for ghidra-cli
//!
//! This is a lightweight smoke test that verifies basic CLI functionality without Ghidra.
//! Comprehensive test coverage is in:
//! - command_tests.rs (version, doctor, config)
//! - project_tests.rs (project management, import, analyze)
//! - daemon_tests.rs (daemon lifecycle)
//! - query_tests.rs (function, strings, memory, decompile, dump)
//! - unimplemented_tests.rs (graceful error messages)

use predicates::prelude::*;

/// Smoke test - verifies basic CLI commands work
#[test]
fn test_smoke() {
    // Version command should always work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra-cli"));

    // Config list should work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("config")
        .arg("list")
        .assert()
        .success();
}
