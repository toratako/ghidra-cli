//! End-to-end smoke tests for ghidra-cli
//!
//! This is a lightweight smoke test that verifies basic CLI functionality without Ghidra.
//! Comprehensive test coverage is in:
//! - command_tests.rs (version flags, doctor, config)
//! - project_tests.rs (project management, import, analyze)
//! - daemon_tests.rs (daemon lifecycle)
//! - readonly_tests.rs (functions, strings, memory, program listings, decompile)
//! - unimplemented_tests.rs (graceful error messages)

/// Smoke test - verifies basic CLI commands work
#[test]
fn test_smoke() {
    for flag in ["--version", "-V"] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg(flag)
            .assert()
            .success()
            .stdout(concat!("ghidra-cli ", env!("CARGO_PKG_VERSION"), "\n"));
    }

    // Config list should work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("config")
        .arg("list")
        .assert()
        .success();
}
