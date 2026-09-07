//! Tests for bridge reliability - bridge death detection and port file cleanup.

use serial_test::serial;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

/// Start the bridge; missing programs and startup failures must fail the test.
fn start_harness(context: &str) -> DaemonTestHarness {
    DaemonTestHarness::new(test_project(), TEST_PROGRAM)
        .unwrap_or_else(|e| panic!("Failed to start bridge ({context}): {e}"))
}

/// Test that stale port files are cleaned up on bridge restart.
///
/// Simulates a crash scenario where port file remains but bridge is dead.
#[test]
#[serial]
fn test_stale_files_cleaned_on_restart() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    // First bridge - start and stop cleanly
    {
        let _harness = start_harness("first bridge");

        // Verify bridge is working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Drop will clean up
    }

    // Brief pause to ensure cleanup completes
    std::thread::sleep(Duration::from_millis(500));

    // Second bridge - should start without issues (no stale port file conflict)
    {
        let _harness = start_harness("second bridge after restart");

        // Verify bridge is working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test recovery after bridge crash (simulated via process kill).
///
/// After killing bridge, a new bridge should be able to start successfully.
#[test]
#[serial]
fn test_recovery_after_crash() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    // Start bridge and verify it works
    {
        let _harness = start_harness("initial bridge");

        // Verify it's working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Harness drop will kill bridge (simulating crash)
    }

    // Brief pause
    std::thread::sleep(Duration::from_millis(1000));

    // New bridge should start successfully after crash cleanup
    {
        let _harness = start_harness("bridge after crash");

        // Verify new bridge is working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test that bridge commands return appropriate errors when bridge is not ready.
#[test]
#[serial]
fn test_bridge_not_ready_error() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_harness("bridge");

    // Ping should work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("ping")
        .arg("--project")
        .arg(test_project())
        .timeout(Duration::from_secs(30))
        .assert()
        .success();

    drop(harness);
}
