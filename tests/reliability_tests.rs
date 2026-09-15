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

/// A clean shutdown releases the project so the next bridge can reopen it.
#[test]
#[serial]
fn test_graceful_restart_reopens_project() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    // First bridge - start and stop cleanly
    {
        let _harness = start_harness("first bridge");

        // Verify bridge is working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Drop will clean up
    }

    // Second bridge - should start without issues (no stale port file conflict)
    {
        let _harness = start_harness("second bridge after restart");

        // Verify bridge is working
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("ping")
            .arg("--project")
            .arg(test_project())
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// A test child publishes startup/discovery state and waits for its owner to
/// terminate it. No process discovered outside this test is ever signalled.
#[test]
fn lifecycle_child() {
    let Some(project) = std::env::var_os("GHIDRA_CLI_TEST_CRASH_PROJECT") else {
        return;
    };
    let project = std::path::PathBuf::from(project);
    let port = ghidra_cli::ghidra::bridge::port_file_path(&project).unwrap();
    let starting = port.with_extension("starting");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(starting)
        .unwrap();
    lock.lock().unwrap();
    std::fs::write(
        ghidra_cli::ghidra::bridge::pid_file_path(&project).unwrap(),
        std::process::id().to_string(),
    )
    .unwrap();
    std::fs::write(port, "1").unwrap();
    std::fs::write(project.with_added_extension("child-ready"), []).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn leave_crashed_child_state(project: &std::path::Path) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_child", "--nocapture"])
        .env("GHIDRA_CLI_TEST_CRASH_PROJECT", project)
        .spawn()
        .unwrap();
    let ready = project.with_added_extension("child-ready");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ready.exists() && std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            panic!("test child exited before publishing state");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let published = ready.exists();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(published, "test child did not publish state");
    std::fs::remove_file(ready).unwrap();
}

#[test]
fn stale_state_recovers_after_owned_child_abrupt_exit() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("Project's state.v1");
    leave_crashed_child_state(&project);
    ghidra_cli::ghidra::bridge::stop_bridge(&project).unwrap();
    assert!(!ghidra_cli::ghidra::bridge::pid_file_path(&project)
        .unwrap()
        .exists());
    assert!(!ghidra_cli::ghidra::bridge::port_file_path(&project)
        .unwrap()
        .exists());
}

/// Real startup must recover the discovery and lifecycle-lock artifacts left by
/// an abruptly terminated, owned test child (not a gracefully stopped bridge).
#[test]
#[serial]
fn test_recovery_after_crash() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    ghidra_cli::ghidra::bridge::stop_bridge(std::path::Path::new(test_project())).unwrap();
    leave_crashed_child_state(std::path::Path::new(test_project()));
    let _harness = start_harness("bridge after owned child crash");
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("ping")
        .arg("--project")
        .arg(test_project())
        .timeout(Duration::from_secs(30))
        .assert()
        .success();
}

/// Test that bridge commands return appropriate errors when bridge is not ready.
#[test]
#[serial]
fn test_ping_fails_after_bridge_stops() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_harness("bridge");

    // Ping should work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("ping")
        .arg("--project")
        .arg(test_project())
        .timeout(Duration::from_secs(30))
        .assert()
        .success();

    drop(harness);

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["ping", "--project", test_project()])
        .timeout(Duration::from_secs(30))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["status"], "error");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("No bridge running"),
        "{diagnostic}"
    );
}
