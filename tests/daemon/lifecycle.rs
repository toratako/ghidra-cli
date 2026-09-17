use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_ping() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "ping"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let _harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "ping"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("No bridge running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_restart() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra-cli bridge restart` stops the old bridge and starts a new JVM. With piped
    // stdout/stderr, the new JVM inherits pipe handles, blocking forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "bridge",
            "restart",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run restart");

    assert!(status.success(), "Restart failed with status: {status}");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "start"])
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}
