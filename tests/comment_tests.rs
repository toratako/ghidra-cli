//! Tests for comment operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_comment_set_and_get() {
    require_ghidra!();
    let harness = harness();

    // Dynamically resolve an address with a code unit
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(&addr)
        .arg("test comment from integration test")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get the comment back
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test comment"));
}

#[test]
#[serial]
fn test_comment_list() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    let addr = &addrs[0];

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("another comment")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Analysis generates thousands of auto EOL reference comments at low
    // addresses; `comment list` is address-ordered and limited (default 1000),
    // so a user comment at a high function address can fall outside the default
    // window. Pass an explicit large limit so the assertion is deterministic.
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("list")
        .arg("--limit")
        .arg("100000")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("another comment"));
}

#[test]
#[serial]
fn test_comment_delete() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 3);
    let addr = &addrs[addrs.len() - 1];

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("to be deleted")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("delete")
        .arg(addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify comment is actually gone
    let get_result = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("get")
        .arg(addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&get_result.stdout);
    assert!(
        !get_result.status.success() || !stdout.contains("to be deleted"),
        "Comment should be deleted but was still found: {}",
        stdout
    );
}

#[test]
#[serial]
fn comment_stdin_preserves_multiline_text_without_prompting_pipelines() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let text = "stdin comment\nsecond line with `literal` $text\n";
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args([
            "--quiet",
            "comment",
            "set",
            &addr,
            "--stdin",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .write_stdin(text)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args([
            "comment",
            "get",
            &addr,
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value
            .to_string()
            .contains("second line with `literal` $text"),
        "{value}"
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn comment_terminal_stdin_explains_eof_even_when_quiet() {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let mut master = -1;
    let mut slave = -1;
    // File takes ownership of the fresh descriptors from openpty.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("ghidra"))
        .args([
            "--quiet",
            "comment",
            "set",
            &addr,
            "--stdin",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(b"terminal comment\n\x04").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("terminal stdin did not finish after EOF");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Enter comment text; finish with EOF (Ctrl-D)."),
        "{stderr}"
    );
}
