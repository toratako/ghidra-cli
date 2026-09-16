use super::{harness, TEST_PROGRAM};
use crate::common::{get_function_address, test_project, GhidraCommand};
use serial_test::serial;
use std::fs;
use std::path::PathBuf;

// Batch Tests

fn create_batch_file(content: &str) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let batch_file = temp_dir.join(format!("ghidra_batch_{}.txt", std::process::id()));
    fs::write(&batch_file, content).expect("Failed to write batch file");
    batch_file
}

#[test]
#[serial]
fn test_batch_multiple_queries() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let batch_content = format!(
        r#"
# Test batch file
program info
function get {address}
"#
    );

    let batch_file = create_batch_file(&batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(test_project())
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("results");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_empty_file() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Only comments


# More comments
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(test_project())
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_with_comments() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let batch_content = format!(
        r#"
# Query main function
function get {address}
# Query program metadata
program info
# Another comment
"#
    );

    let batch_file = create_batch_file(&batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(test_project())
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("2");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_invalid_file() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(test_project())
        .arg("/nonexistent/batch/file.txt")
        .run();

    result.assert_failure();
    assert!(
        result.stderr.contains("not found")
            || result.stderr.contains("No such file")
            || result.stderr.contains("cannot find"),
        "Should contain file-not-found error. Got: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_batch_with_invalid_command() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let batch_content = format!(
        r#"
function get {address}
invalid-command --arg value
program info
"#
    );

    let batch_file = create_batch_file(&batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(test_project())
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_failure();
    assert_eq!(result.exit_code, 1);
    assert!(!result.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_str(&result.stderr).unwrap();
    assert!(diagnostic["detail"].get("results").is_none());
    let report: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
    let error = &report[0];
    assert_eq!(error["commands_executed"], 3);
    assert_eq!(error["failed"], 1);
    assert_eq!(error["not_executed"], 0);
    assert!(error["results"][0]["result"].is_object());
    assert!(error["results"][1]["error"].is_string());
    assert!(error["results"][2]["result"].is_object());

    fs::remove_file(batch_file).ok();
}
