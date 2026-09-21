//! Convention edits must use a concrete model from the selected compiler spec.

use super::*;
use serde_json::{json, Value};

fn command(program: &str, target: &str, convention: &str) -> common::helpers::GhidraResult {
    ghidra(harness())
        .args([
            "function",
            "set-calling-convention",
            target,
            "--convention",
            convention,
        ])
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn function(target: &str) -> Value {
    harness()
        .client()
        .unwrap()
        .send_command(
            "get_function",
            Some(json!({"address": target, "with_signature": true})),
        )
        .unwrap()
}

#[test]
#[serial]
fn convention_validation_uses_selected_spec_and_preserves_rejected_edits_after_reopen() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let x64 = return_types::create_fixture();
    client.open_program(&x64).unwrap();
    let conventions = client
        .send_command("function_list_calling_conventions", None)
        .unwrap();
    let models = conventions["calling_conventions"].as_array().unwrap();
    assert!(
        !models.iter().any(|row| row["name"] == "__cdecl"),
        "{conventions}"
    );
    let supported = models.iter().find(|row| row["is_default"] == true).unwrap()["name"]
        .as_str()
        .unwrap();
    let accepted = command(&x64, "inferred", supported);
    accepted.assert_success();
    assert_eq!(accepted.json::<Value>()[0]["calling_convention"], supported);
    let before = function("inferred");
    assert_eq!(before["calling_convention"], supported);

    // This real model belongs to another ABI, not the selected compiler spec.
    let failed = command(&x64, "inferred", "__cdecl");
    failed.assert_failure();
    let error: Value = serde_json::from_str(&failed.stderr).unwrap();
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("__cdecl"), "{error}");
    for model in models {
        assert!(message.contains(model["name"].as_str().unwrap()), "{error}");
    }
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert_eq!(function("inferred"), before);
    client.program_close().unwrap();
    client.open_program(&x64).unwrap();
    assert_eq!(function("inferred"), before);

    let x32 = format!("convention-x32-{}", unique_suffix());
    client
        .script_run_source(
            include_str!("../readonly/CreateSignatureDetailsFixture.java"),
            &[x32.clone(), "gcc".to_owned()],
            &[],
            false,
        )
        .unwrap();
    client.open_program(&x32).unwrap();
    command(&x32, "unknown", "__cdecl").assert_success();
    assert_eq!(function("unknown")["calling_convention"], "__cdecl");
    client.program_close().unwrap();
    client.open_program(&x32).unwrap();
    assert_eq!(function("unknown")["calling_convention"], "__cdecl");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&x64).unwrap();
    client.program_delete(&x32).unwrap();
}
