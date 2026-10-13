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
fn convention_edits_reject_native_removal_of_explicit_parameters_atomically() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("convention-parameters-{}", unique_suffix());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateSignatureDetailsFixture.java"),
            &[program.clone(), "gcc".to_owned()],
            &[],
            false,
        )
        .unwrap();
    common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateExplicitThisParameter.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let before = function("plain");
        let failed = command(&program, "plain", "__thiscall");
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("explicit parameter"),
            "{error}"
        );
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            assert_eq!(function("plain"), before);
            client
                .script_run_source(
                    include_str!("../fixtures/types/CheckExplicitThisParameterComments.java"),
                    &[],
                    &[],
                    false,
                )
                .unwrap();
        }
        // Other concrete convention changes retain both formal inputs and comments.
        command(&program, "plain", "__regparm3").assert_success();
        let register_abi = function("plain");
        assert_eq!(register_abi["calling_convention"], "__regparm3");
        assert_eq!(
            register_abi["signature_details"]["params"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            register_abi["signature_details"]["params"][0]["name"],
            "this"
        );
        assert_eq!(
            register_abi["signature_details"]["params"][1]["name"],
            "count"
        );
        command(&program, "plain", "__cdecl").assert_success();
        assert_eq!(function("plain"), before);
        client
            .script_run_source(
                include_str!("../fixtures/types/RenameExplicitObjectParameter.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        command(&program, "plain", "__thiscall").assert_success();
        let thiscall = function("plain");
        assert_eq!(
            thiscall["signature_details"]["params"][0]["auto_parameter"],
            "THIS"
        );
        assert_eq!(thiscall["signature_details"]["params"][1]["name"], "object");
        assert_eq!(thiscall["signature_details"]["params"][1]["type"], "int *");
        assert_eq!(thiscall["signature_details"]["params"][2]["name"], "count");
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(function("plain"), thiscall);
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckThiscallFormalParameterComments.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    });
}

#[test]
#[serial]
fn convention_validation_uses_selected_spec_and_preserves_rejected_edits_after_reopen() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let x64 = return_types::create_fixture();
    client.open_program(&x64).unwrap();
    let conventions = client
        .send_command("program_list_calling_conventions", None)
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
    assert_eq!(accepted.data::<Value>()["calling_convention"], supported);
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
            include_str!("../fixtures/readonly/CreateSignatureDetailsFixture.java"),
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
