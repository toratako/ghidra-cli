//! Return-only edits retain inferred inputs without fixing their inferred types.

use super::*;
use serde_json::{json, Value};

pub(super) fn create_fixture() -> String {
    let program = format!("return-types-{}", unique_suffix());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("CreateReturnTypeFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    program
}

fn command(program: &str, args: &[&str]) -> common::helpers::GhidraResult {
    ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn function(program: &str, target: &str) -> Value {
    let result = command(program, &["function", "get", target, "--with-signature"]);
    result.assert_success();
    result.json::<Value>()[0].clone()
}

fn set_return(program: &str, target: &str, ty: &str) -> Value {
    let result = command(
        program,
        &["function", "set-return-type", target, "--type", ty],
    );
    result.assert_success();
    result.json::<Value>()[0].clone()
}

fn decompile(target: &str) -> Value {
    harness()
        .client()
        .unwrap()
        .send_command(
            "decompile",
            Some(json!({"address": target, "with_params": true})),
        )
        .unwrap()
}

#[test]
#[serial]
fn inferred_parameters_survive_return_edits_and_reopen_with_types_still_inferred() {
    require_ghidra!();
    let program = create_fixture();
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();

    for (selected, effective, saved_count) in [
        ("inferred", "inferred", 0),
        ("inferred_thunk", "thunk_target", 0),
        ("partial", "partial", 1),
    ] {
        let before = function(&program, effective);
        assert_eq!(before["signature_details"]["source"], "DEFAULT");
        assert_eq!(
            before["signature_details"]["params"]
                .as_array()
                .unwrap()
                .len(),
            saved_count
        );
        let inferred = decompile(effective);
        assert_eq!(
            inferred["params"].as_array().unwrap().len(),
            2,
            "{inferred}"
        );
        assert_eq!(inferred["params"][0]["type"], "int *", "{inferred}");
        assert_eq!(inferred["params"][1]["type"], "int", "{inferred}");

        let receipt = set_return(&program, selected, "int");
        assert_eq!(
            receipt["parameters_committed"],
            2 - saved_count,
            "{receipt}"
        );
        assert_eq!(receipt["return_type"], "int");
        if selected != effective {
            assert_eq!(receipt["effective_function"], effective, "{receipt}");
            assert_eq!(receipt["effective_address"], before["address"], "{receipt}");
        }
        let after = function(&program, effective);
        let signature = &after["signature_details"];
        assert_eq!(signature["source"], "USER_DEFINED");
        assert_eq!(signature["return"]["type"], "int");
        let params = signature["params"].as_array().unwrap();
        assert_eq!(params.len(), 2, "{after}");
        for (index, ty, storage) in [(0, "undefined8", "RDI:8"), (1, "undefined4", "ESI:4")] {
            assert_eq!(params[index]["type"], ty, "{after}");
            assert_eq!(params[index]["storage"], storage, "{after}");
        }
        if saved_count == 1 {
            assert_eq!(params[0], before["signature_details"]["params"][0]);
        }
        let conventions = client
            .send_command("function_list_calling_conventions", None)
            .unwrap();
        assert!(
            conventions["calling_conventions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == after["calling_convention"]),
            "{after}"
        );

        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(function(&program, effective), after);
        if saved_count == 1 {
            client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CheckPartiallySavedParameter extends GhidraScript {
    public void run() throws Exception {
        var parameter = getFunctionAt(toAddr(0x10a0)).getParameter(0);
        if (!"buffer".equals(parameter.getName()) || parameter.getSource() != SourceType.USER_DEFINED
                || !"retain partially saved parameter".equals(parameter.getComment()))
            throw new IllegalStateException("Return edit replaced existing parameter metadata");
    }
}
"#, &[], &[], false).unwrap();
        }
        let recovered = decompile(effective);
        assert_eq!(recovered["params"][0]["type"], "int *", "{recovered}");
        assert_eq!(recovered["params"][1]["type"], "int", "{recovered}");
        let code = recovered["code"].as_str().unwrap();
        assert!(code.contains(&format!("int {effective}(")), "{code}");
        assert!(
            !code.contains("in_RDI") && !code.contains("in_ESI"),
            "{code}"
        );

        let repeated = set_return(&program, selected, "void");
        assert_eq!(repeated["parameters_committed"], 0, "{repeated}");
        let changed = function(&program, effective);
        assert_eq!(changed["signature_details"]["return"]["type"], "void");
        assert_eq!(changed["signature_details"]["params"], signature["params"]);
        assert_eq!(changed["calling_convention"], after["calling_convention"]);
    }

    let zero = set_return(&program, "zero", "void");
    assert_eq!(zero["parameters_committed"], 0, "{zero}");
    assert_eq!(
        function(&program, "zero")["signature_details"]["params"],
        json!([])
    );

    let floating = decompile("floating");
    assert_eq!(
        floating["params"].as_array().unwrap().len(),
        2,
        "{floating}"
    );
    assert_eq!(
        set_return(&program, "floating", "void")["parameters_committed"],
        2
    );
    let after = function(&program, "floating");
    assert_eq!(after["signature_details"]["storage_mode"], "dynamic");
    assert_eq!(after["signature_details"]["return"]["type"], "void");
    for (index, inferred) in floating["params"].as_array().unwrap().iter().enumerate() {
        let inferred_type = inferred["type"].as_str().unwrap();
        let ty = if inferred_type == "double" {
            "double"
        } else {
            assert!(inferred_type.ends_with(" *"), "{floating}");
            "undefined8"
        };
        let parameter = &after["signature_details"]["params"][index];
        assert_eq!(parameter["type"], ty, "{after}");
        assert_eq!(parameter["storage"], inferred["storage"], "{after}");
    }
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(&program, "floating"), after);
    let recovered = decompile("floating");
    assert_eq!(recovered["params"], floating["params"]);
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn defined_custom_external_and_hidden_return_signatures_keep_explicit_parameters() {
    require_ghidra!();
    let program = format!("defined-return-types-{}", unique_suffix());
    let client = harness().client().unwrap();
    client
        .script_run_source(
            include_str!("../readonly/CreateSignatureDetailsFixture.java"),
            &[program.clone(), "gcc".to_owned()],
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class AnnotateReturnTypeFixture extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1100)).getParameter(0).setComment("retain explicit parameter comment");
    }
}
"#, &[], &[], false).unwrap();

    // These functions have no instructions: explicit declarations must not require decompilation.
    for (target, ty) in [
        ("plain", "void"),
        ("custom", "unsigned long long"),
        ("outside", "int"),
    ] {
        let before = function(&program, target);
        let receipt = set_return(&program, target, ty);
        assert_eq!(receipt["parameters_committed"], 0, "{receipt}");
        let after = function(&program, target);
        assert_eq!(
            after["signature_details"]["params"],
            before["signature_details"]["params"]
        );
        assert_eq!(after["calling_convention"], before["calling_convention"]);
        assert_eq!(
            after["signature_details"]["storage_mode"],
            before["signature_details"]["storage_mode"]
        );
        assert_eq!(
            after["signature_details"]["variadic"],
            before["signature_details"]["variadic"]
        );
        assert_ne!(
            after["signature_details"]["return"]["type"],
            before["signature_details"]["return"]["type"]
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(function(&program, target), after);
    }

    let indirect = function(&program, "indirect");
    assert_eq!(
        indirect["signature_details"]["params"][0]["auto_parameter"],
        "RETURN_STORAGE_PTR"
    );
    assert_eq!(
        set_return(&program, "indirect", "void")["parameters_committed"],
        0
    );
    let after = function(&program, "indirect");
    let params = after["signature_details"]["params"].as_array().unwrap();
    assert_eq!(params.len(), 1, "{after}");
    assert_eq!(params[0]["name"], "value");
    assert_eq!(params[0]["type"], "int");
    assert_eq!(params[0]["auto_parameter"], Value::Null);
    assert_eq!(after["signature_details"]["return"]["type"], "void");
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(&program, "indirect"), after);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckReturnTypeParameterComment extends GhidraScript {
    public void run() throws Exception {
        var parameter = getFunctionAt(toAddr(0x1100)).getParameter(0);
        if (!"retain explicit parameter comment".equals(parameter.getComment()))
            throw new IllegalStateException("Return edit lost explicit parameter comment");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn unavailable_parameter_inference_leaves_live_and_saved_signature_unchanged() {
    require_ghidra!();
    let program = create_fixture();
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    // A dynamic return type fails after inferred inputs have been committed,
    // exercising rollback of parameter and calling-convention edits too.
    for (target, ty) in [("unmapped", "int"), ("inferred", "string")] {
        let before = function(&program, target);
        assert_eq!(before["signature_details"]["source"], "DEFAULT");
        let failed = command(
            &program,
            &["function", "set-return-type", target, "--type", ty],
        );
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        if ty == "string" {
            assert!(
                error["message"].as_str().unwrap().contains("not permitted"),
                "{error}"
            );
        }
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
        assert_eq!(function(&program, target), before);
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(function(&program, target), before);
    }
    assert_eq!(
        set_return(&program, "inferred", "void")["parameters_committed"],
        2
    );
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn undefined_return_edits_keep_parameter_inference_open_without_decompiling_unmapped_functions() {
    require_ghidra!();
    let program = create_fixture();
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    let inferred = decompile("inferred");
    assert_eq!(inferred["params"].as_array().unwrap().len(), 2);
    let mut saved = Vec::new();

    for target in ["inferred", "unmapped"] {
        let before = function(&program, target);
        assert_eq!(before["signature_details"]["source"], "DEFAULT");
        assert_eq!(before["signature_details"]["params"], json!([]));
        assert_eq!(before["calling_convention"], "unknown");
        let receipt = set_return(&program, target, "undefined4");
        assert_eq!(receipt["parameters_committed"], 0, "{receipt}");
        let after = function(&program, target);
        assert_eq!(after["signature_details"]["return"]["type"], "undefined4");
        assert_eq!(after["signature_details"]["source"], "DEFAULT");
        assert_eq!(after["signature_details"]["params"], json!([]));
        assert_eq!(after["calling_convention"], before["calling_convention"]);
        saved.push((target, after));
    }
    assert_eq!(decompile("inferred")["params"], inferred["params"]);
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    for (target, expected) in saved {
        assert_eq!(function(&program, target), expected);
    }
    assert_eq!(decompile("inferred")["params"], inferred["params"]);
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn thiscall_return_edits_preserve_existing_auto_this_and_commit_only_the_formal_parameter() {
    require_ghidra!();
    let program = format!("thiscall-return-{}", unique_suffix());
    let client = harness().client().unwrap();
    client
        .script_run_source(
            include_str!("CreateThiscallReturnFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let before = function(&program, "method");
    assert_eq!(before["signature_details"]["source"], "DEFAULT");
    assert_eq!(
        before["signature_details"]["params"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        before["signature_details"]["params"][0]["auto_parameter"],
        "THIS"
    );
    assert_eq!(before["calling_convention"], "__thiscall");
    let inferred = decompile("method");
    assert_eq!(
        inferred["params"].as_array().unwrap().len(),
        2,
        "{inferred}"
    );
    assert!(
        inferred["code"]
            .as_str()
            .unwrap()
            .contains("__thiscall method("),
        "{inferred}"
    );

    let receipt = set_return(&program, "method", "int");
    assert_eq!(receipt["parameters_committed"], 1, "{receipt}");
    let after = function(&program, "method");
    assert_eq!(after["calling_convention"], "__thiscall");
    assert_eq!(after["signature_details"]["storage_mode"], "dynamic");
    assert_eq!(after["signature_details"]["return"]["type"], "int");
    let params = after["signature_details"]["params"].as_array().unwrap();
    assert_eq!(params.len(), 2, "{after}");
    assert_eq!(params[0]["auto_parameter"], "THIS");
    assert_eq!(params[0], before["signature_details"]["params"][0]);
    assert_eq!(params[0]["storage"], inferred["params"][0]["storage"]);
    assert_eq!(params[1]["auto_parameter"], Value::Null);
    assert_eq!(params[1]["type"], "undefined4");
    assert_eq!(params[1]["storage"], inferred["params"][1]["storage"]);
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(&program, "method"), after);
    let recovered = decompile("method");
    assert_eq!(
        recovered["params"].as_array().unwrap().len(),
        2,
        "{recovered}"
    );
    assert!(
        !recovered["code"].as_str().unwrap().contains("in_ECX"),
        "{recovered}"
    );
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}
