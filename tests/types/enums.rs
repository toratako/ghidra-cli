//! Enum deletion selects a name, including aliases that share a value.

use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::Value;
use serial_test::serial;

fn definition(program: &str, name: &str) -> Value {
    let result = type_command(program, &["get", name]);
    result.assert_success();
    result.data::<Value>()
}

#[test]
#[serial]
fn enum_member_deletion_preserves_same_valued_names_and_saved_metadata() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "create", "enum", "Mode", "--member", "Keep", "1", "--member", "Remove", "1",
            "--member", "Negative", "-1", "--size", "8",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Enum;
public class SetEnumMetadata extends GhidraScript {
    public void run() throws Exception {
        var type = (Enum) currentProgram.getDataTypeManager().getDataType("/Mode");
        type.setDescription("recovered mode");
        type.remove("Keep");
        type.add("Keep", 1, "alias remains");
        type.remove("Negative");
        type.add("Negative", -1, "signed member");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    let deleted = type_command(
        &program,
        &["enum", "member", "delete", "Mode", "--member", "Remove"],
    );
    deleted.assert_success();
    let deleted: Value = deleted.data();
    assert_eq!(deleted["path"], "/Mode");
    assert_eq!(deleted["member"], "Remove");
    assert_eq!(deleted["value"], 1);
    let remaining = definition(&program, "Mode");
    assert_eq!(remaining["size"], 8);
    assert_eq!(remaining["members"].as_array().unwrap().len(), 2);
    assert!(remaining["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|member| { member["name"] == "Keep" && member["value"] == 1 }));

    let missing = type_command(
        &program,
        &["enum", "member", "delete", "Mode", "--member", "Remove"],
    );
    missing
        .assert_failure()
        .assert_stderr_contains("Enum member not found");
    let error: Value = serde_json::from_str(&missing.stderr).unwrap();
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert_eq!(definition(&program, "Mode"), remaining);
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(definition(&program, "Mode"), remaining);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Enum;
public class CheckEnumMetadata extends GhidraScript {
    public void run() throws Exception {
        var type = (Enum) currentProgram.getDataTypeManager().getDataType("/Mode");
        if (!type.getDescription().equals("recovered mode") || type.getLength() != 8
                || !type.getComment("Keep").equals("alias remains")
                || !type.getComment("Negative").equals("signed member"))
            throw new IllegalStateException("Enum metadata changed during deletion");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    for member in ["Keep", "Negative"] {
        type_command(
            &program,
            &["enum", "member", "delete", "Mode", "--member", member],
        )
        .assert_success();
    }
    client.program_close().unwrap();
    let empty = definition(&program, "Mode");
    assert_eq!(empty["size"], 8);
    assert!(empty["members"].as_array().unwrap().is_empty());
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn enum_deletion_rejects_ambiguous_types_and_wrong_kind_before_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    for (category, value) in [("/First", 1), ("/Second", 2)] {
        let definition = format!("enum Mode {{ Keep={value}, Remove={value} }};");
        type_command(&program, &["import-c", &definition, "--category", category]).assert_success();
    }
    type_command(&program, &["create", "struct", "Holder"]).assert_success();
    type_command(
        &program,
        &[
            "field", "append", "Holder", "--name", "Remove", "--type", "byte",
        ],
    )
    .assert_success();
    let first = definition(&program, "/First/Mode");
    let second = definition(&program, "/Second/Mode");
    let holder = definition(&program, "Holder");
    for (name, message) in [("Mode", "Ambiguous"), ("Holder", "not an enum")] {
        let result = type_command(
            &program,
            &["enum", "member", "delete", name, "--member", "Remove"],
        );
        result.assert_failure().assert_stderr_contains(message);
        let error: Value = serde_json::from_str(&result.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    }
    assert_eq!(definition(&program, "/First/Mode"), first);
    assert_eq!(definition(&program, "/Second/Mode"), second);
    assert_eq!(definition(&program, "Holder"), holder);
    type_command(
        &program,
        &[
            "enum",
            "member",
            "delete",
            "/First/Mode",
            "--member",
            "Remove",
        ],
    )
    .assert_success();
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&program, "/Second/Mode"), second);
    assert_eq!(definition(&program, "Holder"), holder);
    assert_eq!(
        definition(&program, "/First/Mode")["members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
