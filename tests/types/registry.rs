use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serial_test::serial;

#[test]
#[serial]
fn test_signed_char_alias_preserves_signedness_on_unsigned_char_abi() {
    require_ghidra!();
    let program = create_type_edit_program("Hexagon:LE:32:default");
    type_command(&program, &["create", "struct", "Holder"]).assert_success();
    for (name, ty) in [("signed_value", "signed char"), ("plain_value", "char")] {
        type_command(
            &program,
            &["field", "append", "Holder", "--name", name, "--type", ty],
        )
        .assert_success();
    }

    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Structure;
public class CheckSignedCharAlias extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        if (dtm.getDataOrganization().isSignedChar())
            throw new IllegalStateException("Fixture must use unsigned plain char");
        var holder = (Structure) dtm.getDataType("/Holder");
        var signed = (CharDataType) holder.getComponent(0).getDataType();
        var plain = (CharDataType) holder.getComponent(1).getDataType();
        if (!signed.isSigned() || plain.isSigned())
            throw new IllegalStateException("Explicit signed char lost its signedness");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn test_type_rename_rejects_immutable_types_and_persists_mutable_types() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(&program, &["create", "struct", "Holder"]).assert_success();
    let before = type_command(&program, &["list", "--limit", "0"]);
    before.assert_success();
    let before: serde_json::Value = before.json();
    for name in ["int", "/int", "byte[4]", "void *"] {
        let failed = type_command(&program, &["rename", name, "Renamed"]);
        failed
            .assert_failure()
            .assert_stderr_contains("Type cannot be renamed");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(error["detail"].get("partial_changes_saved").is_none());
        type_command(&program, &["get", "Renamed"]).assert_failure();
    }
    let after = type_command(&program, &["list", "--limit", "0"]);
    after.assert_success();
    assert_eq!(after.json::<serde_json::Value>(), before);

    let renamed = type_command(&program, &["rename", "Holder", "Renamed"]);
    renamed.assert_success();
    let renamed: serde_json::Value = renamed.json();
    assert_eq!(renamed[0]["path"], "/Renamed");
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    let saved = type_command(&program, &["get", "/Renamed"]);
    saved.assert_success();
    let saved: serde_json::Value = saved.json();
    assert_eq!(saved[0]["name"], "Renamed");
    type_command(&program, &["get", "/Holder"]).assert_failure();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn test_type_delete_removes_registered_arrays_and_pointers() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
public class RegisterTypesForDeletion extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (int count : new int[] { 4, 5 })
            dtm.addDataType(new ArrayDataType(ByteDataType.dataType, count, -1, dtm), null);
        dtm.addDataType(new PointerDataType(ByteDataType.dataType, dtm), null);
        dtm.addDataType(new PointerDataType(CharDataType.dataType, dtm), null);
        dtm.addDataType(UnsignedIntegerDataType.dataType, null);
        dtm.addDataType(DWordDataType.dataType, null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let targets = [
        ("/byte[4]", "/byte[4]"),
        ("byte[5]", "/byte[5]"),
        ("/byte *", "/byte *"),
        ("char *", "/char *"),
        ("unsigned int", "/uint"),
        ("u32", "/dword"),
    ];
    let listed = type_command(&program, &["list", "--limit", "0"]);
    listed.assert_success();
    let listed: Vec<serde_json::Value> = listed.json();
    for (name, path) in targets {
        assert!(listed.iter().any(|ty| ty["path"] == path), "{listed:?}");
        let deleted = type_command(&program, &["delete", name]);
        deleted.assert_success();
        let deleted: serde_json::Value = deleted.json();
        assert_eq!(deleted[0]["path"], path);
        type_command(&program, &["delete", path])
            .assert_failure()
            .assert_stderr_contains("Type not found");
    }
    client.program_close().unwrap();
    // Reading a type expression remains valid without registering it again.
    type_command(&program, &["get", "byte[4]"]).assert_success();
    let saved = type_command(&program, &["list", "--limit", "0"]);
    saved.assert_success();
    let saved: Vec<serde_json::Value> = saved.json();
    for (_, path) in targets {
        assert!(!saved.iter().any(|ty| ty["path"] == path), "{saved:?}");
    }

    // A fixed-width alias must not delete an unrelated type at the same path.
    type_command(&program, &["create", "struct", "dword"]).assert_success();
    let failed = type_command(&program, &["delete", "u32"]);
    failed
        .assert_failure()
        .assert_stderr_contains("Type not found");
    let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
    assert!(error["detail"].get("partial_changes_saved").is_none());
    client.program_close().unwrap();
    let preserved = type_command(&program, &["get", "/dword"]);
    preserved.assert_success();
    let preserved: serde_json::Value = preserved.json();
    assert_eq!(preserved[0]["kind"], "struct");
    client.open_program(TEST_PROGRAM).unwrap();
}
