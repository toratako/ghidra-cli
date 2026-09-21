//! C signature spelling, qualifier rejection, and persisted pointer types.

use super::*;
use serde_json::{json, Value};

fn create_program(bits: u32) -> String {
    let program = create_type_edit_program(&format!("x86:LE:{bits}:default"));
    type_command(
        &program,
        &[
            "import-c",
            "struct Entry { int value; };",
            "--category",
            "/Recovered",
        ],
    )
    .assert_success();
    harness().client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateSignatureSpellingFixture extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x1000);
        currentProgram.getMemory().createInitializedBlock("code", address, 16, (byte) 0, monitor, false);
        currentProgram.getFunctionManager().createFunction("lookup", address,
            new AddressSet(address, address.add(15)), SourceType.USER_DEFINED);
    }
}
"#, &[], &[], false).unwrap();
    program
}

fn set_signature(program: &str, signature: &str) -> common::helpers::GhidraResult {
    ghidra(harness())
        .args([
            "function",
            "set-signature",
            "0x1000",
            "--signature",
            signature,
        ])
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn function() -> Value {
    harness()
        .client()
        .unwrap()
        .send_command("get_function", Some(json!({"address": "0x1000"})))
        .unwrap()
}

#[test]
#[serial]
fn adjacent_pointer_return_names_preserve_types_after_reopen() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for bits in [32, 64] {
        let program = create_program(bits);
        for (declaration, depth) in [
            ("Entry *lookup(Entry *entry, int index)", "1"),
            ("Entry*lookup(Entry *entry, int index)", "1"),
            ("Entry * lookup(Entry *entry, int index)", "1"),
            ("Entry **lookup(Entry *entry, int index)", "2"),
        ] {
            let result = set_signature(&program, declaration);
            result.assert_success();
            let result: Value = result.json();
            assert_eq!(result[0]["status"], "signature_set");
            assert_eq!(result[0]["function"], "lookup");
            let before = function();
            client.program_close().unwrap();
            client.open_program(&program).unwrap();
            assert_eq!(function(), before);
            client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
public class CheckSignaturePointerTypes extends GhidraScript {
    private void checkPointer(DataType type, int depth) {
        for (int i = 0; i < depth; i++) {
            if (!(type instanceof Pointer) || type.getLength() != currentProgram.getDefaultPointerSize())
                throw new IllegalStateException("Wrong pointer type or target width: " + type);
            type = ((Pointer) type).getDataType();
        }
        if (!type.equals(currentProgram.getDataTypeManager().getDataType("/Recovered/Entry")))
            throw new IllegalStateException("Wrong pointee: " + type);
    }
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1000));
        if (!"lookup".equals(function.getName()) || function.getParameterCount() != 2)
            throw new IllegalStateException("Function name or parameters changed");
        checkPointer(function.getReturnType(), Integer.parseInt(getScriptArgs()[0]));
        checkPointer(function.getParameter(0).getDataType(), 1);
        if (!"entry".equals(function.getParameter(0).getName())
                || !"index".equals(function.getParameter(1).getName())
                || !"int".equals(function.getParameter(1).getDataType().getName()))
            throw new IllegalStateException("Parameter name or type changed");
    }
}
"#, &[depth.to_string()], &[], false).unwrap();
        }
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn unrepresentable_qualifiers_fail_without_changing_saved_signature() {
    require_ghidra!();
    let program = create_program(64);
    let client = harness().client().unwrap();
    // Identifier substrings are not qualifiers.
    set_signature(
        &program,
        "int lookup(char *const_buffer, int volatile_count)",
    )
    .assert_success();
    let before = function();
    let types_before = type_command(&program, &["list", "--limit", "0"]);
    types_before.assert_success();
    let types_before: Value = types_before.json();

    for (declaration, qualifier) in [
        ("void renamed(const char *text)", "const"),
        ("char const *renamed(void)", "const"),
        ("void renamed(char *const text)", "const"),
        // The native parser can mistake this unnamed parameter's qualifier for
        // its name and report success with an unqualified pointer type.
        ("void renamed(char *const)", "const"),
        ("void renamed(volatile int *value)", "volatile"),
        ("void renamed(char *restrict text)", "restrict"),
        ("void renamed(_Atomic(int) *value)", "_Atomic"),
    ] {
        let failed = set_signature(&program, declaration);
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(qualifier), "{error}");
        assert!(message.contains("cannot preserve"), "{error}");
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert!(error["detail"].get("partial_changes_saved").is_none());
        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            assert_eq!(function(), before);
            let types_after = type_command(&program, &["list", "--limit", "0"]);
            types_after.assert_success();
            assert_eq!(types_after.json::<Value>(), types_before);
        }
    }
    set_signature(&program, "void lookup(char *text)").assert_success();
    client.open_program(TEST_PROGRAM).unwrap();
}
