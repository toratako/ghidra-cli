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

#[test]
#[serial]
fn batch_resumes_corrected_signature_at_line_45_without_repeating_saved_edits() {
    require_ghidra!();
    let program = create_program(64);
    let before = function();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("refine.ghidra");
    let mut lines = vec!["type create struct Progress".to_owned()];
    for index in 1..44 {
        lines.push(format!(
            "type field append Progress --type int --name step_{index}"
        ));
    }
    lines.push(
        "function set-signature 0x1000 --signature 'void lookup(const char *text)'".to_owned(),
    );
    lines.push("type field append Progress --type int --name tail".to_owned());
    std::fs::write(&file, lines.join("\n")).unwrap();
    let failed = ghidra(harness())
        .args(["batch", file.to_str().unwrap(), "--on-error", "stop"])
        .with_project(test_project(), &program)
        .arg("--json")
        .run();
    failed.assert_failure();
    let report: Value = failed.json();
    assert_eq!(report[0]["commands_executed"], 45);
    assert_eq!(report[0]["not_executed"], 1);
    assert_eq!(report[0]["results"][44]["detail"]["rolled_back"], true);
    assert!(report[0]["results"][44]["error"]
        .as_str()
        .unwrap()
        .contains("const"));
    assert_eq!(report[0]["recovery"]["action"], "resume_from_line");
    assert_eq!(report[0]["recovery"]["line"], 45);
    assert_eq!(report[0]["recovery"]["program"], format!("/{program}"));
    let client = harness().client().unwrap();
    // Check saved state, then change the selection before following the hint.
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(), before);
    let progress: Value = type_command(&program, &["get", "Progress"]).json();
    assert_eq!(progress[0]["components"].as_array().unwrap().len(), 43);
    client.open_program(TEST_PROGRAM).unwrap();
    lines[44] = "function set-signature 0x1000 --signature 'void lookup(char *text)'".to_owned();
    std::fs::write(&file, lines.join("\n")).unwrap();
    let argv: Vec<String> = serde_json::from_value(report[0]["recovery"]["argv"].clone()).unwrap();
    let resumed = common::GhidraCommand::new()
        .arg("--json")
        .args(argv.into_iter().skip(1))
        .run();
    resumed.assert_success();
    let report: Value = resumed.json();
    assert_eq!(report[0]["commands_executed"], 2);
    assert_eq!(report[0]["results"][0]["line"], 45);
    client.program_close().unwrap();
    let progress: Value = type_command(&program, &["get", "Progress"]).json();
    assert_eq!(progress[0]["components"].as_array().unwrap().len(), 44);
    assert_eq!(progress[0]["components"][43]["name"], "tail");
    let signature = client
        .send_command(
            "get_function",
            Some(json!({
                "address": "0x1000", "with_signature": true,
            })),
        )
        .unwrap();
    assert_eq!(signature["signature_details"]["return"]["type"], "void");
    assert_eq!(signature["signature_details"]["params"][0]["name"], "text");
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn test_function_set_signature_rolls_back_native_application_failure() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("signature-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateSignatureTestProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("signature fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", address, 16, (byte) 0, monitor, false);
                var function = program.getFunctionManager().createFunction("signature_target", address,
                    new AddressSet(address, address.add(15)), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(address.add(1), "collision", function,
                    SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&program), &[], false).unwrap();

    let set_signature = |signature: &str| {
        ghidra(harness)
            .arg("function")
            .arg("set-signature")
            .arg("signature_target")
            .arg("--signature")
            .arg(signature)
            .with_project(test_project(), &program)
            .arg("--json")
            .run()
    };
    let valid = set_signature("int signature_target(int argument)");
    valid.assert_success();
    let result: serde_json::Value = valid.json();
    assert_eq!(result[0]["status"], "signature_set");
    assert!(result[0]["signature"]
        .as_str()
        .unwrap()
        .contains("int argument"));
    let before = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "signature_target"})),
        )
        .unwrap();

    // This is valid C syntax, but applying the parameter conflicts with a label
    // in the function's namespace. Ghidra changes the return type before checking
    // that conflict, then reports false without throwing.
    let invalid = set_signature("void signature_target(int collision)");
    invalid.assert_failure();
    let error: serde_json::Value = serde_json::from_str(&invalid.stderr).unwrap();
    assert_eq!(error["status"], "error");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("Failed to set signature: Parameter name conflict"),
        "{error}"
    );
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert!(error["detail"].get("partial_changes_saved").is_none());
    let after = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "signature_target"})),
        )
        .unwrap();
    assert_eq!(after, before);
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    let saved = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "signature_target"})),
        )
        .unwrap();
    assert_eq!(saved, before);

    let repaired = set_signature("void signature_target(int recovered)");
    repaired.assert_success();
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    let saved = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "signature_target"})),
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert!(
        saved["signature"]
            .as_str()
            .unwrap()
            .contains("void signature_target(int recovered)"),
        "{saved}"
    );
}
