use super::{ghidra, harness, test_project, TEST_PROGRAM};
use serial_test::serial;

#[test]
#[serial]
fn test_function_edit_var_updates_locals_and_parameters_and_persists() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("variables-{}", uuid::Uuid::new_v4());
    // Address-taking keeps a real stack local visible to the decompiler. The
    // local starts inferred, so rename-only must not pin its inferred int type.
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateVariableTestProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("variable fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", address, 0x200, (byte) 0, monitor, false);
                String hex = "5589e583ec108b45088945fc8d45fc50e8eb00000083c4048b45fcc9c3";
                byte[] code = new byte[hex.length() / 2];
                for (int i = 0; i < code.length; i++) code[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
                program.getMemory().setBytes(address, code);
                var sinkAddress = address.add(0x100);
                program.getMemory().setByte(sinkAddress, (byte) 0xc3);
                var function = program.getFunctionManager().createFunction("edit_target", address,
                    new AddressSet(address, address.add(code.length - 1)), SourceType.USER_DEFINED);
                function.setCallingConvention("__cdecl");
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                function.addParameter(new ParameterImpl("input", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
                var sink = program.getFunctionManager().createFunction("sink", sinkAddress,
                    new AddressSet(sinkAddress, sinkAddress), SourceType.USER_DEFINED);
                sink.setCallingConvention("__cdecl");
                sink.addParameter(new ParameterImpl("ptr", new PointerDataType(IntegerDataType.dataType), program), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(address.add(1), "collision", function, SourceType.USER_DEFINED);
                if (!new DisassembleCommand(address, null, true).applyTo(program, monitor))
                    throw new IllegalStateException("Fixture disassembly failed");
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&program), &[], false).unwrap();

    let decompile = || {
        let output = ghidra(harness)
            .args([
                "decompile",
                "edit_target",
                "--with-vars",
                "--with-params",
                "--json",
            ])
            .with_project(test_project(), &program)
            .run();
        output.assert_success();
        output.data::<serde_json::Value>()
    };
    let edit = |variable: &str, flags: &[&str]| {
        ghidra(harness)
            .args([
                "function",
                "edit-var",
                "edit_target",
                "--var",
                variable,
                "--json",
            ])
            .args(flags.iter().copied())
            .with_project(test_project(), &program)
            .run()
    };
    let initial = decompile();
    let locals = initial["variables"].as_array().unwrap();
    assert_eq!(locals.len(), 1, "{initial}");
    let original = &locals[0];

    let renamed = edit(original["name"].as_str().unwrap(), &["--name", "value"]);
    renamed.assert_success();
    let renamed: serde_json::Value = renamed.data();
    assert_eq!(renamed["kind"], "local");
    assert_eq!(renamed["before"]["name"], original["name"]);
    assert_eq!(renamed["after"]["name"], "value");
    assert_eq!(renamed["after"]["type"], "undefined4");
    assert_eq!(decompile()["variables"][0]["type"], original["type"]);

    let typed = edit("value", &["--type", "uint"]);
    typed.assert_success();
    let typed: serde_json::Value = typed.data();
    assert_eq!(typed["after"]["name"], "value");
    assert_eq!(typed["after"]["type"], "uint");

    let combined = edit("value", &["--name", "buffer", "--type", "char *"]);
    combined.assert_success();
    let combined: serde_json::Value = combined.data();
    assert_eq!(combined["before"]["name"], "value");
    assert_eq!(combined["after"]["name"], "buffer");
    assert_eq!(combined["after"]["type"], "char *");
    assert_eq!(combined["after"]["storage"], combined["before"]["storage"]);

    let parameter = edit("input", &["--name", "count", "--type", "uint"]);
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["kind"], "parameter");
    assert_eq!(parameter["after"]["name"], "count");
    assert_eq!(parameter["after"]["type"], "uint");
    let parameter = edit("count", &["--name", "length"]);
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["after"]["type"], "uint");
    let parameter = edit("length", &["--type", "int"]);
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["after"]["name"], "length");
    assert_eq!(parameter["after"]["type"], "int");

    let before_errors = decompile();
    for (flags, message) in [
        (vec!["--name", "collision", "--type", "float"], "conflicts"),
        (vec!["--name", "length", "--type", "float"], "conflicts"),
        (
            vec!["--name", "bad name", "--type", "float"],
            "invalid characters",
        ),
        (
            vec!["--name", "changed", "--type", "MissingType"],
            "Type not found",
        ),
        (
            vec!["--name", "changed", "--type", "void"],
            "fixed positive size",
        ),
    ] {
        let failed = edit("buffer", &flags);
        failed.assert_failure();
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["message"].as_str().unwrap().contains(message),
            "{error}"
        );
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
    }
    let missing = edit("does_not_exist", &["--name", "changed"]);
    missing.assert_failure();
    assert!(missing.stderr.contains("Variable not found"));
    // Direct bridge callers receive the same input validation as CLI callers.
    for args in [
        serde_json::json!({"target": "edit_target", "var_name": "buffer"}),
        serde_json::json!({"target": "edit_target", "var_name": "buffer", "new_name": ""}),
        serde_json::json!({"target": "edit_target", "var_name": "buffer", "new_name": "changed", "type_name": ""}),
    ] {
        assert!(client
            .send_command("function_edit_var", Some(args))
            .is_err());
    }
    assert!(client
        .send_command("set_var_type", None)
        .unwrap_err()
        .to_string()
        .contains("Unknown command"));
    let after_errors = decompile();
    assert_eq!(after_errors["variables"], before_errors["variables"]);
    assert_eq!(after_errors["params"], before_errors["params"]);

    // Releasing and reopening the program must recover the saved definitions.
    client.program_close().unwrap();
    let saved = decompile();
    assert_eq!(saved["variables"], before_errors["variables"]);
    assert_eq!(saved["params"], before_errors["params"]);
    assert_eq!(saved["variables"][0]["name"], "buffer");
    assert_eq!(saved["variables"][0]["type"], "char *");
    assert_eq!(saved["params"][0]["name"], "length");
    client.open_program(TEST_PROGRAM).unwrap();
}
