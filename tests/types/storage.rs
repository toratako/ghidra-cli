//! Native ABI storage edits, including byte order, hidden inputs, and atomic replacement.
use super::*;
use serde_json::{json, Value};

fn command(program: &str, args: &[&str]) -> common::helpers::GhidraResult {
    ghidra(harness())
        .arg("function")
        .args(args.iter().copied())
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
            Some(json!({"address": target, "with_signature": true, "with_frame": true})),
        )
        .unwrap()
}

fn assert_rejected(program: &str, target: &str, options: &[&str], diagnostic: &str) {
    let before = function(target);
    let mut args = vec!["set-storage", target];
    args.extend_from_slice(options);
    let failed = command(program, &args);
    failed.assert_failure();
    let error: Value = serde_json::from_str(&failed.stderr).unwrap();
    assert!(
        error["message"].as_str().unwrap().contains(diagnostic),
        "{error}"
    );
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert_eq!(function(target), before);
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(program).unwrap();
    assert_eq!(function(target), before);
}

#[test]
#[serial]
fn storage_partial_edits_preserve_saved_abi_and_replace_parameters_atomically() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("storage-x86-{}", unique_suffix());
    client
        .script_run_source(
            include_str!("../readonly/CreateSignatureDetailsFixture.java"),
            &[program.clone(), "gcc".into()],
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
public class StorageMetadataFixture extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1100));
        function.getParameter(1).setComment("preserved parameter comment");
        function.getParameter(1).getSymbol().setSource(SourceType.IMPORTED);
        var signature = new FunctionDefinitionDataType("local_override");
        signature.setReturnType(CharDataType.dataType);
        HighFunctionDBUtil.writeOverride(function, function.getEntryPoint(), signature);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let override_args = json!({"target":"plain", "at":"0x1100"});
    let call_override = client
        .send_command("function_call_signature_get", Some(override_args.clone()))
        .unwrap();
    assert!(call_override["override"].is_object(), "{call_override}");
    let unrelated = function("custom");
    let before = function("plain");
    let edit = command(
        &program,
        &["set-storage", "plain", "--param-register", "first", "EAX"],
    );
    edit.assert_success();
    let receipt = edit.data::<Value>();
    assert_eq!(receipt["before"]["storage_mode"], "dynamic");
    assert_eq!(receipt["after"]["storage_mode"], "custom");
    assert_eq!(receipt["after"]["variadic"], true);
    assert_eq!(
        receipt["after"]["params"][1],
        before["signature_details"]["params"][1]
    );
    assert_eq!(
        receipt["after"]["return"],
        before["signature_details"]["return"]
    );
    assert_eq!(
        function("plain")["calling_convention"],
        before["calling_convention"]
    );
    assert_eq!(function("custom"), unrelated);
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class InspectStorageMetadata extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1100));
        var parameter = function.getParameter(1);
        if (!"preserved parameter comment".equals(parameter.getComment())
            || parameter.getSource() != SourceType.IMPORTED || function.getLocalVariables().length != 3
            || function.getStackPurgeSize() != 4 || function.getStackFrame().getReturnAddressOffset() != 8)
            throw new IllegalStateException("Partial edit changed unrelated metadata");
    }
}
"#, &[], &[], false).unwrap();
    assert_eq!(
        client
            .send_command("function_call_signature_get", Some(override_args))
            .unwrap(),
        call_override
    );
    let unchanged = command(
        &program,
        &["set-storage", "plain", "--param-register", "first", "EAX"],
    );
    unchanged.assert_success();
    assert_eq!(unchanged.data::<Value>()["changed"], false);

    // The final layout is valid even though each individual move would collide.
    command(
        &program,
        &[
            "set-storage",
            "plain",
            "--param-register",
            "second",
            "EAX",
            "--param-stack",
            "first",
            "8",
        ],
    )
    .assert_success();
    assert_eq!(
        function("plain")["signature_details"]["params"][1]["storage"],
        "EAX:4"
    );
    for (options, message) in [
        (vec!["--param-register", "first", "EAX"], "overlaps"),
        (vec!["--param-register", "first", "ECX"], "conflict"),
        (vec!["--param-stack", "first", "-16"], "conflict"),
        (
            vec!["--param-stack", "first", "-2"],
            "stack frame constraints",
        ),
        (vec!["--param-register", "first", "AX"], "does not fit"),
        (
            vec!["--param-register", "first", "NONEXISTENT"],
            "list-registers",
        ),
        (
            vec!["--param-register", "missing", "EBX"],
            "available parameters",
        ),
    ] {
        assert_rejected(&program, "plain", &options, message);
    }
    assert_rejected(
        &program,
        "indirect",
        &["--param-register", "value", "EBX"],
        "physical signature",
    );
    assert_rejected(
        &program,
        "plain_thunk",
        &["--return-register", "EDX"],
        "storage owner",
    );

    let method = function("method");
    assert_eq!(
        method["signature_details"]["params"][0]["auto_parameter"],
        "THIS"
    );
    command(
        &program,
        &["set-storage", "method", "--param-register", "value", "EDX"],
    )
    .assert_success();
    let after = function("method");
    let mut explicit_this = method["signature_details"]["params"][0].clone();
    explicit_this["auto_parameter"] = Value::Null;
    explicit_this["storage"] = json!(explicit_this["storage"]
        .as_str()
        .unwrap()
        .trim_end_matches(" (auto)"));
    assert_eq!(after["signature_details"]["params"][0], explicit_this);
    assert_eq!(after["signature_details"]["return"]["storage"], "<VOID>");
    command(
        &program,
        &["set-storage", "unassigned", "--return-register", "EAX"],
    )
    .assert_success();
    let saved = function("plain");
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function("plain"), saved);
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn storage_complete_signatures_follow_native_endian_register_and_float_rules() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, first, second, float, float_size, native_return) in [
        (
            "x86:LE:32:default",
            "EAX",
            "EDX",
            "ST0",
            "10",
            "EDX:4,EAX:4",
        ),
        ("ARM:BE:32:v7", "r0", "r1", "s0", "4", "r0:4,r1:4"),
    ] {
        let program = create_type_edit_program(language);
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateStorageFunction extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x1000);
        currentProgram.getFunctionManager().createFunction("entry", address,
            new AddressSet(address, address), SourceType.USER_DEFINED);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let registers = ghidra(harness())
            .args([
                "program",
                "list-registers",
                &program,
                "--filter",
                &format!("name={first}"),
                "--fields",
                "name,size",
                "--json",
            ])
            .run();
        registers.assert_success();
        assert_eq!(
            registers.data::<Value>(),
            json!([{"name": first, "size": 4}])
        );

        let edit = command(
            &program,
            &[
                "set-signature",
                "entry",
                "--signature",
                "long long entry(short small, long long pair, float sample)",
                "--param-stack",
                "small",
                "-0x10",
                "--param-register-piece",
                "pair",
                "4",
                second,
                "4",
                "--param-register-piece",
                "pair",
                "0",
                first,
                "4",
                "--param-register-piece",
                "sample",
                "0",
                float,
                float_size,
                "--return-register-piece",
                "4",
                second,
                "4",
                "--return-register-piece",
                "0",
                first,
                "4",
            ],
        );
        edit.assert_success();
        let receipt = edit.data::<Value>();
        assert_eq!(receipt["after"]["return"]["storage"], native_return);
        assert_eq!(
            receipt["after"]["return"]["storage_pieces"][0]["register"],
            first
        );
        assert_eq!(
            receipt["after"]["return"]["storage_pieces"][1]["value_offset"],
            4
        );
        assert_eq!(
            receipt["after"]["params"][0]["storage_pieces"][0]["stack_offset"],
            -16
        );
        assert_eq!(
            receipt["after"]["params"][2]["storage_size"],
            float_size.parse::<i32>().unwrap()
        );
        // Inspect native offsets independently of the bridge encoder.
        let native = client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class InspectStorageOffset extends GhidraScript {
    public void run() throws Exception {
        var storage = getFunctionAt(toAddr(0x1000)).getReturn().getVariableStorage();
        if (storage.getRegisterOffset(currentProgram.getRegister(getScriptArgs()[0])) != 0
            || storage.getRegisterOffset(currentProgram.getRegister(getScriptArgs()[1])) != 4)
            throw new IllegalStateException("Native byte order differs from requested value offsets");
    }
}
"#, &[first.into(), second.into()], &[], false);
        native.unwrap();
        assert_rejected(
            &program,
            "entry",
            &["--return-register-piece", "0", first, "4"],
            "does not match type size",
        );
        assert_rejected(
            &program,
            "entry",
            &[
                "--return-register-piece",
                "0",
                first,
                "4",
                "--return-register-piece",
                "4",
                first,
                "4",
            ],
            "conflicting storage",
        );
        // A mixed register/stack value and a stack return use the same byte-offset model.
        let mixed = command(
            &program,
            &[
                "set-storage",
                "entry",
                "--param-register-piece",
                "pair",
                "0",
                first,
                "4",
                "--param-stack-piece",
                "pair",
                "4",
                "16",
                "4",
                "--return-stack",
                "-32",
            ],
        );
        mixed.assert_success();
        assert_eq!(
            mixed.data::<Value>()["after"]["params"][1]["storage_pieces"][1]["stack_offset"],
            16
        );
        assert_eq!(
            mixed.data::<Value>()["after"]["return"]["storage_pieces"][0]["stack_offset"],
            -32
        );
        let before = function("entry");
        let incomplete = command(
            &program,
            &[
                "set-signature",
                "entry",
                "--signature",
                "int entry(int value)",
                "--param-register",
                "value",
                first,
            ],
        );
        incomplete.assert_failure();
        assert!(
            incomplete.stderr.contains("Missing return storage"),
            "{}",
            incomplete.stderr
        );
        assert_eq!(function("entry"), before);
        // Void needs no return location; a short uses the low bytes, including BE registers.
        let edit = command(
            &program,
            &[
                "set-signature",
                "entry",
                "--signature",
                "void entry(short small)",
                "--param-register",
                "small",
                first,
            ],
        );
        edit.assert_success();
        assert_eq!(
            edit.data::<Value>()["after"]["params"][0]["storage_size"],
            2
        );
        assert_rejected(
            &program,
            "entry",
            &["--return-register", first],
            "void return",
        );
        let saved = function("entry");
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(function("entry"), saved);
        // A declaration without locations selects the existing dynamic mode.
        command(
            &program,
            &[
                "set-signature",
                "entry",
                "--signature",
                "int entry(int value)",
            ],
        )
        .assert_success();
        assert_eq!(
            function("entry")["signature_details"]["storage_mode"],
            "dynamic"
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
    }
}

#[test]
#[serial]
fn storage_piece_order_changes_native_decompilation_and_survives_reopen() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = create_type_edit_program("x86:LE:32:default");
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateStorageCodeFixture extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x1000);
        var block = currentProgram.getMemory().createInitializedBlock("code", address, 16, (byte)0, monitor, false);
        block.setExecute(true);
        // mov eax,0x11223344; mov edx,0x55667788; ret
        currentProgram.getMemory().setBytes(address, new byte[] {
            (byte)0xb8, 0x44, 0x33, 0x22, 0x11, (byte)0xba, (byte)0x88, 0x77, 0x66, 0x55, (byte)0xc3
        });
        disassemble(address);
        currentProgram.getFunctionManager().createFunction("entry", address,
            new AddressSet(address, address.add(10)), SourceType.USER_DEFINED);
    }
}
"#, &[], &[], false).unwrap();
    command(
        &program,
        &[
            "set-signature",
            "entry",
            "--signature",
            "long long entry(void)",
            "--return-register-piece",
            "0",
            "EAX",
            "4",
            "--return-register-piece",
            "4",
            "EDX",
            "4",
        ],
    )
    .assert_success();
    let c = client
        .decompile("entry".into(), false, false, false, false, None)
        .unwrap();
    assert!(
        c["code"].as_str().unwrap().contains("0x5566778811223344"),
        "{c}"
    );
    command(
        &program,
        &[
            "set-storage",
            "entry",
            "--return-register-piece",
            "0",
            "EDX",
            "4",
            "--return-register-piece",
            "4",
            "EAX",
            "4",
        ],
    )
    .assert_success();
    for reopen in [false, true] {
        if reopen {
            client.program_close().unwrap();
            client.open_program(&program).unwrap();
        }
        let c = client
            .decompile("entry".into(), false, false, false, false, None)
            .unwrap();
        assert!(
            c["code"].as_str().unwrap().contains("0x1122334455667788"),
            "{c}"
        );
    }
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}
