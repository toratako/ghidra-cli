use super::{harness, TEST_PROGRAM};
use crate::common::{get_function_address, ghidra, test_project};
use serial_test::serial;

fn to_fun_style_target(address: &str) -> String {
    let base = address
        .rsplit(':')
        .next()
        .unwrap_or(address)
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let hex: String = base.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    format!("FUN_{}", hex)
}

#[test]
#[serial]
fn test_decompile_by_name() {
    require_ghidra!();
    let harness = harness();

    let function =
        crate::common::helpers::get_fixture_function(&harness.client().unwrap(), "add_numbers");
    let result = ghidra(harness)
        .arg("decompile")
        .arg(&function.name)
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();

    assert!(
        result.stdout.contains("return")
            || result.stdout.contains("param")
            || result.stdout.contains("int")
            || result.stdout.contains("long")
            || result.stdout.contains("void"),
        "Decompiled output should contain C-like code keywords.\nGot: {}",
        result.stdout
    );
}

#[test]
#[serial]
fn test_decompile_by_address() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&main_addr)
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Decompile should produce output"
    );
}

#[test]
#[serial]
fn test_decompile_parameter_order_and_native_timeout_bounds() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("decompile-parameters-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateOrderedParametersFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("ordered parameter fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", address, 1, (byte) 0xc3, monitor, false);
                if (!new DisassembleCommand(address, null, false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Fixture disassembly failed");
                }
                var function = program.getFunctionManager().createFunction("ordered_params", address,
                    new AddressSet(address, address), SourceType.USER_DEFINED);
                function.setCallingConvention("__cdecl");
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                // Symbol allocation order deliberately differs from the final parameter order.
                for (String name : new String[]{"p1", "p2", "p3", "p4", "p0"}) {
                    function.addParameter(new ParameterImpl(name, IntegerDataType.dataType, program),
                        SourceType.USER_DEFINED);
                }
                function.moveParameter(4, 0);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&program), &[], false).unwrap();
    client.open_program(&program).unwrap();
    let checked = std::panic::catch_unwind(|| {
        use serde_json::{json, Value};
        let result = ghidra(harness)
            .args(["decompile", "ordered_params", "--with-params", "--json"])
            .with_project(test_project(), &program)
            .run();
        result.assert_success();
        let output: Value = result.data();
        let names: Vec<_> = output["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["p0", "p1", "p2", "p3", "p4"], "{output}");
        assert!(output["signature"]
            .as_str()
            .unwrap()
            .contains("int p0, int p1, int p2, int p3, int p4"));

        let requests = [
            ("decompile", json!({"address": "ordered_params"})),
            (
                "pcode_function",
                json!({"function": "ordered_params", "high": true}),
            ),
            (
                "function_var_set",
                json!({"target": "ordered_params", "var_name": "p0", "new_name": "p0"}),
            ),
        ];
        for (command, base_args) in &requests {
            for timeout in [
                None,
                Some(Value::Null),
                Some(json!(0)),
                Some(json!(47)),
                Some(json!(2147483)),
            ] {
                let mut args = base_args.clone();
                if let Some(timeout) = timeout {
                    args["timeout_secs"] = timeout;
                }
                client
                    .send_command(command, Some(args.clone()))
                    .unwrap_or_else(|error| panic!("{command} {args}: {error}"));
            }
        }
        let before = client
            .decompile("ordered_params".into(), true, true, false, false)
            .unwrap();
        for (command, base_args) in &requests {
            for timeout in [
                json!(-1),
                json!(1.5),
                json!(2147484),
                json!(i32::MAX),
                json!(2147483648u64),
                json!(u64::MAX),
                json!("47"),
                json!(true),
            ] {
                let mut args = base_args.clone();
                args["timeout_secs"] = timeout;
                if *command == "function_var_set" {
                    args["new_name"] = json!("must_not_be_saved");
                }
                let error = client
                    .send_command(command, Some(args.clone()))
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("timeout_secs must be an integer from 0 to 2147483"),
                    "{command} {args}: {error}"
                );
            }
        }
        assert_eq!(
            client
                .decompile("ordered_params".into(), true, true, false, false)
                .unwrap(),
            before
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[serial]
fn test_decompile_rejects_synthetic_fun_style_target() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let fun_target = to_fun_style_target(&main_addr);

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&fun_target)
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_failure();
}

#[test]
#[serial]
fn test_decompile_nonexistent_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("decompile")
        .arg("this_function_definitely_does_not_exist_xyz123")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        assert!(
            result.stdout.to_lowercase().contains("not found")
                || result.stdout.to_lowercase().contains("error")
                || result.stdout.trim().is_empty(),
            "Should indicate function not found"
        );
    }
}
