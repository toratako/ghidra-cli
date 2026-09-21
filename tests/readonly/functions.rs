use super::{harness, TEST_PROGRAM};
use crate::common::{
    get_function_address, get_function_addresses, ghidra,
    helpers::matches_function_name,
    schemas::{DisasmResult, Function, Validate},
    test_project,
};
use serial_test::serial;

/// Known exported function names from sample_binary
const KNOWN_FUNCTIONS: &[&str] = &[
    "add_numbers",
    "multiply",
    "factorial",
    "fibonacci",
    "process_string",
    "xor_encrypt",
    "simple_hash",
    "init_struct",
    "main",
];

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

// Function List Tests

#[test]
#[serial]
fn test_function_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(!functions.is_empty(), "Function list should not be empty");

    for func in &functions {
        func.assert_valid();
    }

    let has_main = functions.iter().any(|f| f.name == "main");
    assert!(has_main, "Should contain main function");
}

#[test]
#[serial]
fn test_function_list_contains_expected_functions() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

    // main must always be present
    assert!(
        names.iter().any(|n| matches_function_name(n, "main")),
        "Should have main function. Found: {:?}",
        &names[..names.len().min(20)]
    );

    // Binary should have many functions (stdlib + user code)
    assert!(
        functions.len() >= 5,
        "Should have at least 5 functions, found {}",
        functions.len()
    );

    for expected in KNOWN_FUNCTIONS {
        assert!(
            names
                .iter()
                .any(|name| matches_function_name(name, expected)),
            "Missing fixture function: {expected}"
        );
    }
}

#[test]
#[serial]
fn test_function_list_limit() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("3")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        functions.len() <= 3,
        "Limit 3 should return at most 3 functions, got {}",
        functions.len()
    );
}

#[test]
#[serial]
fn test_function_list_filter() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("name~main")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter 'name~main' should match at least one function"
    );

    // The filter must actually filter: EVERY returned row matches, not just one
    // (a bare-word filter used to silently dump the whole unfiltered dataset).
    assert!(
        functions
            .iter()
            .all(|f| f.name.to_lowercase().contains("main")),
        "All filtered results should contain 'main'. Got: {:?}",
        functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
#[serial]
fn test_function_list_address_range_filter() {
    require_ghidra!();
    let harness = harness();

    // Regression: `address` comes back from the bridge as a hex string
    // (e.g. "0x00401000"), never a JSON number. A numeric range filter
    // against it used to fall through to the evaluator's catch-all
    // `Ok(false)` for every row -- exit 0, empty result, no error -- instead
    // of comparing addresses. Derive real bounds from the binary so this
    // isn't tied to one platform's address layout.
    let mut addrs: Vec<u64> = get_function_addresses(harness, test_project(), TEST_PROGRAM, 50)
        .iter()
        .map(|a| {
            let hex = a.strip_prefix("0x").expect("prefixed address");
            u64::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("bad address {}: {}", a, e))
        })
        .collect();
    addrs.sort_unstable();
    let lo = addrs[0];
    let hi = addrs[addrs.len() / 2];

    let filter = format!("address >= 0x{:x} AND address <= 0x{:x}", lo, hi);
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg(&filter)
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter '{}' should match at least one function (addresses {}..={})",
        filter,
        lo,
        hi
    );
    for f in &functions {
        let hex = f.address.strip_prefix("0x").expect("prefixed address");
        let addr = u64::from_str_radix(hex, 16)
            .unwrap_or_else(|e| panic!("bad address {}: {}", f.address, e));
        assert!(
            addr >= lo && addr <= hi,
            "Function {} at {} is outside the filtered range {}..={}",
            f.name,
            f.address,
            lo,
            hi
        );
    }
}

#[test]
#[serial]
fn test_function_list_bare_word_filter_rejected() {
    require_ghidra!();
    let harness = harness();

    // A bare word is not a valid filter expression. It must fail with a
    // nonzero exit instead of dumping the entire unfiltered dataset.
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("main")
        .run();

    result.assert_failure();
}

// Decompile Tests

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
        let output: Value = result.json();
        let names: Vec<_> = output[0]["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["p0", "p1", "p2", "p3", "p4"], "{output}");
        assert!(output[0]["signature"]
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
                "function_edit_var",
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
            .decompile("ordered_params".into(), true, true, false)
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
                if *command == "function_edit_var" {
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
                .decompile("ordered_params".into(), true, true, false)
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

// Disassembly Tests

#[test]
#[serial]
fn test_function_disasm_respects_whole_body_and_query_options() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("function-disasm-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateFunctionDisasmFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("function disassembly fixture");
            try {
                byte[] bytes = new byte[0x100];
                java.util.Arrays.fill(bytes, (byte) 0x90);
                bytes[0] = 0x48; bytes[1] = (byte) 0x89; bytes[2] = (byte) 0xe5;
                for (int offset : new int[]{3, 6, 0x34, 0x51, 0x66, 0x81, 0xa1, 0xc1, 0xc5}) {
                    bytes[offset] = (byte) 0xc3;
                }
                // Jump across another function to a disjoint tail.
                bytes[0x60] = (byte) 0xe9; bytes[0x61] = 0x1b;
                bytes[0x62] = 0; bytes[0x63] = 0; bytes[0x64] = 0;
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
                var offsets = new java.util.ArrayList<Integer>();
                for (int offset : new int[]{0, 3, 4, 5, 6, 0x50, 0x51, 0x60, 0x65, 0x66, 0x80, 0x81, 0xa0, 0xc0, 0xc4}) {
                    offsets.add(offset);
                }
                for (int offset = 0x20; offset <= 0x34; offset++) offsets.add(offset);
                for (int offset : offsets) {
                    if (!new DisassembleCommand(start.add(offset), null, false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture at " + offset);
                    }
                }
                var fm = program.getFunctionManager();
                fm.createFunction("short_case", start, new AddressSet(start, start.add(3)), SourceType.USER_DEFINED);
                fm.createFunction("neighbor_case", start.add(4), new AddressSet(start.add(4), start.add(6)), SourceType.USER_DEFINED);
                fm.createFunction("long_case", start.add(0x20), new AddressSet(start.add(0x20), start.add(0x34)), SourceType.USER_DEFINED);
                var splitBody = new AddressSet(start.add(0x50), start.add(0x51));
                splitBody.add(start.add(0x60), start.add(0x64));
                splitBody.add(start.add(0x80), start.add(0x81));
                fm.createFunction("split_case", start.add(0x60), splitBody, SourceType.USER_DEFINED);
                fm.createFunction("gap_case", start.add(0x65), new AddressSet(start.add(0x65), start.add(0x66)), SourceType.USER_DEFINED);
                fm.createFunction("empty_case", start.add(0xb0), new AddressSet(start.add(0xb0)), SourceType.USER_DEFINED);
                fm.createFunction("undefined_gap_case", start.add(0xc0), new AddressSet(start.add(0xc0), start.add(0xc5)), SourceType.USER_DEFINED);
                if (program.getListing().getInstructionContaining(start.add(0xc2)) != null) {
                    throw new IllegalStateException("Fixture gap must remain undefined");
                }
                program.getSymbolTable().createLabel(start, "shared_target", SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(start.add(0x20), "shared_target", SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        use serde_json::{json, Value};
        let addresses = |rows: &Value| -> Vec<u64> {
            rows.as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    u64::from_str_radix(
                        row["address"].as_str().unwrap().strip_prefix("0x").unwrap(),
                        16,
                    )
                    .unwrap()
                })
                .collect()
        };
        for (targets, expected) in [
            (vec!["short_case", "0x1000", "0x1001"], vec![0x1000, 0x1003]),
            (vec!["long_case", "0x1025"], (0x1020..=0x1034).collect()),
            (
                vec!["split_case", "0x1051", "0x1062", "0x1081"],
                vec![0x1050, 0x1051, 0x1060, 0x1080, 0x1081],
            ),
            (vec!["empty_case"], vec![]),
        ] {
            for target in targets {
                let result = client.function_disasm(target, None).unwrap();
                assert_eq!(
                    addresses(&result["instructions"]),
                    expected,
                    "{target}: {result}"
                );
                assert_eq!(result["count"], expected.len());
                let output = ghidra(harness)
                    .args(["function", "disassemble", target, "--limit", "0"])
                    .with_project(test_project(), &name)
                    .run();
                output.assert_success();
                assert_eq!(output.json::<Value>(), result["instructions"], "{target}");
            }
        }
        let all = client.function_disasm("long_case", Some(0)).unwrap()["instructions"].clone();
        assert_eq!(
            client.function_disasm("long_case", Some(12)).unwrap()["instructions"],
            json!(&all.as_array().unwrap()[..12])
        );
        assert_eq!(
            client
                .function_disasm("long_case", Some(i32::MAX as usize + 1))
                .unwrap()["instructions"],
            all
        );
        for (flags, expected) in [
            (vec!["--limit", "12"], json!(&all.as_array().unwrap()[..12])),
            (vec!["--count"], json!(21)),
            (
                vec!["--filter", "mnemonic=RET", "--limit", "1"],
                json!([all[20]]),
            ),
            (
                vec!["--offset", "12", "--limit", "2"],
                json!([all[12], all[13]]),
            ),
            (vec!["--offset", "12", "--limit", "2", "--count"], json!(2)),
            (
                vec![
                    "--sort=-address",
                    "--offset",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "address",
                ],
                json!([{"address": all[19]["address"]}]),
            ),
        ] {
            let result = ghidra(harness)
                .args(["function", "disassemble", "long_case"])
                .args(flags)
                .with_project(test_project(), &name)
                .run();
            result.assert_success();
            assert_eq!(result.json::<Value>(), expected);
        }
        let asm = ghidra(harness)
            .args([
                "function",
                "disassemble",
                "short_case",
                "--format",
                "asm",
                "--limit",
                "0",
            ])
            .with_project(test_project(), &name)
            .run();
        asm.assert_success();
        assert_eq!(asm.stdout.lines().count(), 2);
        assert!(
            asm.stdout.contains("MOV") && asm.stdout.contains("RET"),
            "{}",
            asm.stdout
        );
        for target in ["no_such_function", "0x10a0", "0x1010", "FUN_00001000"] {
            let result = ghidra(harness)
                .args(["function", "disassemble", target])
                .with_project(test_project(), &name)
                .run();
            result
                .assert_failure()
                .assert_stderr_contains("Cannot resolve function target");
        }
        let ambiguous = client.function_disasm("shared_target", None).unwrap_err();
        assert!(
            ambiguous.to_string().contains("Ambiguous function target"),
            "{ambiguous}"
        );
        for limit in [json!(-1), json!(1.5), json!(u64::MAX)] {
            let error = client
                .send_command(
                    "function_disasm",
                    Some(json!({"target": "long_case", "limit": limit})),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("limit must be an integer"),
                "{error}"
            );
        }
        check_disasm_limits(harness, &client, &name);
        // A function body can include undefined bytes between instructions.
        // An address query there must not silently rewind to the function entry.
        assert_eq!(
            addresses(&client.function_disasm("0x10c2", None).unwrap()["instructions"]),
            vec![0x10c0, 0x10c1, 0x10c4, 0x10c5]
        );
        let error = client.disasm("0x10c2", Some(1)).unwrap_err();
        assert!(
            error.to_string().contains("No instruction at address"),
            "{error}"
        );
        ghidra(harness)
            .args(["disassemble", "0x10c2", "--limit", "1"])
            .with_project(test_project(), &name)
            .run()
            .assert_failure()
            .assert_stderr_contains("No instruction at address");
        client.program_close().unwrap();
        assert!(client
            .function_disasm("short_case", None)
            .unwrap_err()
            .to_string()
            .contains("No program loaded"));
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

fn check_disasm_limits(
    harness: &crate::common::DaemonTestHarness,
    client: &ghidra_cli::ipc::client::BridgeClient,
    program: &str,
) {
    use serde_json::{json, Value};
    let all = client.disasm("long_case", Some(0)).unwrap();
    let rows = all["instructions"].as_array().unwrap();
    assert!(
        rows.len() > 21,
        "disassemble must continue beyond the function body"
    );
    for limit in [None, Some(i32::MAX as usize + 1)] {
        assert_eq!(client.disasm("long_case", limit).unwrap(), all);
    }
    assert_eq!(
        client.disasm("long_case", Some(12)).unwrap()["instructions"],
        json!(&rows[..12])
    );
    // Preserve existing resolution of an address inside an instruction.
    assert_eq!(
        client.disasm("0x1001", Some(1)).unwrap(),
        client.disasm("short_case", Some(1)).unwrap()
    );

    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    test_config.default_limit = Some(12);
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    let cli = |flags: &[&str]| -> Value {
        let result = ghidra(harness)
            .args(["--json", "disassemble", "long_case"])
            .args(flags.iter().copied())
            .with_project(test_project(), program)
            .env("GHIDRA_CLI_CONFIG", config.to_string_lossy())
            .run();
        result.assert_success();
        result.json()
    };
    assert_eq!(cli(&[]), json!(&rows[..12]));
    assert_eq!(cli(&["--limit", "0"]), json!(rows));
    assert_eq!(cli(&["--limit", "13"]), json!(&rows[..13]));
    assert_eq!(
        cli(&["--offset", "12", "--limit", "2"]),
        json!(&rows[12..14])
    );
    assert_eq!(cli(&["--count"]), json!(rows.len()));
    assert_eq!(
        cli(&["--offset", "12", "--limit", "2", "--count"]),
        json!(2)
    );
    let returns: Vec<_> = rows.iter().filter(|row| row["mnemonic"] == "RET").collect();
    assert!(returns.len() >= 3);
    assert_eq!(
        cli(&["--filter", "mnemonic=RET", "--limit", "1"]),
        json!([returns[0]])
    );
    let selected: Vec<_> = returns
        .iter()
        .rev()
        .skip(1)
        .take(2)
        .map(|row| json!({"address": row["address"]}))
        .collect();
    assert_eq!(
        cli(&[
            "--filter",
            "mnemonic=RET",
            "--sort=-address",
            "--offset",
            "1",
            "--limit",
            "2",
            "--fields",
            "address",
        ]),
        json!(selected)
    );
    for limit in [json!(-1), json!(1.5), json!(u64::MAX)] {
        let error = client
            .send_command(
                "disasm",
                Some(json!({"address": "long_case", "limit": limit})),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("limit must be an integer"),
            "{error}"
        );
    }
}

#[test]
#[serial]
fn test_disasm_end_includes_only_instruction_starts_in_range() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let client = harness.client().unwrap();
    let baseline = client.disasm(&address, Some(6)).unwrap();
    let instructions = baseline["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 6);
    let start = instructions[0]["address"].as_str().unwrap();
    let end = instructions[5]["address"].as_str().unwrap();
    let ranged = client.disasm_range(start, end, Some(0)).unwrap();
    assert_eq!(ranged["instructions"], baseline["instructions"]);
    assert_eq!(
        client.disasm_range(start, start, None).unwrap()["instructions"],
        serde_json::json!([instructions[0]])
    );
    assert_eq!(
        client.disasm_range(start, end, Some(2)).unwrap()["instructions"],
        serde_json::json!(&instructions[..2])
    );

    let result = ghidra(harness)
        .args(["disassemble", start, "--end", end, "--limit", "0"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
    assert_eq!(result.json::<serde_json::Value>(), baseline["instructions"]);
    let result = ghidra(harness)
        .args([
            "disassemble",
            start,
            "--end",
            end,
            "--sort=-address",
            "--offset",
            "1",
            "--limit",
            "1",
            "--fields",
            "address",
        ])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
    assert_eq!(
        result.json::<serde_json::Value>(),
        serde_json::json!([{"address": instructions[4]["address"]}])
    );

    // An interior lower boundary must not rewind to the containing instruction.
    if instructions[0]["bytes"].as_str().unwrap().len() > 2 {
        let interior = format!(
            "0x{:x}",
            u64::from_str_radix(start.strip_prefix("0x").unwrap(), 16).unwrap() + 1
        );
        let ranged = client.disasm_range(&interior, end, None).unwrap();
        assert_eq!(
            ranged["instructions"],
            serde_json::json!(&instructions[1..])
        );
    }
    for (range_start, range_end, expected) in [
        (end, start, "Start address"),
        (start, "not_an_address_or_symbol", "Invalid end"),
        ("not_an_address_or_symbol", end, "Invalid start"),
    ] {
        let error = client
            .disasm_range(range_start, range_end, None)
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
#[serial]
fn test_explicit_c_and_asm_output_match_ghidra_results() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let client = harness.client().unwrap();
    let decompiled = client
        .decompile(address.clone(), false, false, false)
        .unwrap();
    let result = ghidra(harness)
        .args(["decompile", &address, "--format", "c"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
    assert_eq!(
        result.stdout.trim_end(),
        decompiled["code"].as_str().unwrap().trim_end()
    );
    let instructions = client.disasm(&address, Some(3)).unwrap();
    let result = ghidra(harness)
        .args(["disassemble", &address, "--limit", "3", "--format", "asm"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
    assert_eq!(result.stdout.lines().count(), 3);
    for (line, instruction) in result
        .stdout
        .lines()
        .zip(instructions["instructions"].as_array().unwrap())
    {
        assert!(
            line.starts_with(instruction["address"].as_str().unwrap()),
            "{line}"
        );
        assert!(
            line.contains(instruction["mnemonic"].as_str().unwrap()),
            "{line}"
        );
    }
}

#[test]
#[serial]
fn test_disasm_at_main() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disassemble")
        .arg(&main_addr)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let disasm: DisasmResult = result.json();
    assert!(
        !disasm.results.is_empty(),
        "Should have at least one instruction"
    );
    for instr in &disasm.results {
        instr.assert_valid();
    }
}

#[test]
#[serial]
fn test_disasm_with_instruction_limit() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let limit = 5;

    let result = ghidra(harness)
        .arg("disassemble")
        .arg(&main_addr)
        .arg("--limit")
        .arg(limit.to_string())
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let disasm: DisasmResult = result.json();
    assert!(
        disasm.results.len() <= limit,
        "Should return at most {} instructions, got {}",
        limit,
        disasm.results.len()
    );
    for instr in &disasm.results {
        instr.assert_valid();
    }
}

#[test]
#[serial]
fn test_disasm_small_limit() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disassemble")
        .arg(&main_addr)
        .arg("--limit")
        .arg("1")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let disasm: DisasmResult = result.json();
    assert!(
        disasm.results.len() <= 1,
        "Should return at most 1 instruction, got {}",
        disasm.results.len()
    );
}

#[test]
#[serial]
fn test_disasm_instruction_fields() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disassemble")
        .arg(&main_addr)
        .arg("--limit")
        .arg("10")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let disasm: DisasmResult = result.json();
    assert!(!disasm.results.is_empty(), "Should have instructions");

    let first = &disasm.results[0];
    assert!(!first.mnemonic.is_empty(), "Mnemonic should not be empty");
    assert!(!first.address.is_empty(), "Address should not be empty");

    let addr_hex = first
        .address
        .strip_prefix("0x")
        .expect("instruction address must have a 0x prefix");
    assert!(
        !addr_hex.is_empty() && addr_hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "Address should be hex format, got: {}",
        first.address
    );

    let common_first_instr = [
        "PUSH", "SUB", "MOV", "ENDBR", "LEA", "XOR", "JMP", // x86
        "STP", "STR", "BL", "NOP", "ADRP", "ADD", "RET", // ARM64
    ];
    let mnemonic_upper = first.mnemonic.to_uppercase();

    if !common_first_instr
        .iter()
        .any(|&m| mnemonic_upper.starts_with(m))
    {
        eprintln!(
            "Note: First instruction is '{}' - unusual but not necessarily wrong",
            first.mnemonic
        );
    }
}

#[test]
#[serial]
fn test_disasm_invalid_address() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("disassemble")
        .arg("0xFFFFFFFFFFFFFFFF")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        if let Some(_disasm) = result.try_json::<DisasmResult>() {
            // Empty results are acceptable for unmapped address
        }
    } else {
        assert!(
            !result.stderr.is_empty() || !result.stdout.is_empty(),
            "Should provide some output explaining the error"
        );
    }
}

#[test]
#[serial]
fn test_disasm_missing_program() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness).arg("disassemble").arg("0x101000").run();

    result.assert_failure();
}
