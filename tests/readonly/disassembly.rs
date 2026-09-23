use super::{harness, TEST_PROGRAM};
use crate::common::schemas::{DisasmResult, Validate};
use crate::common::{get_function_address, ghidra, test_project};
use serial_test::serial;

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
                assert_eq!(output.data::<Value>(), result["instructions"], "{target}");
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
                vec!["--skip", "12", "--limit", "2"],
                json!([all[12], all[13]]),
            ),
            (vec!["--skip", "12", "--limit", "2", "--count"], json!(2)),
            (
                vec![
                    "--sort=-address",
                    "--skip",
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
            assert_eq!(result.data::<Value>(), expected);
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
        result.data()
    };
    assert_eq!(cli(&[]), json!(&rows[..12]));
    assert_eq!(cli(&["--limit", "0"]), json!(rows));
    assert_eq!(cli(&["--limit", "13"]), json!(&rows[..13]));
    assert_eq!(cli(&["--skip", "12", "--limit", "2"]), json!(&rows[12..14]));
    assert_eq!(cli(&["--count"]), json!(rows.len()));
    assert_eq!(cli(&["--skip", "12", "--limit", "2", "--count"]), json!(2));
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
            "--skip",
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
    assert_eq!(result.data::<serde_json::Value>(), baseline["instructions"]);
    let result = ghidra(harness)
        .args([
            "disassemble",
            start,
            "--end",
            end,
            "--sort=-address",
            "--skip",
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
        result.data::<serde_json::Value>(),
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
        .decompile(address.clone(), false, false, false, false)
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

    let disasm: DisasmResult = result.data();
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

    let disasm: DisasmResult = result.data();
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

    let disasm: DisasmResult = result.data();
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

    let disasm: DisasmResult = result.data();
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
        let disasm: DisasmResult = result.data();
        assert!(disasm.results.is_empty());
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
