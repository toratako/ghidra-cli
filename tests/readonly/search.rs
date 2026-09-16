use super::{harness, TEST_PROGRAM};
use crate::common::{get_function_address, ghidra, test_project};
use serial_test::serial;

// Find Tests

#[test]
#[serial]
fn test_instruction_queries_on_x86_and_aarch64_without_functions() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, hex, last) in [
        ("x86:LE:64:default", "4889e590c3", "1004"),
        ("AARCH64:LE:64:v8A", "1f2003d51f2003d5c0035fd6", "1008"),
    ] {
        let name = format!("instruction-fixture-{}", uuid::Uuid::new_v4());
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateInstructionSearchFixture extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        var program = new ProgramDB(args[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("instruction fixture");
            try {
                byte[] bytes = new byte[32];
                for (int i = 0; i < args[2].length() / 2; i++) {
                    bytes[i] = (byte) Integer.parseInt(args[2].substring(i * 2, i * 2 + 2), 16);
                }
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
                int[] offsets = args[1].startsWith("x86") ? new int[]{0, 3, 4} : new int[]{0, 4, 8};
                for (int offset : offsets) {
                    if (!new DisassembleCommand(start.add(offset), null, false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture at " + offset);
                    }
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, &[name.clone(), language.to_owned(), hex.to_owned()], &[], false).unwrap();
        client.open_program(&name).unwrap();
        let checked = std::panic::catch_unwind(|| {
            let disasm = client.disasm_range("1000", last, Some(0)).unwrap();
            let rows = disasm["instructions"].as_array().unwrap();
            assert_eq!(rows.len(), 3, "{language}: {disasm}");
            let mnemonic = rows[1]["mnemonic"].as_str().unwrap();
            let search = client
                .find_instruction(mnemonic, None, None, false, None)
                .unwrap();
            assert!(
                !search["results"].as_array().unwrap().is_empty(),
                "{search}"
            );
            assert!(search["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r.get("function").is_none()));
            assert_eq!(client.disasm_range("1001", last, None).unwrap()["count"], 2);
            assert_eq!(
                client.disasm_range("1000", "1001", None).unwrap()["count"],
                1
            );
            assert_eq!(
                client.disasm_range("1010", "101f", None).unwrap()["count"],
                0
            );
            let tail = rows[2]["mnemonic"].as_str().unwrap();
            assert_eq!(
                client
                    .find_instruction(tail, Some(last), None, false, None)
                    .unwrap()["count"],
                1
            );
            assert_eq!(
                client
                    .find_instruction(tail, None, Some("1000"), false, None)
                    .unwrap()["count"],
                0
            );
            let error = client.disasm_range("1000", "register:0", None).unwrap_err();
            assert!(error.to_string().contains("same address space"), "{error}");
        });
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&name).unwrap();
        if let Err(error) = checked {
            std::panic::resume_unwind(error);
        }
    }
}

#[test]
#[serial]
fn test_find_instruction_text_ranges_and_query_controls() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let client = harness.client().unwrap();
    let baseline = client.disasm(&address, Some(6)).unwrap();
    let instructions = baseline["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 6);
    let start = instructions[0]["address"].as_str().unwrap();
    let end = instructions[5]["address"].as_str().unwrap();
    let mnemonic = instructions[0]["mnemonic"].as_str().unwrap();
    let single = client
        .find_instruction(mnemonic, Some(start), Some(start), false, Some(0))
        .unwrap();
    assert_eq!(single["count"], 1, "{single}");
    let text = single["results"][0]["disasm"].as_str().unwrap();
    assert_eq!(single["results"][0]["address"], start);
    assert!(single["results"][0]["function"].is_string());

    let changed_case: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    assert_ne!(text, changed_case);
    assert_eq!(
        client
            .find_instruction(&changed_case, Some(start), Some(start), false, None)
            .unwrap()["count"],
        1
    );
    assert_eq!(
        client
            .find_instruction(&changed_case, Some(start), Some(start), true, None)
            .unwrap()["count"],
        0
    );
    assert_eq!(
        client
            .find_instruction(text, Some(start), Some(start), true, None)
            .unwrap()["count"],
        1
    );

    let all = client
        .find_instruction(mnemonic, Some(start), Some(end), false, None)
        .unwrap();
    let rows = all["results"].as_array().unwrap();
    let output = ghidra(harness)
        .args([
            "find",
            "instruction",
            mnemonic,
            "--start",
            start,
            "--end",
            end,
            "--limit",
            "0",
        ])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    output.assert_success();
    assert_eq!(output.json::<serde_json::Value>(), all["results"]);
    let counted = ghidra(harness)
        .args([
            "find",
            "instruction",
            mnemonic,
            "--start",
            start,
            "--end",
            end,
            "--count",
        ])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    counted.assert_success();
    assert_eq!(counted.stdout.trim(), rows.len().to_string());
    for (range_start, range_end, expected) in [
        (Some(end), Some(start), "Start address"),
        (Some("not_an_address_or_symbol"), Some(end), "Invalid start"),
        (Some(start), Some("not_an_address_or_symbol"), "Invalid end"),
    ] {
        let error = client
            .find_instruction(mnemonic, range_start, range_end, false, None)
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert!(client
        .find_instruction("", None, None, false, None)
        .is_err());
}

#[test]
#[serial]
fn test_find_string() {
    require_ghidra!();
    let harness = harness();

    // Search for "Ghidra CLI" rather than "Hello": on macOS arm64 Ghidra does
    // not define the fixture's string literals, and a "Hello" search would
    // otherwise match the mangled `HELLO_WORLD` symbol name (case-insensitively)
    // and suppress the raw memory-scan fallback. "Ghidra CLI" only appears in
    // the actual greeting, so it resolves via defined strings (x86_64) or the
    // memory-scan fallback (arm64) on both arches.
    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("Ghidra CLI")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("Ghidra CLI");
}

#[test]
#[serial]
fn test_find_bytes() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("bytes")
        .arg("4883ec08")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_calls() {
    require_ghidra!();
    let harness = harness();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("find")
        .arg("calls")
        .arg(&address)
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_string_no_matches() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("nonexistent_string_xyz123")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(json) = result.try_json::<serde_json::Value>() {
        if let Some(arr) = json.as_array() {
            assert!(
                arr.is_empty(),
                "Should have no matches for nonexistent string"
            );
        }
    }
}

#[test]
#[serial]
fn test_find_bytes_rejects_incomplete_patterns() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for pattern in ["", " ", "0x", "909", "0x9", "gg", "+1"] {
        assert!(client.find_bytes(pattern).is_err(), "accepted {pattern:?}");
    }
    assert!(client.find_bytes("0x90 90").is_ok());
}

#[test]
#[serial]
fn test_search_raw_string_windows() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("search-window-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateSearchWindowFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("search fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                String[] strings = {"A".repeat(300) + "needle-one" + "B".repeat(300),
                    "boundary-needle", "C".repeat(256), "D".repeat(300)};
                for (int i = 0; i < strings.length; i++) {
                    byte[] bytes = strings[i].getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                    program.getMemory().createInitializedBlock("raw" + i,
                        space.getAddress(0x1000 + i * 0x1000),
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        for (pattern, length, truncated) in [
            ("needle-one".to_owned(), 256, true),
            ("boundary-needle".to_owned(), 15, false),
            ("C".repeat(256), 256, false),
            ("D".repeat(300), 300, false),
        ] {
            let found = client.find_string(&pattern).unwrap();
            assert_eq!(found["count"], 1, "{found}");
            let row = &found["results"][0];
            assert_eq!(row["source"], "memory-scan");
            assert!(row["value"].as_str().unwrap().contains(&pattern), "{row}");
            assert_eq!(row["length"], length);
            assert_eq!(row["truncated"], truncated);
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn test_call_search_and_callers_validate_thunks_import_pointers_and_call_sites() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("call-search-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateCallSearchFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("call search fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var fm = program.getFunctionManager();
                var refs = program.getReferenceManager();
                var source = SourceType.USER_DEFINED;
                program.getMemory().createInitializedBlock("code", space.getAddress(0x1000), 0x3000, (byte) 0, monitor, false);
                String[] names = {"search_caller", "search_helper", "search_leaf"};
                for (int i = 0; i < names.length; i++) {
                    var entry = space.getAddress(0x1000 + i * 0x100);
                    fm.createFunction(names[i], entry, new AddressSet(entry, entry.add(0xff)), source);
                }
                for (int address : new int[] {0x1000, 0x1008, 0x1010, 0x1100, 0x1060}) {
                    var site = space.getAddress(address);
                    program.getMemory().setBytes(site, new byte[] {(byte)0xff, (byte)0xd0});
                    if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble call at " + site);
                    }
                }
                refs.addMemoryReference(space.getAddress(0x1000), space.getAddress(0x1100), RefType.UNCONDITIONAL_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x1100), space.getAddress(0x1200), RefType.UNCONDITIONAL_CALL, source, 0);
                var external = program.getExternalManager().addExtFunction("KERNEL32.dll", "CreateProcessA", null, source);
                var thunkEntry = space.getAddress(0x2000);
                var thunk = fm.createFunction("CreateProcessA", thunkEntry, new AddressSet(thunkEntry, thunkEntry.add(5)), source);
                thunk.setThunkedFunction(external.getFunction());
                refs.addExternalReference(space.getAddress(0x1008), 0, external, source, RefType.UNCONDITIONAL_CALL);
                refs.addMemoryReference(space.getAddress(0x1010), thunkEntry, RefType.UNCONDITIONAL_CALL, source, 0);
                var slot = space.getAddress(0x3000);
                program.getListing().createData(slot, PointerDataType.dataType);
                refs.addExternalReference(slot, 0, external, source, RefType.DATA);
                var indirect = space.getAddress(0x1020);
                program.getMemory().setBytes(indirect, new byte[] {(byte)0xff, 0x15, (byte)0xda, 0x1f, 0, 0});
                new DisassembleCommand(indirect, new AddressSet(indirect, indirect.add(5)), false).applyTo(program, monitor);
                refs.addMemoryReference(indirect, slot, RefType.READ, source, 0);
                // A pointer to local code can use the flow-type INDIRECTION.
                var localSlot = space.getAddress(0x3010);
                program.getListing().createData(localSlot, PointerDataType.dataType);
                refs.addMemoryReference(localSlot, space.getAddress(0x1100), RefType.INDIRECTION, source, 0);
                var localIndirect = space.getAddress(0x1040);
                program.getMemory().setBytes(localIndirect, new byte[] {(byte)0xff, 0x15, (byte)0xca, 0x1f, 0, 0});
                if (!new DisassembleCommand(localIndirect, new AddressSet(localIndirect, localIndirect.add(5)), false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble local indirect call");
                }
                refs.addMemoryReference(localIndirect, localSlot, RefType.READ, source, 0);
                // Argument references do not call the API, including on an unrelated CALL.
                for (int address : new int[] {0x1030, 0x1050, 0x1070}) {
                    var site = space.getAddress(address);
                    program.getMemory().setByte(site, (byte)0x90);
                    new DisassembleCommand(site, new AddressSet(site, site), false).applyTo(program, monitor);
                }
                refs.addExternalReference(space.getAddress(0x1030), 0, external, source, RefType.DATA);
                refs.addExternalReference(space.getAddress(0x1050), 0, external, source, RefType.PARAM);
                refs.addExternalReference(space.getAddress(0x1060), 0, external, source, RefType.PARAM);
                // Even a mislabeled CALL reference from a NOP or undefined bytes is not a call.
                refs.addExternalReference(space.getAddress(0x1070), 0, external, source, RefType.UNCONDITIONAL_CALL);
                refs.addExternalReference(space.getAddress(0x1080), 0, external, source, RefType.UNCONDITIONAL_CALL);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let incoming = client.find_calls("search_helper").unwrap();
        assert_eq!(incoming["count"], 2, "{incoming}");
        assert_eq!(incoming["results"][0]["caller"], "search_caller");
        let local = client
            .graph_callers("search_helper", Some(1), None)
            .unwrap();
        let local_sites: Vec<_> = local["callers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| u64::from_str_radix(row["call_site"].as_str().unwrap(), 16).unwrap())
            .collect();
        assert_eq!(local_sites, [0x1000, 0x1040], "{local}");
        let outgoing = client.function_calls("search_helper").unwrap();
        assert_eq!(outgoing["count"], 1, "{outgoing}");
        assert_eq!(outgoing["results"][0]["callee"], "search_leaf");
        for target in ["CreateProcessA", "0x2000", "0x3000"] {
            let found = client.find_calls(target).unwrap();
            let sites: Vec<_> = found["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| u64::from_str_radix(row["call_site"].as_str().unwrap(), 16).unwrap())
                .collect();
            assert_eq!(sites, [0x1008, 0x1010, 0x1020], "{target}: {found}");
            let graph = client.graph_callers(target, Some(1), None).unwrap();
            let mut caller_sites: Vec<_> = graph["callers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    assert_eq!(row["name"], "search_caller");
                    assert_eq!(row["depth"], 0);
                    u64::from_str_radix(row["call_site"].as_str().unwrap(), 16).unwrap()
                })
                .collect();
            caller_sites.sort_unstable();
            assert_eq!(caller_sites, sites, "{target}: {graph}");
            for limit in [1, 2] {
                assert_eq!(
                    client.graph_callers(target, Some(0), Some(limit)).unwrap()["count"],
                    limit,
                    "caller traversal must retain its bridge-side cap"
                );
            }
        }
        assert_eq!(client.find_calls("search_caller").unwrap()["count"], 0);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
