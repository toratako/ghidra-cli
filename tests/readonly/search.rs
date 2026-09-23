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
        ("x86:LE:64:default", "4889e590c3", "0x1004"),
        ("AARCH64:LE:64:v8A", "1f2003d51f2003d5c0035fd6", "0x1008"),
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
            let disasm = client.disasm_range("0x1000", last, Some(0)).unwrap();
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
            assert_eq!(
                client.disasm_range("0x1001", last, None).unwrap()["count"],
                2
            );
            assert_eq!(
                client.disasm_range("0x1000", "0x1001", None).unwrap()["count"],
                1
            );
            assert_eq!(
                client.disasm_range("0x1010", "0x101f", None).unwrap()["count"],
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
                    .find_instruction(tail, None, Some("0x1000"), false, None)
                    .unwrap()["count"],
                0
            );
            let error = client
                .disasm_range("0x1000", "register:0x0", None)
                .unwrap_err();
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
    assert_eq!(output.data::<serde_json::Value>(), all["results"]);
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
    assert_eq!(counted.data::<usize>(), rows.len());
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
fn test_find_text_in_analyzed_binary() {
    require_ghidra!();
    let harness = harness();

    // Text search finds the greeting even when the platform's analyzers leave
    // the literal undefined.
    let result = ghidra(harness)
        .arg("find")
        .arg("text")
        .arg("Ghidra CLI")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    let rows: Vec<serde_json::Value> = result.data();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row["byte_length"] == 10));
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

    let rows: Vec<serde_json::Value> = result.data();
    assert!(
        rows.is_empty(),
        "Should have no matches for nonexistent string"
    );
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
fn test_string_refs_match_string_values_independent_of_locale() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("string-refs-{}", uuid::Uuid::new_v4());
    let values = [
        "C:\\Windows\\Temp",
        "line1\nline2",
        "say \"hello\"",
        "INDIGO",
    ];
    let mut fixture_args = vec![name.clone()];
    fixture_args.extend(values.iter().map(|value| value.to_string()));
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateStringRefsFixture extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(args[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("string refs fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var from = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("references", from, 0x10, (byte) 0, monitor, false);
                for (int i = 1; i < args.length; i++) {
                    var address = space.getAddress(0x2000 + i * 0x100);
                    byte[] bytes = (args[i] + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    program.getMemory().createInitializedBlock("string" + i, address,
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                    program.getListing().createData(address, StringDataType.dataType, bytes.length);
                    program.getReferenceManager().addMemoryReference(from.add(i), address,
                        RefType.DATA, SourceType.USER_DEFINED, 0);
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, &fixture_args, &[], false).unwrap();
    client.open_program(&name).unwrap();
    const LOCALE_SCRIPT: &str = r#"
import ghidra.app.script.GhidraScript;
import java.util.Locale;
public class StringRefsTestLocale extends GhidraScript {
    public void run() {
        writer.println(Locale.getDefault().toLanguageTag());
        Locale.setDefault(Locale.forLanguageTag(getScriptArgs()[0]));
    }
}
"#;
    let previous = client
        .script_run_source(LOCALE_SCRIPT, &["tr-TR".into()], &[], false)
        .unwrap();
    let previous = previous["stdout"].as_str().unwrap().trim().to_string();
    let checked = std::panic::catch_unwind(|| {
        for value in values {
            let pattern = value.to_lowercase();
            let found = client.find_string(&pattern).unwrap();
            let references = client.string_refs(pattern.clone()).unwrap();
            assert_eq!(found["count"], 1, "{pattern:?}: {found}");
            assert_eq!(references["count"], 1, "{pattern:?}: {references}");
            assert_eq!(references["results"][0]["string_value"], value);
            assert_eq!(
                references["results"][0]["string_address"],
                found["results"][0]["address"]
            );
            let output = ghidra(harness)
                .args(["string", "refs", &pattern, "--limit", "0", "--json"])
                .with_project(test_project(), &name)
                .run();
            output.assert_success();
            assert_eq!(output.data::<serde_json::Value>(), references["results"]);
        }
        // Formatting escapes must not themselves create matches in a string value.
        assert_eq!(
            client.string_refs("line1\\nline2".into()).unwrap()["count"],
            0
        );
        assert_eq!(client.string_refs("absent".into()).unwrap()["count"], 0);
    });
    client
        .script_run_source(LOCALE_SCRIPT, &[previous], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn test_find_text_encodings_and_defined_string_boundary() {
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
                String[] hex = {
                    "50617373776f726400", // undefined Password
                    "50617373776f726400", // defined Password
                    "5261774f6e6c7900",   // undefined RawOnly
                    "e697a5e69cac",       // 日本, UTF-8
                    "e5652c67",           // 日本, UTF-16LE
                    "65e5672c",           // 日本, UTF-16BE
                    "93fa967b",           // 日本, Shift_JIS
                    "6161616161",         // overlapping aa matches
                    "58".repeat(300)      // no implicit extraction window
                };
                for (int i = 0; i < hex.length; i++) {
                    byte[] bytes = java.util.HexFormat.of().parseHex(hex[i]);
                    var address = space.getAddress(0x1000 + i * 0x1000);
                    program.getMemory().createInitializedBlock("raw" + i, address,
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                    if (i == 1) program.getListing().createData(address,
                        ghidra.program.model.data.StringDataType.dataType, bytes.length);
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
        let defined = client.find_string("password").unwrap();
        assert_eq!(defined["count"], 1, "{defined}");
        assert_eq!(defined["results"][0]["value"], "Password");
        assert_eq!(client.find_string("RawOnly").unwrap()["count"], 0);
        assert_eq!(client.find_string("").unwrap()["count"], 1);
        assert_eq!(client.find_text("Password", "utf-8").unwrap()["count"], 2);
        assert_eq!(client.find_text("password", "utf-8").unwrap()["count"], 0);
        assert_eq!(client.find_text("RawOnly", "ascii").unwrap()["count"], 1);
        assert_eq!(client.find_text("aa", "utf-8").unwrap()["count"], 4);
        let long = client.find_text(&"X".repeat(300), "utf-8").unwrap();
        assert_eq!(long["count"], 1);
        assert_eq!(long["results"][0]["byte_length"], 300);
        for (encoding, address, length, canonical) in [
            ("utf-8", 0x4000, 6, "UTF-8"),
            ("utf-16le", 0x5000, 4, "UTF-16LE"),
            ("utf-16be", 0x6000, 4, "UTF-16BE"),
            ("shift_jis", 0x7000, 4, "Shift_JIS"),
        ] {
            let found = client.find_text("日本", encoding).unwrap();
            assert_eq!(found["count"], 1, "{encoding}: {found}");
            let row = &found["results"][0];
            assert_eq!(
                u64::from_str_radix(
                    row["address"].as_str().unwrap().strip_prefix("0x").unwrap(),
                    16
                )
                .unwrap(),
                address
            );
            assert_eq!(row["byte_length"], length);
            assert_eq!(row["encoding"], canonical);
        }
        let default = client
            .send_command("find_text", Some(serde_json::json!({"text": "日本"})))
            .unwrap();
        assert_eq!(default, client.find_text("日本", "utf-8").unwrap());
        for (text, encoding, message) in [
            ("日本", "ascii", "cannot be encoded"),
            ("needle", "no-such-encoding", "Unsupported encoding"),
            ("needle", "", "Unsupported encoding"),
            ("", "utf-8", "Non-empty text"),
        ] {
            let error = client.find_text(text, encoding).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
        let output = ghidra(harness())
            .args(["find", "text", "日本", "--encoding", "utf-16le", "--json"])
            .with_project(test_project(), &name)
            .run();
        output.assert_success();
        let rows: serde_json::Value = output.data();
        assert_eq!(
            rows,
            client.find_text("日本", "utf-16le").unwrap()["results"]
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn exact_search_continues_after_address_space_maximum() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("search-spaces-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateSearchSpacesFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("search spaces fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("end", space.getMaxAddress(),
                    1, (byte) 'X', monitor, false);
                program.getMemory().createInitializedBlock("later", space.getAddress(0x1000),
                    1, (byte) 'X', monitor, true);
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
        for result in [
            client.find_bytes("58").unwrap(),
            client.find_text("X", "ascii").unwrap(),
        ] {
            assert_eq!(result["count"], 2, "{result}");
            assert_eq!(result["results"][0]["address"], "0xffffffff");
            assert_eq!(result["results"][1]["address"], "later:0x00001000");
        }
        for command in ["find_bytes", "find_text"] {
            let result = client
                .send_command(
                    command,
                    Some(serde_json::json!({
                        "hex": "58", "text": "X", "limit": 1
                    })),
                )
                .unwrap();
            assert_eq!(result["count"], 1);
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
