use super::{harness, TEST_PROGRAM};
use crate::common::{get_function_address, ghidra, test_project};
use serial_test::serial;

// Find Tests

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
fn test_find_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("main")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
}

#[test]
#[serial]
fn test_find_function_glob() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("m*")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
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
fn test_find_crypto() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("crypto")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
}

#[test]
#[serial]
fn test_find_interesting() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("interesting")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
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
fn test_search_literal_glob_and_raw_string_windows() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("search-window-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
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
                String[] names = {"literal[part]+(x)$", "literalpprtx", "quote\"slash\\name"};
                for (int i = 0; i < names.length; i++) {
                    var entry = space.getAddress(0x1000 + i * 0x10);
                    program.getFunctionManager().createFunction(names[i], entry,
                        new AddressSet(entry, entry), SourceType.USER_DEFINED);
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
        for pattern in ["literal[part]+(x)$*", "*literal[part]+(x)$"] {
            let found = client.find_function(pattern).unwrap();
            assert_eq!(found["count"], 1, "{found}");
            assert_eq!(found["results"][0]["name"], "literal[part]+(x)$");
        }
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
        let dot = client.graph_export("dot").unwrap();
        assert!(
            dot["output"]
                .as_str()
                .unwrap()
                .contains(r#"label="quote\"slash\\name""#),
            "{dot}"
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
