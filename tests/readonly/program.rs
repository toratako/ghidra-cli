use super::{harness, TEST_PROGRAM};
use crate::common::{
    ghidra,
    schemas::{MemoryBlock, StringData, Validate},
    test_project, GhidraCommand,
};
use serial_test::serial;
use std::fs;

// Strings List Tests

#[test]
#[serial]
fn test_strings_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("string")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("50")
        .run();

    result.assert_success();

    let strings: Vec<StringData> = result.json();
    assert!(!strings.is_empty(), "Should have at least one string");

    for s in &strings {
        s.assert_valid();
    }

    // Check if any known strings are present (informational)
    let known = ["Hello", "test_binary", "super_secret"];
    let found: Vec<_> = known
        .iter()
        .filter(|k| strings.iter().any(|s| s.value.contains(*k)))
        .collect();
    if !found.is_empty() {
        eprintln!("Found known strings: {:?}", found);
    }
}

// Memory Map Tests

#[test]
#[serial]
fn test_memory_map_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let blocks: Vec<MemoryBlock> = result.json();
    assert!(
        !blocks.is_empty(),
        "Memory map should have at least one block"
    );

    for block in &blocks {
        block.assert_valid();
    }

    let has_text = blocks
        .iter()
        .any(|b| b.name.contains("text") || b.name.contains("code") || b.name.contains(".text"));
    assert!(
        has_text,
        "Should have a text/code segment. Found: {:?}",
        blocks.iter().map(|b| &b.name).collect::<Vec<_>>()
    );
}

// Program info Tests

#[test]
#[serial]
fn test_program_info_contains_expected_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .args(["program", "info"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Program info should produce output"
    );
    result.assert_stdout_contains("sample_binary");
}

#[test]
#[serial]
fn test_symbol_externals_and_entry_points_match_bridge_rows() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    for (kind, wire, key) in [
        ("externals", "symbol_externals", "externals"),
        ("entry-points", "symbol_entry_points", "entry_points"),
    ] {
        let all = client.send_command(wire, None).unwrap();
        let rows = all[key].as_array().unwrap();
        assert!(!rows.is_empty(), "fixture must contain {kind}: {all}");
        let run = |flags: &[&str]| -> serde_json::Value {
            let result = ghidra(harness)
                .args(["symbol", kind])
                .args(flags.iter().copied())
                .with_project(test_project(), TEST_PROGRAM)
                .json_format()
                .run();
            result.assert_success();
            result.json()
        };
        assert_eq!(run(&["--limit", "0"]), all[key]);
        assert_eq!(run(&["--count"]), serde_json::json!(rows.len()));
        for row in rows {
            assert!(row["name"].is_string(), "{row}");
            assert!(row["address"].is_string(), "{row}");
            if kind == "externals" {
                assert!(row["library"].is_string(), "{row}");
            }
        }
        let first = rows
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .min()
            .unwrap();
        assert_eq!(
            run(&["--sort", "name", "--fields", "name", "--limit", "1"]),
            serde_json::json!([{"name": first}]),
        );
    }
}

// Stats Tests

#[test]
#[serial]
fn test_stats_normal() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("stats")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("stats");
    result.assert_stdout_contains("functions");
    result.assert_stdout_contains("symbols");
}

#[test]
#[serial]
fn test_stats_has_all_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("stats")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();

    // Stats may be returned as flat object or wrapped: [{"stats": {...}}]
    let obj = if let Some(obj) = json.as_object() {
        obj.clone()
    } else if let Some(arr) = json.as_array() {
        arr.first()
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("stats"))
            .and_then(|v| v.as_object())
            .expect("Expected stats object in array wrapper")
            .clone()
    } else {
        panic!("Stats should be a JSON object or array");
    };

    // Verify key fields exist
    for key in &["functions", "strings", "symbols"] {
        assert!(obj.contains_key(*key), "Missing stats field: {}", key);
    }

    let functions = obj.get("functions").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        functions > 0,
        "functions count should be > 0, got {}",
        functions
    );

    let strings = obj.get("strings").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(strings > 0, "strings count should be > 0, got {}", strings);
}

#[test]
#[serial]
fn test_stats_json_format() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("stats")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();

    // Verify output is valid JSON
    let json: serde_json::Value = result.json();

    // Extract stats object (may be flat or wrapped)
    let stats = if json.is_object() {
        json.clone()
    } else if let Some(arr) = json.as_array() {
        arr.first()
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("stats"))
            .cloned()
            .expect("Expected stats in array wrapper")
    } else {
        panic!("Expected JSON object or array");
    };

    // Verify it has numeric function count
    let functions = stats
        .get("functions")
        .and_then(|v| v.as_u64())
        .expect("Should have numeric functions field");
    assert!(
        functions >= 8,
        "Should have at least 8 functions, got {}",
        functions
    );

    let strings = stats
        .get("strings")
        .and_then(|v| v.as_u64())
        .expect("Should have numeric strings field");
    assert!(
        strings >= 3,
        "Should have at least 3 strings, got {}",
        strings
    );
}

// Program Tests

#[test]
#[serial]
fn test_program_info() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("info")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();

    // Program info should mention the program name
    assert!(
        result.stdout.contains("sample_binary") || result.stdout.contains("name"),
        "Program info should contain program name or 'name' field. Got: {}",
        &result.stdout[..result.stdout.len().min(500)]
    );
}

#[test]
#[serial]
fn test_program_export_rejects_unknown_and_missing_formats() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program.export");
    fs::write(&path, b"existing output").unwrap();
    let error = client
        .program_export("unknown-format", Some(path.to_str().unwrap()))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Unsupported export format: unknown-format"),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"existing output");
    let error = client.send_command("program_export", None).unwrap_err();
    assert!(
        error.to_string().contains("Export format required"),
        "{error}"
    );
}

#[test]
#[serial]
fn test_program_export_gzf_reopens_and_preserves_selection() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let original = client.program_info().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program.gzf");
    fs::write(&path, b"previous export").unwrap();
    let exported = client
        .program_export("gzf", Some(path.to_str().unwrap()))
        .unwrap();
    assert_eq!(exported["status"], "exported");
    assert!(fs::metadata(&path).unwrap().len() > 0);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.io.File;
public class VerifyPackedExport extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        var file = root.createFile(getScriptArgs()[1], new File(getScriptArgs()[0]), monitor);
        Object consumer = new Object();
        try {
            Program reopened = (Program) file.getDomainObject(consumer, true, false, monitor);
            try {
                if (!reopened.getName().equals(currentProgram.getName()) ||
                    reopened.getFunctionManager().getFunctionCount() !=
                        currentProgram.getFunctionManager().getFunctionCount() ||
                    reopened.getMemory().getSize() != currentProgram.getMemory().getSize()) {
                    throw new IllegalStateException("Packed export differs from current program");
                }
            } finally {
                reopened.release(consumer);
            }
        } finally {
            file.delete();
        }
    }
}
"#,
            &[
                path.to_str().unwrap().to_owned(),
                format!("gzf-{}", uuid::Uuid::new_v4()),
            ],
            &[],
            false,
        )
        .unwrap();
    assert_eq!(client.program_info().unwrap(), original);
    assert!(
        client.stats().unwrap()["stats"]["functions"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
#[serial]
fn test_program_export_gzf_save_failure_preserves_existing_output() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let original = client.program_info().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program.gzf");
    fs::write(&path, b"previous export").unwrap();
    let blocked = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class BlockPackedExportSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("block packed export save")));
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap_err();
    let blocked = blocked
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap();
    let transaction = blocked.detail["command_response"]["data"]["stdout"]
        .as_str()
        .unwrap()
        .trim()
        .to_owned();
    let exported = client.program_export("gzf", Some(path.to_str().unwrap()));
    // Restore the shared session before assertions about the expected failure.
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class UnblockPackedExportSave extends GhidraScript {
    public void run() throws Exception {
        currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
    }
}
"#,
            &[transaction],
            &[],
            false,
        )
        .unwrap();
    let error = exported.unwrap_err();
    let error = error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap();
    assert_eq!(error.detail["save_failed"], true);
    assert_eq!(fs::read(&path).unwrap(), b"previous export");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(client.program_info().unwrap(), original);
    client
        .program_export("gzf", Some(path.to_str().unwrap()))
        .unwrap();
}

#[test]
#[serial]
fn test_program_export_gzf_publish_failure_cleans_staging() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let original = client.program_info().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("existing-directory");
    fs::create_dir(&destination).unwrap();
    let sentinel = destination.join("keep");
    fs::write(&sentinel, b"existing data").unwrap();
    let error = client
        .program_export("gzf", Some(destination.to_str().unwrap()))
        .unwrap_err();
    assert!(
        error.to_string().contains("Failed to export (gzf)"),
        "{error}"
    );
    assert_eq!(fs::read(sentinel).unwrap(), b"existing data");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(client.program_info().unwrap(), original);
    assert!(
        client.stats().unwrap()["stats"]["functions"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
#[serial]
fn test_program_close() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("close")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    assert!(
        result.exit_code == 0 || result.stderr.contains("Unknown command"),
        "Expected success or 'Unknown command', got: {}",
        result.stderr
    );

    // The bridge is shared across the whole suite, and `program close` clears the
    // current program. Re-open it so later tests (which assume a program is
    // loaded, e.g. test_program_info_no_program) aren't broken by test ordering.
    let _ = ghidra(harness)
        .arg("program")
        .arg("info")
        .with_project(test_project(), TEST_PROGRAM)
        .run();
}

#[test]
#[serial]
fn test_program_info_no_program() {
    require_ghidra!();
    let harness = harness();

    let result = GhidraCommand::new()
        .arg("program")
        .arg("info")
        .with_daemon(harness)
        .run();

    result.assert_success();
}
