//! Decompiler diagnostics and the attributes of the selected function entry.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("decompile-details-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("../fixtures/readonly/CreateDecompileDetails.java"),
                std::slice::from_ref(&name),
                &[],
                false,
            )
            .unwrap();
        name
    })
}

fn command(args: &[&str]) -> crate::common::helpers::GhidraResult {
    ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), fixture())
        .arg("--json")
        .run()
}

fn row(args: &[&str]) -> Value {
    let result = command(args);
    result.assert_success();
    result.data::<Value>()
}

#[test]
#[serial]
fn function_entry_attributes_match_memory_block_list_and_preserve_list_membership() {
    require_ghidra!();
    let listed = command(&["function", "list", "--limit", "0"]);
    listed.assert_success();
    let listed: Value = listed.data();
    // Ghidra's existing memory-function iterator excludes external and unmapped entries.
    assert_eq!(listed.as_array().unwrap().len(), 6, "{listed}");
    assert!(!listed
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["name"] == "outside"));
    let memory = command(&["memory", "block", "list", "--limit", "0"]);
    memory.assert_success();
    let memory: Value = memory.data();
    for (name, block) in [
        ("clean", "code"),
        ("warned", "code"),
        ("nonexec", "data"),
        ("thunk", "code"),
    ] {
        let expected = memory
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == block)
            .unwrap();
        let expected = json!({"name": block, "permissions": expected["permissions"]});
        let mut got = row(&["function", "get", name]);
        assert_eq!(got["is_external"], false);
        assert_eq!(got["entry_memory"], expected);
        let from_list = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap();
        assert!(got.as_object_mut().unwrap().remove("body_ranges").is_some());
        assert_eq!(from_list, &got);
    }
    assert_eq!(
        row(&["function", "get", "clean"])["entry_memory"]["permissions"],
        "rx"
    );
    assert_eq!(
        row(&["function", "get", "nonexec"])["entry_memory"]["permissions"],
        "rw"
    );
    for (name, external) in [("outside", true), ("unmapped", false)] {
        let got = row(&["function", "get", name]);
        assert_eq!(got["is_external"], external, "{got}");
        assert!(got.get("entry_memory").unwrap().is_null(), "{got}");
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn completed_decompiles_retain_comment_warnings_and_failures_stay_errors() {
    require_ghidra!();
    for name in ["clean", "nonexec", "literal"] {
        let got = row(&["decompile", name]);
        assert_eq!(got["warnings"], json!([]), "{got}");
        assert_eq!(got["is_external"], false);
        assert_eq!(
            got["entry_memory"],
            row(&["function", "get", name])["entry_memory"]
        );
        if name == "literal" {
            assert!(
                got["code"]
                    .as_str()
                    .unwrap()
                    .contains("\"WARNING: string literal\""),
                "{got}"
            );
        }
    }
    let warned = row(&["decompile", "warned"]);
    let warnings = warned["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2, "{warned}");
    assert!(
        warnings.iter().any(|w| w["message"]
            .as_str()
            .unwrap()
            .contains("Unknown calling convention")),
        "{warned}"
    );
    assert!(
        warnings.iter().any(|w| w["message"]
            .as_str()
            .unwrap()
            .contains("continued line 日本語")),
        "{warned}"
    );
    for warning in warnings {
        assert_eq!(warning["source"], "c_comment");
        assert_eq!(warning["address"], warned["address"]);
    }
    let c = command(&["decompile", "warned", "--format", "c"]);
    c.assert_success();
    assert_eq!(c.stdout, warned["code"].as_str().unwrap());
    assert!(c.stderr.is_empty(), "{}", c.stderr);
    for format in ["compact", "full"] {
        let output = command(&["decompile", "warned", "--format", format]);
        output
            .assert_success()
            .assert_stdout_contains("Warnings:")
            .assert_stdout_contains("Entry memory: code (rx)");
    }
    let bad = command(&["decompile", "bad"]);
    bad.assert_success();
    let got: Value = bad.data();
    assert!(
        got["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["message"].as_str().unwrap().contains("bad instruction")),
        "{got}"
    );
    assert!(bad.stderr.is_empty(), "{}", bad.stderr);
    let failure = command(&["decompile", "outside"]);
    failure.assert_failure();
    let failure: Value = serde_json::from_str(&failure.stderr).unwrap();
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["detail"]["is_external"], true, "{failure}");
    assert!(failure["detail"].get("entry_memory").unwrap().is_null());
    // A failed decompile must not poison the next request or retain old warnings.
    assert_eq!(row(&["decompile", "clean"])["warnings"], json!([]));
    // Exercise the independent API-message channel alongside real comment
    // markup. Native warning messages are not reliably triggerable on demand.
    harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/readonly/CheckApiDecompileWarning.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
