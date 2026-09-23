//! Tests for function tag operations (issue #17).
//!
//! Tags share one project within this suite, so every test
//! cleans up its own uniquely-prefixed tags (and tolerates leftovers by
//! deleting them up front).

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, helpers::ghidra,
    DaemonTestHarness,
};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

/// Delete a tag, ignoring failure (used for pre-test cleanup of leftovers).
fn cleanup_tag(harness: &DaemonTestHarness, name: &str) {
    let _ = ghidra(harness)
        .arg("tag")
        .arg("delete")
        .arg(name)
        .with_project(test_project(), TEST_PROGRAM)
        .run();
}

/// Run a tag subcommand with JSON output and return the result data.
/// Uses the global `--json` flag: mutation subcommands deliberately carry no
/// QueryOptions, so `--format json` is not available on them.
fn tag_json(harness: &DaemonTestHarness, args: &[&str]) -> serde_json::Value {
    let result = ghidra(harness)
        .args(args.iter().copied())
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
    result.data()
}

fn str_items(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

#[test]
#[serial]
fn test_tag_create_and_list_roundtrip() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt1_crypto");

    let rows = tag_json(
        harness,
        &["tag", "create", "tt1_crypto", "--comment", "AES helpers"],
    );
    assert_eq!(rows["status"], "created");
    assert_eq!(rows["existed"], false);

    let tags = tag_json(harness, &["tag", "list"]);
    let row = tags
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "tt1_crypto")
        .expect("created tag missing from tag list");
    assert_eq!(row["comment"], "AES helpers");
    assert_eq!(row["use_count"], 0);

    cleanup_tag(harness, "tt1_crypto");
}

#[test]
#[serial]
fn test_tag_create_existing_reports_existed() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt2_dup");

    tag_json(harness, &["tag", "create", "tt2_dup"]);
    let rows = tag_json(harness, &["tag", "create", "tt2_dup"]);
    assert_eq!(rows["existed"], true);

    cleanup_tag(harness, "tt2_dup");
}

#[test]
#[serial]
fn test_tag_attach_reports_attached_and_already_present() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt3_pre");
    cleanup_tag(harness, "tt3_other");

    tag_json(harness, &["tag", "create", "tt3_pre"]);
    tag_json(harness, &["tag", "create", "tt3_other"]);

    let rows = tag_json(
        harness,
        &["tag", "attach", "tt3_pre", "tt3_other", "--function", &addr],
    );
    let row = &rows;
    assert_eq!(row["status"], "attached");
    assert_eq!(str_items(&row["attached"]), vec!["tt3_pre", "tt3_other"]);
    assert!(str_items(&row["already_present"]).is_empty());

    // Idempotency: re-run reports already_present, not an error.
    let rows = tag_json(
        harness,
        &["tag", "attach", "tt3_pre", "tt3_other", "--function", &addr],
    );
    assert!(str_items(&rows["attached"]).is_empty());
    assert_eq!(
        str_items(&rows["already_present"]),
        vec!["tt3_pre", "tt3_other"]
    );

    cleanup_tag(harness, "tt3_pre");
    cleanup_tag(harness, "tt3_other");
}

#[test]
#[serial]
fn test_tag_attach_dedupes_argv() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt4_dup");
    tag_json(harness, &["tag", "create", "tt4_dup"]);

    let rows = tag_json(
        harness,
        &["tag", "attach", "tt4_dup", "tt4_dup", "--function", &addr],
    );
    assert_eq!(str_items(&rows["attached"]), vec!["tt4_dup"]);

    cleanup_tag(harness, "tt4_dup");
}

#[test]
#[serial]
fn test_tag_get_details_track_membership() {
    require_ghidra!();
    let harness = harness();
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    assert_eq!(addrs.len(), 2);
    cleanup_tag(harness, "tt5_member");

    tag_json(
        harness,
        &["tag", "create", "tt5_member", "--comment", "Review queue"],
    );
    let mut expected = serde_json::json!({
        "name": "tt5_member", "comment": "Review queue", "use_count": 0
    });
    assert_eq!(
        tag_json(harness, &["tag", "get", "tt5_member"]),
        expected.clone()
    );

    for addr in &addrs {
        tag_json(
            harness,
            &["tag", "attach", "tt5_member", "--function", addr],
        );
    }
    expected["use_count"] = serde_json::json!(2);
    assert_eq!(
        harness.client().unwrap().tag_get("tt5_member").unwrap(),
        expected
    );
    assert_eq!(
        tag_json(harness, &["tag", "get", "tt5_member"]),
        expected.clone()
    );

    let tags = tag_json(harness, &["tag", "list", "--function", &addrs[0]]);
    assert!(tags.as_array().unwrap().contains(&expected));

    tag_json(
        harness,
        &["tag", "detach", "tt5_member", "--function", &addrs[0]],
    );
    expected["use_count"] = serde_json::json!(1);
    assert_eq!(tag_json(harness, &["tag", "get", "tt5_member"]), expected);

    cleanup_tag(harness, "tt5_member");
}

#[test]
#[serial]
fn test_function_list_tag_filter_and_semantics() {
    require_ghidra!();
    let harness = harness();
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    assert!(addrs.len() >= 2, "need two functions for AND test");
    cleanup_tag(harness, "tt6_both");
    cleanup_tag(harness, "tt6_only1");
    tag_json(harness, &["tag", "create", "tt6_both"]);
    tag_json(harness, &["tag", "create", "tt6_only1"]);

    tag_json(
        harness,
        &[
            "tag",
            "attach",
            "tt6_both",
            "tt6_only1",
            "--function",
            &addrs[0],
        ],
    );
    tag_json(
        harness,
        &["tag", "attach", "tt6_both", "--function", &addrs[1]],
    );

    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--tag",
            "tt6_both",
            "--fields",
            "name,address",
        ],
    );
    assert_eq!(rows.as_array().unwrap().len(), 2);
    for (row, addr) in rows.as_array().unwrap().iter().zip(&addrs) {
        assert!(row["name"].is_string());
        assert_eq!(row["address"], *addr);
        assert_eq!(row.as_object().unwrap().len(), 2);
    }

    // Multiple --tag = AND: only the function carrying BOTH matches.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--tag",
            "tt6_both",
            "--tag",
            "tt6_only1",
        ],
    );
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["address"], serde_json::json!(addrs[0]));

    cleanup_tag(harness, "tt6_both");
    cleanup_tag(harness, "tt6_only1");
}

#[test]
#[serial]
fn test_function_list_unknown_tag_errors_with_hint() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt7_real");
    tag_json(harness, &["tag", "create", "tt7_real"]);

    // Unknown tag is an error (nonzero exit), never a silent empty result.
    let result = ghidra(harness)
        .args(["function", "list", "--tag", "tt7_zzzz"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("No tag named");

    // Case-insensitive near-match hint
    let result = ghidra(harness)
        .args(["tag", "get", "TT7_REAL"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("Did you mean 'tt7_real'?");

    cleanup_tag(harness, "tt7_real");
}

#[test]
#[serial]
fn test_function_list_untagged() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt8_tagged");
    tag_json(harness, &["tag", "create", "tt8_tagged"]);

    tag_json(
        harness,
        &["tag", "attach", "tt8_tagged", "--function", &addr],
    );

    let rows = tag_json(harness, &["function", "list", "--untagged", "--limit", "0"]);
    assert!(
        !rows
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["address"] == serde_json::json!(addr)),
        "--untagged must exclude the tagged function"
    );

    cleanup_tag(harness, "tt8_tagged");
}

#[test]
#[serial]
fn test_tag_detach_and_all() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt9_a");
    cleanup_tag(harness, "tt9_b");
    cleanup_tag(harness, "tt9_unattached");
    for name in ["tt9_a", "tt9_b", "tt9_unattached"] {
        tag_json(harness, &["tag", "create", name]);
    }

    tag_json(
        harness,
        &["tag", "attach", "tt9_a", "tt9_b", "--function", &addr],
    );

    // Known definitions that are not attached are successful no-ops.
    let rows = tag_json(
        harness,
        &[
            "tag",
            "detach",
            "tt9_a",
            "tt9_unattached",
            "--function",
            &addr,
        ],
    );
    assert_eq!(rows["status"], "detached");
    assert_eq!(str_items(&rows["detached"]), vec!["tt9_a"]);
    assert_eq!(str_items(&rows["not_present"]), vec!["tt9_unattached"]);

    // --all clears the rest
    let rows = tag_json(harness, &["tag", "detach", "--all", "--function", &addr]);
    assert_eq!(str_items(&rows["detached"]), vec!["tt9_b"]);
    for name in ["tt9_a", "tt9_b", "tt9_unattached"] {
        assert_eq!(tag_json(harness, &["tag", "get", name])["use_count"], 0);
    }

    let tags = tag_json(harness, &["tag", "list", "--function", &addr]);
    assert!(
        !tags
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "tt9_a" || t["name"] == "tt9_b"),
        "function should have no tt9 tags after detach --all"
    );

    cleanup_tag(harness, "tt9_a");
    cleanup_tag(harness, "tt9_b");
    cleanup_tag(harness, "tt9_unattached");
}

#[test]
#[serial]
fn test_tag_rename_and_collision() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt10_old");
    cleanup_tag(harness, "tt10_new");
    cleanup_tag(harness, "tt10_taken");

    tag_json(harness, &["tag", "create", "tt10_old"]);
    tag_json(harness, &["tag", "create", "tt10_taken"]);

    let rows = tag_json(harness, &["tag", "rename", "tt10_old", "tt10_new"]);
    assert_eq!(rows["status"], "renamed");

    let tags = tag_json(harness, &["tag", "list"]);
    assert!(tags
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "tt10_new"));
    assert!(!tags
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "tt10_old"));

    // Renaming onto an existing name errors — no implicit merge.
    let result = ghidra(harness)
        .args(["tag", "rename", "tt10_new", "tt10_taken"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("already exists");

    cleanup_tag(harness, "tt10_new");
    cleanup_tag(harness, "tt10_taken");
}

#[test]
#[serial]
fn test_tag_set_comment_and_clear() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt11_c");

    tag_json(harness, &["tag", "create", "tt11_c"]);
    tag_json(
        harness,
        &["tag", "set-comment", "tt11_c", "--text", "first pass done"],
    );

    let tags = tag_json(harness, &["tag", "get", "tt11_c"]);
    assert_eq!(tags["comment"], "first pass done");

    // Empty string clears
    tag_json(harness, &["tag", "set-comment", "tt11_c", "--text", ""]);
    let tags = tag_json(harness, &["tag", "get", "tt11_c"]);
    assert_eq!(tags["comment"], "");

    cleanup_tag(harness, "tt11_c");
}

#[test]
#[serial]
fn test_tag_delete_reports_counts_then_get_errors() {
    require_ghidra!();
    let harness = harness();
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    assert_eq!(addrs.len(), 2);
    cleanup_tag(harness, "tt12_del");
    tag_json(harness, &["tag", "create", "tt12_del"]);

    for addr in &addrs {
        tag_json(harness, &["tag", "attach", "tt12_del", "--function", addr]);
    }

    let rows = tag_json(harness, &["tag", "delete", "tt12_del"]);
    assert_eq!(rows["status"], "deleted");
    assert_eq!(rows["use_count"], 2);
    assert_eq!(rows["functions_affected"], 2);
    for addr in &addrs {
        let tags = tag_json(harness, &["tag", "list", "--function", addr]);
        assert!(!tags
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag["name"] == "tt12_del"));
    }

    let result = ghidra(harness)
        .args(["tag", "get", "tt12_del"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("No tag named");
}

#[test]
#[serial]
fn test_tag_attach_unknown_definition_errors_without_mutating() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt13_known");
    cleanup_tag(harness, "tt13_unknown");
    tag_json(harness, &["tag", "create", "tt13_known"]);
    let before = tag_json(harness, &["tag", "list", "--function", &addr]);

    let result = ghidra(harness)
        .args([
            "tag",
            "attach",
            "tt13_known",
            "tt13_unknown",
            "--function",
            &addr,
        ])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("No tag named 'tt13_unknown'");

    assert_eq!(
        tag_json(harness, &["tag", "list", "--function", &addr]),
        before
    );
    let tags = tag_json(harness, &["tag", "list"]);
    assert!(!tags
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "tt13_unknown"));
    cleanup_tag(harness, "tt13_known");
}

#[test]
#[serial]
fn test_tag_wire_preflights_definition_names_and_detach_scope() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    for name in ["tt17_attached", "tt17_unattached", "tt17_unknown"] {
        cleanup_tag(harness, name);
    }
    for name in ["tt17_attached", "tt17_unattached"] {
        tag_json(harness, &["tag", "create", name]);
    }
    tag_json(
        harness,
        &["tag", "attach", "tt17_attached", "--function", &addr],
    );
    let before = tag_json(harness, &["tag", "list", "--function", &addr]);
    let definitions = tag_json(harness, &["tag", "list"]);

    for (command, args, message) in [
        (
            "tag_attach",
            serde_json::json!({"function": addr, "tags": ["tt17_unattached", "tt17_unknown"]}),
            "No tag named 'tt17_unknown'",
        ),
        (
            "tag_detach",
            serde_json::json!({"function": addr, "tags": ["tt17_attached", "tt17_unknown"]}),
            "No tag named 'tt17_unknown'",
        ),
        (
            "tag_detach",
            serde_json::json!({"function": addr, "tags": ["tt17_attached"], "all": true}),
            "exactly one",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(message), "{command}: {error}");
        assert_eq!(
            tag_json(harness, &["tag", "list", "--function", &addr]),
            before
        );
        assert_eq!(tag_json(harness, &["tag", "list"]), definitions);
    }
    for name in ["tt17_attached", "tt17_unattached"] {
        cleanup_tag(harness, name);
    }
}

#[test]
#[serial]
fn test_tag_invalid_names_rejected_at_creation() {
    require_ghidra!();
    let harness = harness();

    for bad in ["", "a,b", "a;b"] {
        let result = ghidra(harness)
            .args(["tag", "create", bad])
            .with_project(test_project(), TEST_PROGRAM)
            .run();
        result.assert_failure();
        result.assert_stderr_contains("Tag name cannot");
    }
}

#[test]
#[serial]
fn test_tag_case_sensitivity() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt14_Case");
    cleanup_tag(harness, "tt14_case");
    tag_json(harness, &["tag", "create", "tt14_Case"]);

    tag_json(
        harness,
        &["tag", "attach", "tt14_Case", "--function", &addr],
    );

    // Server-side --tag is exact: wrong case errors (tag does not exist).
    let result = ghidra(harness)
        .args(["function", "list", "--tag", "tt14_case"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_failure();

    // Client-side DSL `~` is case-insensitive: matches despite case.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--filter",
            "tags ~ 'tt14_case'",
            "--limit",
            "0",
        ],
    );
    assert!(rows
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["address"] == serde_json::json!(addr)));

    // DSL `=` is exact: wrong case matches nothing.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--filter",
            "tags = 'tt14_case'",
            "--limit",
            "0",
        ],
    );
    assert!(!rows
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["address"] == serde_json::json!(addr)));

    cleanup_tag(harness, "tt14_Case");
}

#[test]
#[serial]
fn test_function_outputs_include_tags_field() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt15_b");
    cleanup_tag(harness, "tt15_a");
    tag_json(harness, &["tag", "create", "tt15_b"]);
    tag_json(harness, &["tag", "create", "tt15_a"]);

    tag_json(
        harness,
        &["tag", "attach", "tt15_b", "tt15_a", "--function", &addr],
    );

    // function get carries tags, sorted alphabetically
    let row = tag_json(harness, &["function", "get", &addr]);
    assert_eq!(str_items(&row["tags"]), vec!["tt15_a", "tt15_b"]);

    // function list rows carry tags too (stable schema: present even when empty)
    let rows = tag_json(harness, &["function", "list", "--limit", "0"]);
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == serde_json::json!(addr))
        .expect("function missing from list");
    assert_eq!(str_items(&row["tags"]), vec!["tt15_a", "tt15_b"]);
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["tags"].is_array()),
        "every function row must carry a tags array"
    );

    cleanup_tag(harness, "tt15_b");
    cleanup_tag(harness, "tt15_a");
}

#[test]
#[serial]
fn test_csv_tags_join_with_semicolon() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt16_x");
    cleanup_tag(harness, "tt16_y");
    tag_json(harness, &["tag", "create", "tt16_x"]);
    tag_json(harness, &["tag", "create", "tt16_y"]);

    tag_json(
        harness,
        &["tag", "attach", "tt16_x", "tt16_y", "--function", &addr],
    );

    // Fields chosen to exclude `signature`, whose own commas are a
    // pre-existing, out-of-scope CSV wart.
    let result = ghidra(harness)
        .args([
            "function",
            "list",
            "--fields",
            "name,address,tags",
            "--format",
            "csv",
            "--limit",
            "0",
        ])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();

    let line = result
        .stdout
        .lines()
        .find(|l| l.contains(&addr))
        .expect("tagged function missing from CSV")
        .to_string();
    assert_eq!(
        line.matches(',').count(),
        2,
        "multi-tag row must not shift CSV columns: {}",
        line
    );
    assert!(
        line.contains("tt16_x;tt16_y"),
        "tags must join with ';' in CSV: {}",
        line
    );

    cleanup_tag(harness, "tt16_x");
    cleanup_tag(harness, "tt16_y");
}

// --- clap-level grammar tests (no Ghidra required) ---

#[test]
fn test_clap_tag_attach_requires_tags() {
    // Attaching requires at least one tag as well as the function target.
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["tag", "attach", "--function", "some_func"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_clap_tag_detach_all_conflicts_with_tags() {
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "tag",
            "detach",
            "--all",
            "extra_tag",
            "--function",
            "some_func",
        ])
        .assert()
        .failure()
        .code(2);

    // Neither tags nor --all is also a parse error
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["tag", "detach", "--function", "some_func"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_clap_untagged_conflicts_with_tag() {
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["function", "list", "--tag", "x", "--untagged"])
        .assert()
        .failure()
        .code(2);
}
