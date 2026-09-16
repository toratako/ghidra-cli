//! Read-query integration tests sharing one bridge and suite-owned project.

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, ghidra, test_project, DaemonTestHarness};

#[path = "readonly/batch.rs"]
mod batch;
#[path = "readonly/functions.rs"]
mod functions;
#[path = "readonly/program.rs"]
mod program;
#[path = "readonly/query.rs"]
mod query;
#[path = "readonly/relationships.rs"]
mod relationships;
#[path = "readonly/search.rs"]
mod search;
#[path = "readonly/search_limits.rs"]
mod search_limits;

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

// Keep snapshots in this crate root: Insta derives their identities and paths
// from the module and source file containing each assertion.

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_function_list_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("1")
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("function_list_structure", json, {
        "[].address" => "[ADDR]",
        "[].entry_point" => "[ADDR]",
        "[].size" => "[SIZE]",
        "[].parameters[].ordinal" => "[N]",
        "[].local_variables[].stack_offset" => "[N]",
        "[].calls[]" => "[ADDR]",
        "[].called_by[]" => "[ADDR]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_stats_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("stats")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("stats_structure", json, {
        ".functions" => "[N]",
        ".instructions" => "[N]",
        ".strings" => "[N]",
        ".symbols" => "[N]",
        ".imports" => "[N]",
        ".exports" => "[N]",
        ".memory_blocks" => "[N]",
        ".memory_size" => "[N]",
        ".sections" => "[N]",
        ".data_types" => "[N]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_memory_map_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("memory_map_structure", json, {
        "[].start" => "[ADDR]",
        "[].end" => "[ADDR]",
        "[].size" => "[SIZE]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_disasm_structure() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("3")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("disasm_structure", json, {
        ".results[].address" => "[ADDR]",
        ".results[].operands" => "[OPS]",
        ".results[].bytes" => "[BYTES]",
        ".results[].length" => "[N]",
        ".start_address" => "[ADDR]",
        ".end_address" => "[ADDR]",
        "[].address" => "[ADDR]",
        "[].operands" => "[OPS]",
        "[].bytes" => "[BYTES]",
        "[].length" => "[N]",
    });
}

#[test]
#[serial]
#[ignore] // Run `cargo insta test --review` to bootstrap snapshots
fn test_snapshot_graph_callees_structure() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg(&main_addr)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("graph_callees_structure", json, {
        ".nodes[].id" => "[ID]",
        ".nodes[].address" => "[ADDR]",
        ".edges[].from" => "[ID]",
        ".edges[].to" => "[ID]",
    });
}
