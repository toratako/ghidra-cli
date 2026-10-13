use crate::common;
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = include_str!("../fixtures/memory/CreateBlockLifecycleFixture.java");

// Shared by the ordinary read-only check and the test-owned dispatcher failure probe.
const CHECK_STATE: &str = include_str!("../fixtures/memory/BlockLifecycleState.java.inc");

fn fixture() -> (BridgeClient, String) {
    let client = super::harness().client().unwrap();
    let name = format!("block-lifecycle-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, std::slice::from_ref(&name), &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    (client, name)
}

fn check_state(client: &BridgeClient, start: &str, deleted: bool) {
    let source = include_str!("../fixtures/memory/CheckBlockLifecycleFixture.java.in")
        .replace("/* CHECK_STATE */", CHECK_STATE);
    client
        .script_run_source(&source, &[start.into(), deleted.to_string()], &[], false)
        .unwrap();
}

fn command(client: &BridgeClient, name: &str, args: Value) -> Value {
    client.send_command(name, Some(args)).unwrap()
}

fn reject(client: &BridgeClient, name: &str, args: Value, expected: &str) {
    let error = client.send_command(name, Some(args)).unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains(expected),
        "{error}"
    );
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["rolled_back"], true, "{error}");
    assert!(detail.get("partial_changes_saved").is_none());
}

fn reopen(client: &BridgeClient, name: &str) {
    client.program_close().unwrap();
    client.open_program(name).unwrap();
}

fn cleanup(client: &BridgeClient, name: &str) {
    client.open_program(common::FIXTURE_PROGRAM).unwrap();
    client.program_delete(name).unwrap();
}

#[test]
#[serial]
fn move_and_delete_preserve_native_analysis_effects_and_file_bytes_after_reopen() {
    require_ghidra!();
    let (client, name) = fixture();
    check_state(&client, "2000", false);
    // Exclude the selected block when checking destination collisions. Its own
    // overlapping range must support movement in both directions.
    for (start, destination, expected) in
        [("0x2000", "0x2080", "2080"), ("0x2080", "0x2000", "2000")]
    {
        let moved = command(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":destination}),
        );
        assert_eq!(moved["changed"], true);
        check_state(&client, expected, false);
    }
    let moved = command(
        &client,
        "memory_block_move",
        json!({"block_start":"ram:0x2000", "start":"ram:0x6000"}),
    );
    assert_eq!(moved["changed"], true);
    assert_eq!(moved["before"]["start"], "0x00002000");
    assert_eq!(moved["after"]["start"], "0x00006000");
    assert_eq!(moved["after"]["end"], "0x000060ff");
    let original = command(
        &client,
        "read_memory",
        json!({"address":"0x6050", "size":1, "source":"original"}),
    );
    assert_eq!(original["hex"], "55");
    assert_eq!(original["mappings"][0]["file_offset"], 0x258);
    assert_eq!(original["mappings"][0]["file_bytes_offset"], 0x58);
    let mappings = command(
        &client,
        "memory_file_mappings",
        json!({"file_offset":"0x258"}),
    );
    assert_eq!(mappings["count"], 1);
    assert_eq!(mappings["mappings"][0]["address"], "0x00006050");
    assert_eq!(mappings["mappings"][0]["block_start"], "0x00006000");
    assert_eq!(mappings["mappings"][0]["source_at"], "0x00006000");
    reopen(&client, &name);
    check_state(&client, "6000", false);
    reject(
        &client,
        "memory_block_delete",
        json!({"block_start":"0x2000"}),
        "block",
    );
    let unchanged = command(
        &client,
        "memory_block_move",
        json!({"block_start":moved["after"]["start"], "start":"0x6000"}),
    );
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["before"], unchanged["after"]);
    let removed = command(
        &client,
        "memory_block_delete",
        json!({"block_start":moved["after"]["start"]}),
    );
    assert_eq!(removed["changed"], true);
    assert_eq!(removed["before"], moved["after"]);
    assert!(removed["after"].is_null());
    assert_eq!(removed["overlay_removed"], false);
    reopen(&client, &name);
    check_state(&client, "6000", true);
    let mappings = command(
        &client,
        "memory_file_mappings",
        json!({"file_offset":"0x258"}),
    );
    assert_eq!(mappings["count"], 0);
    assert_eq!(mappings["mappings"], json!([]));
    cleanup(&client, &name);
}

#[test]
#[serial]
fn overlay_move_and_delete_keep_space_until_its_last_block_is_removed() {
    require_ghidra!();
    let (client, name) = fixture();
    command(
        &client,
        "memory_block_create",
        json!({"name":"bank_code", "start":"ram:0x2000", "size":16,
            "uninitialized":false, "fill":171, "permissions":"rx", "volatile":false,
            "overlay":"bank"}),
    );
    command(
        &client,
        "memory_block_create",
        json!({"name":"bank_data", "start":"bank:0x4000", "size":16,
            "uninitialized":true, "permissions":"rw", "volatile":true}),
    );
    client
        .script_run_source(
            include_str!("../fixtures/memory/MarkMovingOverlay.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let moved = command(
        &client,
        "memory_block_move",
        json!({"block_start":"bank:0x2000", "start":"bank:0x6000"}),
    );
    assert_eq!(moved["after"]["start"], "bank:0x00006000");
    assert_eq!(moved["after"]["address_space"], "bank");
    assert_eq!(moved["after"]["base_space"], "ram");
    reopen(&client, &name);
    client
        .script_run_source(
            include_str!("../fixtures/memory/CheckMovedOverlay.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let first = command(
        &client,
        "memory_block_delete",
        json!({"block_start":moved["after"]["start"]}),
    );
    assert_eq!(first["overlay_removed"], false);
    reopen(&client, &name);
    let last = command(
        &client,
        "memory_block_delete",
        json!({"block_start":"bank:0x4000"}),
    );
    assert_eq!(last["overlay_removed"], true);
    reopen(&client, &name);
    client
        .script_run_source(
            include_str!("../fixtures/memory/CheckRemovedOverlay.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    check_state(&client, "2000", false);
    cleanup(&client, &name);
}

#[test]
#[serial]
fn block_lifecycle_rejects_conflicts_wrap_space_changes_and_indirect_mapping_damage() {
    require_ghidra!();
    let (client, name) = fixture();
    client
        .script_run_source(
            include_str!("../fixtures/memory/CreateBlockConstraints.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = client.memory_block_list().unwrap();
    for (start, destination, diagnostic) in [
        ("0x2000", "0x4000", "overlap"),
        ("0x2000", "0xffffffffffffff80", "overflow"),
        ("0x2000", "constraint_bank:0x6000", "same address space"),
        ("other_bank:0x2000", "other_bank:0x6000", "nonloaded"),
        ("0x2000", "0x8040", "mapped"),
        ("0x2000", "0xd000", "mapped"),
    ] {
        reject(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":destination}),
            diagnostic,
        );
    }
    for start in ["0x8000", "0x9000", "0xb000", "0xc000"] {
        reject(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":"0x10000"}),
            "mapped",
        );
        reject(
            &client,
            "memory_block_delete",
            json!({"block_start":start}),
            "mapped",
        );
    }
    assert_eq!(client.memory_block_list().unwrap(), before);
    reopen(&client, &name);
    assert_eq!(client.memory_block_list().unwrap(), before);
    check_state(&client, "2000", false);
    cleanup(&client, &name);
}

const ROLLBACK_PROBE: &str = include_str!("../fixtures/memory/BlockLifecycleRollbackProbe.java.in");

#[test]
#[serial]
fn move_and_delete_roll_back_after_native_failure_and_cancellation_and_recover_failed_saves() {
    require_ghidra!();
    let (client, name) = fixture();
    let source = ROLLBACK_PROBE.replace("/* CHECK_STATE */", CHECK_STATE);
    for operation in ["move", "delete"] {
        let folder = format!("block-rollback-{}", uuid::Uuid::new_v4());
        client
            .script_run_source(&source, &[folder.clone(), operation.into()], &[], false)
            .unwrap();
        let copied = format!("/{folder}/{name}");
        client.open_program(&copied).unwrap();
        check_state(
            &client,
            if operation == "move" { "6000" } else { "2000" },
            operation == "delete",
        );
        client.open_program(&name).unwrap();
        check_state(&client, "2000", false);
        client.program_delete(&copied).unwrap();
    }
    cleanup(&client, &name);
}
