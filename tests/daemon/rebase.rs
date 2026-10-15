use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = include_str!("../fixtures/daemon/CreateRebaseFixture.java");

const CHECK_FIXTURE: &str = include_str!("../fixtures/daemon/CheckRebaseFixture.java");

fn create_fixture(client: &BridgeClient, language: &str) -> String {
    let name = format!("rebase-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, &[name.clone(), language.into()], &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    name
}

fn check_fixture(client: &BridgeClient, byte_base: &str) {
    client
        .script_run_source(CHECK_FIXTURE, &[byte_base.into()], &[], false)
        .unwrap();
}

fn rebase(client: &BridgeClient, base: &str) -> Value {
    client
        .send_command("program_rebase", Some(json!({"base":base})))
        .unwrap()
}

fn reject_rebase(client: &BridgeClient, base: &str, expected: &str) {
    let error = client
        .send_command("program_rebase", Some(json!({"base":base})))
        .unwrap_err();
    assert!(error.to_string().contains(expected), "{error}");
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["rolled_back"], true);
    assert!(detail.get("partial_changes_saved").is_none());
}

#[test]
#[serial]
fn rebase_preserves_native_metadata_and_pointer_bytes_after_reopen() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client, "x86:LE:64:default");
    check_fixture(&client, "1000");
    let result = rebase(&client, "0x5000");
    assert_eq!(result["old_base"], "0x00001000");
    assert_eq!(result["new_base"], "0x00005000");
    assert_eq!(result["delta_bytes"], "16384");
    let moved = result["moved_blocks"].as_array().unwrap();
    assert_eq!(moved.len(), 4);
    assert!(
        moved.contains(&json!({"name":"code", "old_start":"0x00002000",
        "old_end":"0x000020ff", "new_start":"0x00006000", "new_end":"0x000060ff"}))
    );
    assert!(
        moved.contains(&json!({"name":"mmio", "old_start":"0x00005000",
        "old_end":"0x0000500f", "new_start":"0x00009000", "new_end":"0x0000900f"}))
    );
    assert_eq!(
        result["unchanged_blocks"],
        json!([{"name":"rebase_overlay",
        "start":"rebase_overlay:0x00002000", "end":"rebase_overlay:0x0000201f", "reason":"overlay"}])
    );
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "5000");

    let unchanged = rebase(&client, "0x5000");
    assert_eq!(unchanged["delta_bytes"], "0");
    assert_eq!(unchanged["moved_blocks"], json!([]));
    assert_eq!(unchanged["unchanged_blocks"].as_array().unwrap().len(), 5);
    assert_eq!(
        unchanged["unchanged_blocks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|block| block["reason"] == "same_base")
            .count(),
        4
    );
    for (base, message) in [
        ("rebase_function", "explicit address"),
        ("rebase_overlay:0x2000", "default address space"),
        ("0x10000000000000000", "Invalid address"),
        // Both cases can otherwise wrap a block start while leaving its end in range.
        ("0x0", "wrap or exceed"),
        ("0xffffffffffffd000", "wrap or exceed"),
    ] {
        reject_rebase(&client, base, message);
        check_fixture(&client, "5000");
    }

    // These deltas exceed the signed-long range in both directions.
    let high = rebase(&client, "0xf000000000001000");
    assert_eq!(
        high["delta_bytes"],
        (0xf000000000001000_i128 - 0x5000).to_string()
    );
    check_fixture(&client, "f000000000001000");
    let low = rebase(&client, "0x1000");
    assert_eq!(
        low["delta_bytes"],
        (0x1000_i128 - 0xf000000000001000_i128).to_string()
    );
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "1000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
}

#[test]
#[serial]
fn rebase_uses_byte_deltas_for_word_and_segmented_spaces() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let word = create_fixture(&client, "avr8:LE:16:default");
    let result = rebase(&client, "0x1800.1");
    assert_eq!(result["delta_bytes"], "8193");
    assert!(result["new_base"].as_str().unwrap().ends_with("0x1800.1"));
    let other = result["unchanged_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|block| block["name"] == "other")
        .unwrap();
    assert_eq!(other["reason"], "other_address_space");
    assert!(other["start"].as_str().unwrap().ends_with("0x2000"));
    check_fixture(&client, "3001");
    reject_rebase(&client, "0xffff", "wrap or exceed");
    client.program_close().unwrap();
    client.open_program(&word).unwrap();
    check_fixture(&client, "3001");

    let segmented = create_fixture(&client, "x86:LE:16:Real Mode");
    let result = rebase(&client, "ram:0x0200:0x0000");
    assert_eq!(result["old_base"], "ram:0x0100:0x0000");
    assert_eq!(result["new_base"], "ram:0x0200:0x0000");
    assert_eq!(result["delta_bytes"], "4096");
    check_fixture(&client, "2000");
    reject_rebase(&client, "ram:0x0200:0x0001", "zero segment offset");
    reject_rebase(&client, "ram:0xffff:0x0000", "wrap or exceed");
    client.program_close().unwrap();
    client.open_program(&segmented).unwrap();
    check_fixture(&client, "2000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&word).unwrap();
    client.program_delete(&segmented).unwrap();
}

#[test]
#[serial]
fn rebase_rolls_back_native_mutation_on_error_and_cancellation() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client, "x86:LE:64:default");
    let folder = format!("rebase-rollback-{}", uuid::Uuid::new_v4());
    // Invoke the real dispatcher with a Program proxy that fails only after
    // native setImageBase has actually changed the separate test database.
    client
        .script_run_source(
            include_str!("../fixtures/daemon/RebaseRollbackProbe.java"),
            std::slice::from_ref(&folder),
            &[],
            false,
        )
        .unwrap();
    let copied = format!("/{folder}/{name}");
    client.open_program(&copied).unwrap();
    check_fixture(&client, "5000");
    client.open_program(&name).unwrap();
    check_fixture(&client, "1000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    client.program_delete(&copied).unwrap();
}

#[test]
#[serial]
fn rebase_rejects_wrapping_unmapped_metadata_while_blocks_fit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    const METADATA: &str = include_str!("../fixtures/daemon/UnmappedRebaseMetadata.java");
    for kind in [
        "symbol",
        "reference source",
        "reference destination",
        "comment",
        "register context",
        "bookmark",
        "user property",
        "relocation",
        "equate reference",
        "function body",
        "byte-mapped source",
        "bit-mapped source",
        "overlay mapped source",
        "byte-mapped source end",
    ] {
        let name = create_fixture(&client, "x86:LE:64:default");
        client
            .script_run_source(METADATA, &[kind.into()], &[], false)
            .unwrap();
        let before = client.memory_block_list().unwrap();
        if kind == "symbol" {
            assert_eq!(rebase(&client, "0x1000")["moved_blocks"], json!([]));
        }
        let expected = if kind.contains("mapped source") {
            "mapped source"
        } else {
            kind
        };
        reject_rebase(&client, "0x5000", expected);
        assert_eq!(client.memory_block_list().unwrap(), before);
        assert_eq!(client.program_info().unwrap()["image_base"], "0x00001000");
        client.program_close().unwrap();
        client.open_program(&name).unwrap();
        reject_rebase(&client, "0x5000", expected);
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&name).unwrap();
    }

    let name = create_fixture(&client, "x86:LE:64:default");
    client
        .script_run_source(METADATA, &["pinned".into()], &[], false)
        .unwrap();
    rebase(&client, "0x5000");
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "5000");
    client
        .script_run_source(METADATA, &["check pinned".into()], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
}

#[test]
#[serial]
fn rebase_preserves_mapped_sources_in_moving_and_stationary_blocks() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client, "x86:LE:64:default");
    const MAPPINGS: &str = include_str!("../fixtures/daemon/RebaseMappedSources.java");
    client
        .script_run_source(MAPPINGS, &["create".into()], &[], false)
        .unwrap();
    rebase(&client, "0x5000");
    client
        .script_run_source(MAPPINGS, &["check".into()], &[], false)
        .unwrap();
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    client
        .script_run_source(MAPPINGS, &["check".into()], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
}

#[test]
#[serial]
fn rebase_rejects_wrapping_range_property_maps_while_blocks_fit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    const RANGE_MAP: &str = include_str!("../fixtures/daemon/RebaseRangePropertyMaps.java");
    for kind in ["address set", "integer range"] {
        // Both ranges straddle the edge of the wrapping interval, rather than
        // starting within it. Native range iterators must detect that overlap.
        for (offset, base) in [("ffffffffffffbff8", "0x5000"), ("7f8", "0x800")] {
            let name = create_fixture(&client, "x86:LE:64:default");
            client
                .script_run_source(
                    RANGE_MAP,
                    &[kind.into(), offset.into(), "create".into()],
                    &[],
                    false,
                )
                .unwrap();
            let before = client.memory_block_list().unwrap();
            for reopen in [false, true] {
                if reopen {
                    client.program_close().unwrap();
                    client.open_program(&name).unwrap();
                }
                reject_rebase(&client, base, "range property");
                assert_eq!(client.memory_block_list().unwrap(), before);
                assert_eq!(client.program_info().unwrap()["image_base"], "0x00001000");
                client
                    .script_run_source(
                        RANGE_MAP,
                        &[kind.into(), offset.into(), "check".into()],
                        &[],
                        false,
                    )
                    .unwrap();
            }
            client.open_program(TEST_PROGRAM).unwrap();
            client.program_delete(&name).unwrap();
        }

        let name = create_fixture(&client, "x86:LE:64:default");
        client
            .script_run_source(
                RANGE_MAP,
                &[kind.into(), "8000".into(), "create".into()],
                &[],
                false,
            )
            .unwrap();
        rebase(&client, "0x5000");
        client.program_close().unwrap();
        client.open_program(&name).unwrap();
        client
            .script_run_source(
                RANGE_MAP,
                &[kind.into(), "c000".into(), "check".into()],
                &[],
                false,
            )
            .unwrap();
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&name).unwrap();
    }
}
