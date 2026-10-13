use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, DaemonTestHarness};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = include_str!("../fixtures/memory/CreateBlockBasicsFixture.java");

fn with_fixture(language: &str, check: impl FnOnce(&DaemonTestHarness, &BridgeClient, &str)) {
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("block-basics-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, &[name.clone(), language.into()], &[], false)
        .unwrap();
    crate::common::with_temporary_program(&client, &name, TEST_PROGRAM, || {
        check(harness, &client, &name);
    });
}

fn cli(harness: &DaemonTestHarness, program: &str, args: &[&str]) -> Value {
    let result = ghidra(harness)
        .args(["memory", "block"])
        .args(args.iter().copied())
        .with_project(harness.project(), program)
        .json_format()
        .run();
    result.assert_success();
    result.data()
}

fn command(client: &BridgeClient, name: &str, args: Value) -> Value {
    client.send_command(name, Some(args)).unwrap()
}

fn read(client: &BridgeClient, address: &str, size: usize) -> Value {
    command(
        client,
        "read_memory",
        json!({"address": address, "size": size}),
    )
}

fn map_block(client: &BridgeClient, start: &Value) -> Value {
    client.memory_block_list().unwrap()["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["start"] == *start)
        .unwrap_or_else(|| panic!("No block at {start}"))
        .clone()
}

fn reject(client: &BridgeClient, name: &str, args: Value) {
    let before = client.memory_block_list().unwrap();
    let error = client
        .send_command(name, Some(args.clone()))
        .expect_err(&format!("Invalid mutation accepted: {name} {args}"));
    let error = error.downcast_ref::<BridgeCommandError>().unwrap();
    assert_eq!(error.detail["rolled_back"], true, "{args}: {error:?}");
    assert_eq!(client.memory_block_list().unwrap(), before, "{args}");
}

#[test]
#[serial]
fn create_distinguishes_unknown_memory_from_fill_and_persists_block_attributes() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |harness, client, program| {
        let ram = cli(
            harness,
            program,
            &[
                "create",
                ".ram",
                "--start",
                "ram:0x2000",
                "--size",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(ram["status"], "created");
        assert_eq!(ram["changed"], true);
        assert!(ram["before"].is_null());
        assert_eq!(
            ram["after"],
            json!({
                "name": ".ram", "start": "0x00002000", "end": "0x0000200f", "size": 16,
                "permissions": "rw", "initialized": false, "is_loaded": true, "address_space": "ram",
                "overlay": false, "base_space": null, "type": "default", "volatile": false
            })
        );
        let info = client.memory_info("0x2005").unwrap();
        assert_eq!(info["memory"]["initialized"], false);
        assert_eq!(info["file_mapping"]["state"], "unmapped");
        client
            .send_command("read_memory", Some(json!({"address": "0x2000", "size": 4})))
            .expect_err("Uninitialized memory must not read as zero");
        let before = client.memory_block_list().unwrap();
        client
            .memory_write("0x2000", "01020304")
            .expect_err("memory write must not initialize unknown storage");
        assert_eq!(client.memory_block_list().unwrap(), before);

        let mmio = cli(
            harness,
            program,
            &[
                "create",
                ".mmio",
                "--start",
                "ram:0x3000",
                "--size",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
                "--volatile",
                "true",
            ],
        );
        assert_eq!(mmio["after"]["volatile"], true);
        let zero = cli(
            harness,
            program,
            &[
                "create",
                ".zero",
                "--start",
                "ram:0x4000",
                "--size",
                "16",
                "--fill",
                "0x00",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(zero["after"]["initialized"], true);
        assert_eq!(read(client, "0x4000", 16)["hex"], "00".repeat(16));
        let filled = cli(
            harness,
            program,
            &[
                "create",
                ".filled",
                "--start",
                "ram:0x5000",
                "--size",
                "16",
                "--fill",
                "0xff",
                "--permissions",
                "rwx",
            ],
        );
        assert_eq!(read(client, "0x5000", 16)["hex"], "ff".repeat(16));
        assert_eq!(
            client.memory_info("0x5001").unwrap()["file_mapping"]["state"],
            "unmapped"
        );

        let permissions = cli(harness, program, &["set", "0x5000", "--permissions", "r"]);
        assert_eq!(permissions["status"], "updated");
        assert_eq!(permissions["before"], filled["after"]);
        assert_eq!(permissions["after"]["permissions"], "r");
        assert_eq!(permissions["changed"], true);
        let none = cli(
            harness,
            program,
            &["set", "0x5000", "--permissions", "none"],
        );
        assert_eq!(none["before"], permissions["after"]);
        assert_eq!(none["after"]["permissions"], "");
        let unchanged = cli(
            harness,
            program,
            &["set", "0x5000", "--permissions", "none"],
        );
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        let cleared = cli(harness, program, &["set", "0x3000", "--volatile", "false"]);
        assert_eq!(cleared["status"], "updated");
        assert_eq!(cleared["before"], mmio["after"]);
        assert_eq!(cleared["after"]["volatile"], false);
        assert_eq!(cleared["changed"], true);
        let restored = cli(harness, program, &["set", "0x3000", "--volatile", "true"]);
        assert_eq!(restored["before"], cleared["after"]);
        assert_eq!(restored["after"], mmio["after"]);
        let unchanged = cli(harness, program, &["set", "0x3000", "--volatile", "true"]);
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        for receipt in [&ram, &mmio, &zero, &none] {
            let block = &receipt["after"];
            let mapped = map_block(client, &block["start"]);
            assert_eq!(&mapped, block);
            let info = client
                .memory_info(block["start"].as_str().unwrap())
                .unwrap();
            assert_eq!(&info["memory"], block);
        }
        // Mapped blocks report initialized=false natively, but still expose the
        // initialized source bytes. Only genuinely unknown storage is unreadable.
        client
            .script_run_source(
                include_str!("../fixtures/memory/CreateBlockReadAliases.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        for (start, kind, expected) in [
            ("0x00006000", "byte_mapped", "ffffffffffffffff"),
            ("0x00007000", "bit_mapped", "0101010101010101"),
        ] {
            let mapped = map_block(client, &json!(start));
            assert_eq!(mapped["type"], kind);
            assert_eq!(mapped["initialized"], false);
            assert_eq!(read(client, start, 8)["hex"], expected);
        }
        let saved = client.memory_block_list().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_block_list().unwrap(), saved);
        assert_eq!(read(client, "0x4000", 16)["hex"], "00".repeat(16));
        assert_eq!(read(client, "0x5000", 16)["hex"], "ff".repeat(16));
        assert_eq!(
            client.memory_info("0x2000").unwrap()["memory"]["initialized"],
            false
        );
    });
}

#[test]
#[serial]
fn overlays_keep_explicit_space_identity_and_edits_require_exact_block_starts() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |harness, client, program| {
        let physical = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "--start",
                "ram:0x2000",
                "--size",
                "16",
                "--fill",
                "0x11",
                "--permissions",
                "rw",
            ],
        );
        let overlay = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "--start",
                "ram:0x2000",
                "--size",
                "16",
                "--overlay",
                "bank1",
                "--fill",
                "0x22",
                "--permissions",
                "rx",
            ],
        );
        assert_eq!(overlay["after"]["name"], physical["after"]["name"]);
        assert_eq!(overlay["after"]["start"], "bank1:0x00002000");
        assert_eq!(overlay["after"]["address_space"], "bank1");
        assert_eq!(overlay["after"]["base_space"], "ram");
        assert_eq!(overlay["after"]["overlay"], true);
        assert_eq!(read(client, "0x2000", 4)["hex"], "11111111");
        assert_eq!(read(client, "bank1:0x2000", 4)["hex"], "22222222");

        let renamed = cli(
            harness,
            program,
            &["set", "bank1:0x00002000", "--name", ".renamed"],
        );
        assert_eq!(renamed["status"], "updated");
        assert_eq!(renamed["before"], overlay["after"]);
        assert_eq!(renamed["changed"], true);
        let mut expected = overlay["after"].clone();
        expected["name"] = json!(".renamed");
        assert_eq!(renamed["after"], expected);
        assert_eq!(
            map_block(client, &physical["after"]["start"])["name"],
            ".shared"
        );
        let unchanged = cli(
            harness,
            program,
            &["set", "bank1:0x00002000", "--name", ".renamed"],
        );
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        let extra = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "--start",
                "bank1:0x4000",
                "--size",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(extra["after"]["address_space"], "bank1");
        assert_eq!(extra["after"]["base_space"], "ram");
        assert_eq!(extra["after"]["overlay"], true);
        assert_eq!(extra["after"]["start"], "bank1:0x00004000");
        let blocks = client.memory_block_list().unwrap();
        let block_count = blocks["blocks"].as_array().unwrap().len();
        // Seed, physical block, initialized overlay, and uninitialized overlay.
        assert_eq!(block_count, 4);
        assert_eq!(
            client.stats().unwrap()["stats"]["memory_blocks"],
            block_count
        );
        let changed = cli(
            harness,
            program,
            &[
                "set",
                "bank1:0x00002000",
                "--name",
                ".mmio",
                "--permissions",
                "w",
                "--volatile",
                "true",
            ],
        );
        let mut expected = renamed["after"].clone();
        expected["name"] = json!(".mmio");
        expected["permissions"] = json!("w");
        expected["volatile"] = json!(true);
        assert_eq!(changed["before"], renamed["after"]);
        assert_eq!(changed["after"], expected);
        assert_eq!(changed["status"], "updated");
        let unchanged = cli(
            harness,
            program,
            &[
                "set",
                "bank1:0x00002000",
                "--name",
                ".mmio",
                "--permissions",
                "w",
                "--volatile",
                "true",
            ],
        );
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], expected);
        assert_eq!(unchanged["after"], expected);
        let renamed = cli(
            harness,
            program,
            &["set", "bank1:0x00002000", "--name", ".renamed"],
        );
        expected["name"] = json!(".renamed");
        assert_eq!(renamed["after"], expected);
        let untouched = map_block(client, &physical["after"]["start"]);
        assert_eq!(untouched["permissions"], "rw");
        assert_eq!(untouched["volatile"], false);

        // All attributes share the exact, space-aware target validator.
        for target in ["0x2001", "block_start_symbol", ".shared", "bank1:0x2001"] {
            reject(
                client,
                "memory_block_set",
                json!({"block_start": target, "name": ".wrong", "permissions": "none", "volatile": false}),
            );
        }
        let saved = client.memory_block_list().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_block_list().unwrap(), saved);
        assert_eq!(
            client.memory_info("bank1:0x2003").unwrap()["memory"]["name"],
            ".renamed"
        );
        assert_eq!(read(client, "0x2000", 4)["hex"], "11111111");
        assert_eq!(read(client, "bank1:0x2000", 4)["hex"], "22222222");
    });
}

#[test]
#[serial]
fn creation_validation_and_collisions_leave_memory_and_overlay_spaces_unchanged() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |_, client, program| {
        let valid = json!({"name": ".valid", "start": "ram:0x2000", "size": 16,
            "uninitialized": false, "fill": 0, "permissions": "rw", "volatile": false});
        for (field, replacement) in [
            ("fill", None),
            ("uninitialized", Some(json!(true))),
            ("size", Some(json!(1.5))),
            ("size", Some(json!(0))),
            ("fill", Some(json!(256))),
            ("permissions", None),
            ("permissions", Some(json!("read"))),
            ("volatile", Some(json!("true"))),
        ] {
            let mut invalid = valid.clone();
            if let Some(value) = replacement {
                invalid[field] = value;
            } else {
                invalid.as_object_mut().unwrap().remove(field);
            }
            reject(client, "memory_block_create", invalid);
        }
        let created = command(client, "memory_block_create", valid.clone());
        assert_eq!(created["after"]["name"], ".valid");
        reject(client, "memory_block_create", valid.clone());
        let mut overlay = valid.clone();
        overlay["overlay"] = json!("bank1");
        command(client, "memory_block_create", overlay.clone());
        overlay["start"] = json!("ram:0x3000");
        reject(client, "memory_block_create", overlay.clone());
        overlay["overlay"] = json!("ram");
        reject(client, "memory_block_create", overlay.clone());
        overlay["overlay"] = json!("overflow_bank");
        overlay["start"] = json!("ram:0xffffffffffffffff");
        overlay["size"] = json!(2);
        reject(client, "memory_block_create", overlay);
        reject(client, "memory_block_set", json!({"block_start": "0x2000"}));
        for (field, value) in [
            ("name", json!("")),
            ("permissions", json!("read")),
            ("volatile", json!("false")),
            ("volatile", Value::Null),
        ] {
            let mut args = json!({"block_start": "0x2000", "name": ".changed",
                "permissions": "rx", "volatile": true});
            args[field] = value;
            reject(client, "memory_block_set", args);
        }

        // A map comparison alone would miss an empty space leaked on failed creation.
        const CHECK_SPACES: &str = include_str!("../fixtures/memory/CheckBlockSpaces.java");
        client
            .script_run_source(CHECK_SPACES, &[], &[], false)
            .unwrap();
        let saved = client.memory_block_list().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_block_list().unwrap(), saved);
        client
            .script_run_source(CHECK_SPACES, &[], &[], false)
            .unwrap();
    });
}

#[test]
#[serial]
fn block_creation_and_compound_edits_roll_back_after_native_mutations() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |_, client, program| {
        let before = client.memory_block_list().unwrap();
        let folder = format!("block-create-rollback-{}", uuid::Uuid::new_v4());
        // A separate database lets the production dispatcher own the request
        // transaction while the surrounding script retains its own session.
        client
            .script_run_source(
                include_str!("../fixtures/memory/BlockCreateRollbackProbe.java"),
                std::slice::from_ref(&folder),
                &[],
                false,
            )
            .unwrap();
        let copied = format!("/{folder}/{program}");
        client.open_program(&copied).unwrap();
        assert_eq!(client.memory_block_list().unwrap(), before);
        client
            .script_run_source(
                include_str!("../fixtures/memory/CheckReopenedCancelledOverlay.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        client.open_program(program).unwrap();
        client.program_delete(&copied).unwrap();
    });
}

#[test]
#[serial]
fn block_sizes_count_bytes_in_word_and_segmented_spaces_and_starts_round_trip() {
    require_ghidra!();
    for (language, start, expected_offset) in [
        ("avr8:LE:16:default", "0x1000.1", "2001"),
        ("x86:LE:16:Real Mode", "ram:0x0200:0x0001", "2001"),
    ] {
        with_fixture(language, |_, client, program| {
            let created = command(
                client,
                "memory_block_create",
                json!({
                    "name": ".odd", "start": start, "size": 3, "uninitialized": false,
                    "fill": 165, "permissions": "rw", "volatile": false
                }),
            );
            assert_eq!(created["after"]["size"], 3);
            let returned_start = created["after"]["start"].as_str().unwrap();
            assert_eq!(read(client, returned_start, 3)["hex"], "a5a5a5");
            let renamed = command(
                client,
                "memory_block_set",
                json!({
                    "block_start": returned_start, "name": ".renamed_odd"
                }),
            );
            assert_eq!(renamed["before"], created["after"]);
            assert_eq!(renamed["after"]["start"], created["after"]["start"]);
            assert_eq!(renamed["after"]["end"], created["after"]["end"]);
            const CHECK_BYTES: &str = include_str!("../fixtures/memory/CheckBlockByteSize.java");
            client
                .script_run_source(CHECK_BYTES, &[expected_offset.into()], &[], false)
                .unwrap();
            let saved = client.memory_block_list().unwrap();
            client.program_close().unwrap();
            client.open_program(program).unwrap();
            assert_eq!(client.memory_block_list().unwrap(), saved);
            client
                .script_run_source(CHECK_BYTES, &[expected_offset.into()], &[], false)
                .unwrap();
        });
    }
}

#[test]
#[serial]
fn creating_backing_memory_preserves_existing_mapped_data() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |_, client, program| {
        const CHECK_MAPPED_POINTER: &str =
            include_str!("../fixtures/memory/CheckCreationMappedPointer.java");
        client
            .script_run_source(CHECK_MAPPED_POINTER, &["create".into()], &[], false)
            .unwrap();
        // Filling this source would make the pointer readable without updating
        // its default reference, leaving saved data and xrefs inconsistent.
        reject(
            client,
            "memory_block_create",
            json!({"name": ".backing", "start": "0x4000", "size": 8,
                "fill": 17, "permissions": "rw"}),
        );
        command(
            client,
            "memory_block_create",
            json!({"name": ".isolated", "start": "0x4000", "size": 8,
                "fill": 17, "permissions": "rw", "overlay": "isolated"}),
        );
        command(
            client,
            "memory_block_create",
            json!({"name": ".unknown", "start": "0x4000", "size": 8,
                "uninitialized": true, "permissions": "rw"}),
        );
        let saved = client.memory_block_list().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_block_list().unwrap(), saved);
        client
            .script_run_source(CHECK_MAPPED_POINTER, &["check".into()], &[], false)
            .unwrap();
    });
}
