//! Equate definitions, exact operand selection, native reference preservation, and persistence.

#[macro_use]
mod common;

use common::{ensure_test_project, test_project, DaemonTestHarness, FIXTURE_PROGRAM};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), FIXTURE_PROGRAM);
        DaemonTestHarness::new(test_project(), FIXTURE_PROGRAM).expect("Failed to start bridge")
    })
}

fn fixture(test: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    let name = format!("equates-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("equates/CreateEquateFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&client, &name)));
    client.open_program(FIXTURE_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn run(client: &BridgeClient, command: &str, args: Value) -> Value {
    client.send_command(command, Some(args)).unwrap()
}

fn get(client: &BridgeClient, name: &str) -> Value {
    run(client, "equate_get", json!({"name":name}))
}

fn create(client: &BridgeClient, name: &str, value: &str) -> Value {
    run(client, "equate_create", json!({"name":name,"value":value}))
}

fn attach(client: &BridgeClient, name: &str, address: &str, operand: u32) -> Value {
    run(
        client,
        "equate_attach",
        json!({"name":name,"address":address,"operand_index":operand}),
    )
}

fn rejected(client: &BridgeClient, command: &str, args: Value) -> Value {
    let error = client.send_command(command, Some(args)).unwrap_err();
    let bridge = error.downcast_ref::<BridgeCommandError>().unwrap();
    assert_eq!(bridge.detail["rolled_back"], true, "{bridge:?}");
    bridge.detail.clone()
}

#[test]
#[serial]
fn definitions_preserve_integer_precision_and_reject_conflicting_or_overflowing_values() {
    require_ghidra!();
    fixture(|client, _| {
        for (name, value, hex, signed) in [
            (
                "PRECISE",
                "9007199254740993",
                "0x20000000000001",
                "9007199254740993",
            ),
            ("MINUS_ONE", "-1", "0xffffffffffffffff", "-1"),
            (
                "MINIMUM",
                "-9223372036854775808",
                "0x8000000000000000",
                "-9223372036854775808",
            ),
            ("BYTE", "0xff", "0xff", "255"),
            ("POSITIVE", "+1", "0x1", "1"),
        ] {
            let receipt = create(client, name, value);
            assert_eq!(receipt["created"], true);
            assert_eq!(receipt["value"], hex);
            assert_eq!(receipt["signed_value"], signed);
            assert_eq!(receipt["reference_count"], 0);
            assert_eq!(get(client, name)["references"], json!([]));
        }
        assert_eq!(
            create(client, "MINUS_ONE", "0xffffffffffffffff")["created"],
            false
        );
        let before = get(client, "PRECISE");
        rejected(
            client,
            "equate_create",
            json!({"name":"PRECISE","value":"9007199254740992"}),
        );
        assert_eq!(get(client, "PRECISE"), before);
        for value in [
            json!("9223372036854775808"),
            json!("-9223372036854775809"),
            json!("0x10000000000000000"),
            json!(9007199254740993u64),
            json!("1.5"),
        ] {
            rejected(
                client,
                "equate_create",
                json!({"name":"INVALID","value":value}),
            );
        }
        assert!(client
            .send_command("equate_get", Some(json!({"name":"INVALID"})))
            .is_err());
        let listed = run(client, "equate_list", json!({"limit":0}));
        let rows = listed["equates"].as_array().unwrap();
        assert_eq!(listed["count"], rows.len());
        let names: Vec<_> = rows
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert_eq!(
            run(client, "equate_list", json!({"limit":1}))["equates"],
            json!(rows[..1])
        );
        let enum_name = rows.iter().find(|row| row["kind"] == "enum").unwrap()["name"]
            .as_str()
            .unwrap();
        assert_eq!(get(client, enum_name)["kind"], "enum");
        for command in ["equate_attach", "equate_detach", "equate_delete"] {
            rejected(
                client,
                command,
                json!({"name":enum_name,"address":"0x1000","operand_index":1}),
            );
        }
        rejected(
            client,
            "equate_create",
            json!({"name":"dtID:123:42","value":"42"}),
        );
        assert_eq!(get(client, enum_name)["kind"], "enum");
    });
}

#[test]
#[serial]
fn attaching_matches_scalar_signedness_and_width_without_truncation() {
    require_ghidra!();
    fixture(|client, _| {
        for (name, value, address) in [
            ("BYTE", "255", "0x1010"),
            ("DWORD", "0xffffffff", "0x1020"),
            ("NEGATIVE", "-1", "0x1040"),
            ("QWORD", "0xffffffffffffffff", "0x1030"),
            ("PRECISE", "9007199254740993", "0x1050"),
        ] {
            create(client, name, value);
            assert_eq!(attach(client, name, address, 1)["attached"], 1);
            assert_eq!(attach(client, name, address, 1)["attached"], 0);
            assert_eq!(get(client, name)["reference_count"], 1);
            assert_eq!(
                get(client, name)["references"][0]["operand_selectable"],
                true
            );
        }
        create(client, "TOO_WIDE", "0x1ff");
        for (name, address) in [
            ("NEGATIVE", "0x1010"),
            ("BYTE", "0x1040"),
            ("TOO_WIDE", "0x1010"),
        ] {
            let detail = rejected(
                client,
                "equate_attach",
                json!({"name":name,"address":address,"operand_index":1}),
            );
            assert!(!detail["candidates"].as_array().unwrap().is_empty());
        }
        assert_eq!(get(client, "TOO_WIDE")["reference_count"], 0);
        assert_eq!(get(client, "BYTE")["reference_count"], 1);
        assert_eq!(get(client, "NEGATIVE")["reference_count"], 1);
    });
}

#[test]
#[serial]
fn ambiguous_operands_and_conflicts_preserve_all_existing_attachments() {
    require_ghidra!();
    fixture(|client, _| {
        create(client, "ANSWER", "42");
        create(client, "ALIAS", "42");
        create(client, "EIGHT", "8");
        create(client, "THIRTY_TWO", "32");
        attach(client, "ANSWER", "0x1000", 1);
        let before = get(client, "ANSWER");
        rejected(
            client,
            "equate_attach",
            json!({"name":"ALIAS","address":"0x1000","operand_index":1}),
        );
        assert_eq!(get(client, "ANSWER"), before);
        assert_eq!(get(client, "ALIAS")["reference_count"], 0);
        for (name, address, operand) in [("EIGHT", "0x1070", 0), ("THIRTY_TWO", "0x1080", 1)] {
            let detail = rejected(
                client,
                "equate_attach",
                json!({"name":name,"address":address,"operand_index":operand}),
            );
            assert_eq!(detail["candidates"].as_array().unwrap().len(), 2);
            assert_eq!(get(client, name)["reference_count"], 0);
        }
        for (address, operand) in [
            ("0x1001", json!(1)),
            ("0x1800", json!(0)),
            ("0x1000", json!(-1)),
            ("0x1000", json!(2147483648u64)),
            ("0x1000", json!(0)),
            ("0x1000", json!(2)),
            ("0x1000", Value::Null),
        ] {
            rejected(
                client,
                "equate_attach",
                json!({"name":"ALIAS","address":address,"operand_index":operand}),
            );
        }
        // Two distinct scalar operands can each keep their own definition.
        attach(client, "THIRTY_TWO", "0x1090", 0);
        let first = get(client, "THIRTY_TWO");
        attach(client, "EIGHT", "0x1090", 1);
        assert_eq!(get(client, "THIRTY_TWO"), first);
        assert_eq!(get(client, "EIGHT")["reference_count"], 1);
        // Existing native uses remain distinguishable by operand even when
        // creating another application would have ambiguous scalar correspondence.
        assert_eq!(get(client, "NATIVE_REPEATED")["reference_count"], 2);
        let detached = run(
            client,
            "equate_detach",
            json!({"name":"NATIVE_REPEATED","address":"0x1070","operand_index":0}),
        );
        assert_eq!(detached["detached"], 1);
        let remaining = get(client, "NATIVE_REPEATED");
        assert_eq!(remaining["reference_count"], 1);
        assert_eq!(remaining["references"][0]["operand_index"], 1);
    });
}

#[test]
#[serial]
fn native_dynamic_hash_collisions_preserve_other_operands_and_dynamic_only_uses() {
    require_ghidra!();
    fixture(|client, _| {
        create(client, "ANSWER", "42");
        let collateral = get(client, "COLLATERAL");
        assert_eq!(collateral["references"][0]["operand_index"], 0);
        assert_ne!(collateral["references"][0]["dynamic_hash"], "0x0");
        let detail = rejected(
            client,
            "equate_attach",
            json!({"name":"ANSWER","address":"0x10a0","operand_index":1}),
        );
        assert_eq!(detail["references"][0]["name"], "COLLATERAL");
        assert_eq!(get(client, "COLLATERAL"), collateral);
        let dynamic = get(client, "DYNAMIC_ONLY");
        assert_eq!(dynamic["reference_count"], 2);
        for reference in dynamic["references"].as_array().unwrap() {
            assert_eq!(reference["operand_index"], Value::Null);
            assert_eq!(reference["operand_selectable"], false);
            assert_ne!(reference["dynamic_hash"], "0x0");
        }
        rejected(
            client,
            "equate_attach",
            json!({"name":"ANSWER","address":"0x10b0","operand_index":1}),
        );
        rejected(
            client,
            "equate_detach",
            json!({"name":"DYNAMIC_ONLY","address":"0x10b0","operand_index":1}),
        );
        assert_eq!(get(client, "DYNAMIC_ONLY"), dynamic);
        assert_eq!(get(client, "ANSWER")["reference_count"], 0);
        assert_eq!(
            run(client, "equate_delete", json!({"name":"DYNAMIC_ONLY"}))["references_removed"],
            2
        );
        assert!(client
            .send_command("equate_get", Some(json!({"name":"DYNAMIC_ONLY"})))
            .is_err());
        assert_eq!(attach(client, "ANSWER", "0x10b0", 1)["attached"], 1);
        assert_eq!(get(client, "COLLATERAL"), collateral);
    });
}

#[test]
#[serial]
fn exact_detach_keeps_definition_and_other_uses_while_global_delete_survives_reopen() {
    require_ghidra!();
    fixture(|client, program| {
        create(client, "ANSWER", "42");
        attach(client, "ANSWER", "0x1000", 1);
        attach(client, "ANSWER", "0x1060", 1);
        let detached = run(
            client,
            "equate_detach",
            json!({"name":"ANSWER","address":"0x1000","operand_index":1}),
        );
        assert_eq!(detached["detached"], 1);
        assert_eq!(detached["reference_count"], 1);
        assert_eq!(
            run(
                client,
                "equate_detach",
                json!({"name":"ANSWER","address":"0x1000","operand_index":1})
            )["detached"],
            0
        );
        assert_eq!(
            get(client, "ANSWER")["references"][0]["address"],
            "0x00001060"
        );
        rejected(
            client,
            "equate_detach",
            json!({"name":"MISSING","address":"0x1000","operand_index":1}),
        );
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "ANSWER")["reference_count"], 1);
        run(
            client,
            "equate_detach",
            json!({"name":"ANSWER","address":"0x1060","operand_index":1}),
        );
        assert_eq!(get(client, "ANSWER")["reference_count"], 0);
        assert_eq!(get(client, "ANSWER")["value"], "0x2a");
        attach(client, "ANSWER", "0x1000", 1);
        attach(client, "ANSWER", "0x1060", 1);
        let collateral = get(client, "COLLATERAL");
        assert_eq!(
            run(client, "equate_delete", json!({"name":"ANSWER"}))["references_removed"],
            2
        );
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert!(client
            .send_command("equate_get", Some(json!({"name":"ANSWER"})))
            .is_err());
        assert_eq!(get(client, "COLLATERAL"), collateral);
        create(client, "REUSED", "42");
        assert_eq!(attach(client, "REUSED", "0x1000", 1)["attached"], 1);
        assert_eq!(attach(client, "REUSED", "0x1060", 1)["attached"], 1);
    });
}
