//! Memory-reference edits against native Ghidra reference storage.

use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;

static HARNESS: OnceLock<common::DaemonTestHarness> = OnceLock::new();
const FIXTURE: &str = include_str!("xref/XrefMutationFixture.java");

fn fixture(check: impl FnOnce(&BridgeClient)) {
    require_ghidra!();
    let harness = HARNESS.get_or_init(|| {
        common::ensure_test_project(common::test_project(), common::FIXTURE_PROGRAM);
        common::DaemonTestHarness::new(common::test_project(), common::FIXTURE_PROGRAM).unwrap()
    });
    let client = harness.client().unwrap();
    let name = format!("xref-mutation-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(FIXTURE, &["create".to_owned(), name.clone()], &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&client)));
    client.open_program(common::FIXTURE_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn reopen(client: &BridgeClient) {
    let program = client.send_command("program_info", None).unwrap();
    client.program_close().unwrap();
    client
        .open_program(program["name"].as_str().unwrap())
        .unwrap();
}

fn target(from: &str, to: &str, operand: i32) -> Value {
    json!({"from": from, "to": to, "operand_index": operand})
}

fn create(client: &BridgeClient, from: &str, to: &str, operand: i32, kind: &str) -> Value {
    let mut args = target(from, to, operand);
    args["ref_type"] = json!(kind);
    client
        .send_command("xref_create_memory", Some(args))
        .unwrap()
}

fn from(client: &BridgeClient, address: &str) -> Vec<Value> {
    client.xrefs_from(address.to_owned(), false).unwrap()["xrefs"]
        .as_array()
        .unwrap()
        .clone()
}

fn reference(rows: &[Value], destination: &str, operand: i32) -> Value {
    rows.iter()
        .find(|row| row["to"] == destination && row["operand_index"] == operand)
        .unwrap_or_else(|| panic!("Missing {destination}/{operand}: {rows:?}"))
        .clone()
}

fn assert_directions(client: &BridgeClient, address: &str) {
    for outgoing in from(client, address) {
        let incoming = client
            .xrefs_to(outgoing["to"].as_str().unwrap().to_owned())
            .unwrap();
        // Incoming queries also display destination labels when no function exists.
        // The reference identity and metadata must agree in both directions.
        assert!(
            incoming["xrefs"].as_array().unwrap().iter().any(|row| {
                [
                    "from",
                    "to",
                    "operand_index",
                    "ref_type",
                    "source",
                    "primary",
                ]
                .iter()
                .all(|field| row[field] == outgoing[field])
            }),
            "Outgoing reference missing from incoming query: {outgoing}; {incoming}"
        );
    }
}

#[test]
#[serial]
fn memory_xrefs_preserve_operands_and_round_trip_saved_edits() {
    fixture(|client| {
        for operand in [-1, 0, 1] {
            let result = create(client, "0x1000", "0x9000", operand, "READ_WRITE");
            assert_eq!(result["changed"], true);
            assert_eq!(result["count"], 1);
            assert!(result["before"].is_null());
            assert_eq!(result["after"]["operand_index"], operand);
            assert_eq!(result["after"]["source"], "USER_DEFINED");
            let repeated = create(client, "0x1000", "0x9000", operand, "read_write");
            assert_eq!(repeated["changed"], false);
            assert_eq!(repeated["before"], repeated["after"]);
        }
        assert_eq!(from(client, "0x1000").len(), 3);
        assert_directions(client, "0x1000");
        let deleted = client
            .send_command("xref_delete", Some(target("0x1000", "0x9000", 0)))
            .unwrap();
        assert_eq!(deleted["count"], 1);
        assert_eq!(deleted["before"]["operand_index"], 0);
        assert!(deleted["after"].is_null());
        assert_eq!(
            client
                .send_command("xref_delete", Some(target("0x1000", "0x9000", 0)))
                .unwrap()["count"],
            0
        );
        let rows = from(client, "0x1000");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["operand_index"] != 0));
        reopen(client);
        assert_eq!(from(client, "0x1000"), rows);
        assert_directions(client, "0x1000");
    });
}

#[test]
#[serial]
fn primary_changes_only_one_operand_and_reports_the_previous_source() {
    fixture(|client| {
        let original = from(client, "0x1010");
        let result = client
            .send_command("xref_set_primary", Some(target("0x1010", "0x2010", 0)))
            .unwrap();
        assert_eq!(result["changed"], true);
        let before = result["before"].as_array().unwrap();
        let after = result["after"].as_array().unwrap();
        assert_eq!(before.len(), 2);
        assert_eq!(reference(before, "0x00002000", 0)["source"], "ANALYSIS");
        assert_eq!(reference(before, "0x00002000", 0)["primary"], true);
        assert_eq!(reference(after, "0x00002000", 0)["primary"], false);
        assert_eq!(reference(after, "0x00002010", 0)["primary"], true);
        assert_eq!(
            reference(&from(client, "0x1010"), "0x00002000", 1),
            reference(&original, "0x00002000", 1)
        );
        assert_eq!(
            client
                .send_command("xref_set_primary", Some(target("0x1010", "0x2010", 0)))
                .unwrap()["changed"],
            false
        );
        assert_directions(client, "0x1010");
        reopen(client);
        assert_eq!(
            reference(&from(client, "0x1010"), "0x00002010", 0)["primary"],
            true
        );
        assert_directions(client, "0x1010");
        let mut args = target("0x1010", "0x2000", 0);
        args["source"] = json!("analysis");
        assert_eq!(
            client.send_command("xref_set_primary", Some(args)).unwrap()["changed"],
            true
        );
        for (site, source) in [
            ("0x1050", "analysis"),
            ("0x1060", "IMPORTED"),
            ("0x1070", "DEFAULT"),
        ] {
            let mut args = target(site, "0x2000", 0);
            args["source"] = json!(source);
            assert_eq!(
                client.send_command("xref_delete", Some(args)).unwrap()["count"],
                1
            );
            assert!(from(client, site).is_empty());
        }
        reopen(client);
        assert_eq!(
            reference(&from(client, "0x1010"), "0x00002000", 0)["primary"],
            true
        );
        for site in ["0x1050", "0x1060", "0x1070"] {
            assert!(from(client, site).is_empty());
        }
    });
}

#[test]
#[serial]
fn reference_collisions_preserve_native_types_sources_and_other_operands() {
    fixture(|client| {
        create(client, "0x1000", "0x2000", 0, "READ");
        for (verb, args, fragment) in [
            (
                "xref_create_memory",
                json!({"from":"0x1000","to":"0x2000","operand_index":0,"ref_type":"WRITE"}),
                "different ref_type",
            ),
            (
                "xref_create_memory",
                json!({"from":"0x1050","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
                "different ref_type",
            ),
            (
                "xref_delete",
                target("0x1050", "0x2000", 0),
                "source mismatch",
            ),
            (
                "xref_set_primary",
                target("0x1050", "0x2000", 0),
                "source mismatch",
            ),
            (
                "xref_create_memory",
                json!({"from":"0x1020","to":"0x2010","operand_index":0,"ref_type":"DATA"}),
                "non-memory",
            ),
            (
                "xref_create_memory",
                json!({"from":"0x1020","to":"0x2010","operand_index":1,"ref_type":"DATA"}),
                "non-memory",
            ),
            (
                "xref_create_memory",
                json!({"from":"0x1030","to":"0x2004","operand_index":0,"ref_type":"DATA"}),
                "ordinary memory",
            ),
            (
                "xref_delete",
                target("0x1030", "0x2004", 0),
                "ordinary memory",
            ),
            (
                "xref_set_primary",
                target("0x1030", "0x2010", 0),
                "ordinary memory",
            ),
            (
                "xref_create_memory",
                json!({"from":"0x1040","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
                "ordinary memory",
            ),
            (
                "xref_delete",
                target("0x1040", "0x2000", 0),
                "ordinary memory",
            ),
            (
                "xref_set_primary",
                target("0x1040", "0x2010", 0),
                "ordinary memory",
            ),
            (
                "xref_delete",
                target("0x10a0", "0x2000", -1),
                "instruction flow",
            ),
            (
                "xref_set_primary",
                target("0x10a0", "0x2000", -1),
                "instruction flow",
            ),
            (
                "xref_set_primary",
                target("0x10a0", "0x2010", -1),
                "instruction flow",
            ),
            (
                "xref_delete",
                target("0x10b0", "0x2000", -1),
                "instruction flow",
            ),
            (
                "xref_set_primary",
                target("0x10b0", "0x2000", -1),
                "instruction flow",
            ),
            (
                "xref_set_primary",
                target("0x10b0", "0x2010", -1),
                "instruction flow",
            ),
        ] {
            let site = args["from"].as_str().unwrap().to_owned();
            let before = from(client, &site);
            let error = client.send_command(verb, Some(args)).unwrap_err();
            assert!(error.to_string().contains(fragment), "{error}");
            let detail = &error
                .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
                .unwrap()
                .detail;
            assert_eq!(detail["rolled_back"], true);
            assert!(detail["reference"]["source"].is_string());
            if fragment == "source mismatch" {
                assert_eq!(detail["reference"]["source"], "ANALYSIS");
            }
            assert_eq!(from(client, &site), before);
        }
        // Special references on other operands or destinations are preserved on creation.
        create(client, "0x1020", "0x2010", -1, "DATA");
        create(client, "0x1030", "0x2020", 0, "DATA");
        create(client, "0x1040", "0x2020", 0, "DATA");
        create(client, "0x10b0", "0x2020", -1, "DATA");
        client
            .script_run_source(FIXTURE, &["verify-special".to_owned()], &[], false)
            .unwrap();
        reopen(client);
        client
            .script_run_source(FIXTURE, &["verify-special".to_owned()], &[], false)
            .unwrap();
    });
}

#[test]
#[serial]
fn memory_reference_validation_rejects_wrong_targets_before_mutating() {
    fixture(|client| {
        for args in [
            json!({"from":"xref_site","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1001","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1101","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1110","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"xref_site","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"EXTERNAL:0x1","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x100000000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":2,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":4294967296_u64,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":0.5,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":-2,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","ref_type":"DATA"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":0,"ref_type":"FALL_THROUGH"}),
            json!({"from":"0x1000","to":"0x2000","operand_index":0,"ref_type":"DATA","source":"ANALYSIS"}),
            json!({"from":"0x1080","to":"0x2000","operand_index":0,"ref_type":"DATA"}),
            json!({"from":"0x1100","to":"0x2000","operand_index":0,"ref_type":"COMPUTED_CALL"}),
            json!({"from":"0x1100","to":"0x2000","operand_index":1,"ref_type":"DATA"}),
            json!({"from":"0x1000","to":"overlay:0x4000","operand_index":0,"ref_type":"DATA"}),
        ] {
            assert!(
                client
                    .send_command("xref_create_memory", Some(args.clone()))
                    .is_err(),
                "{args}"
            );
            assert!(from(client, "0x1000").is_empty());
            assert!(from(client, "0x1080").is_empty());
            assert!(from(client, "0x1100").is_empty());
        }
        assert!(client
            .send_command("xref_set_primary", Some(target("0x1000", "0x9000", 0)))
            .is_err());
        create(client, "0x1080", "0x2000", -1, "DATA");
        create(client, "0x1100", "0x9000", 0, "INDIRECTION");
        assert_eq!(
            create(client, "0x1000", "overlay:0x3000", 0, "DATA")["after"]["to"],
            "overlay:0x00003000"
        );
        for (i, kind) in [
            "DATA",
            "READ",
            "WRITE",
            "READ_WRITE",
            "INDIRECTION",
            "UNCONDITIONAL_CALL",
            "CONDITIONAL_CALL",
            "COMPUTED_CALL",
            "UNCONDITIONAL_JUMP",
            "CONDITIONAL_JUMP",
            "COMPUTED_JUMP",
        ]
        .iter()
        .enumerate()
        {
            let result = create(client, "0x1090", &format!("0x{:x}", 0x9000 + i), 0, kind);
            assert_eq!(result["after"]["ref_type"], *kind);
        }
        reopen(client);
        assert_eq!(from(client, "0x1090").len(), 11);
        assert_eq!(from(client, "0x1100")[0]["to"], "0x00009000");
        assert_directions(client, "0x1000");
        assert_directions(client, "0x1090");
    });
}
