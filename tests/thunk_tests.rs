//! Native thunk relations, visible signatures, rollback, and saved definitions.

#[macro_use]
mod common;

use common::{ensure_test_project, test_project, DaemonTestHarness};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), common::FIXTURE_PROGRAM);
        DaemonTestHarness::new(test_project(), common::FIXTURE_PROGRAM).expect("start thunk bridge")
    })
}

fn with_fixture(check: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    let program = format!("thunk-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("fixtures/thunk/CreateThunkFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let checked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&client, &program)));
    client.open_program(common::FIXTURE_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn command(program: &str, args: &[&str]) -> Value {
    let result = common::ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .json_format()
        .run();
    result.assert_success();
    result.data()
}

fn get(client: &BridgeClient, target: &str) -> Value {
    client
        .send_command(
            "get_function",
            Some(json!({"address":target, "with_signature":true})),
        )
        .unwrap()
}

fn set(client: &BridgeClient, source: &str, target: &str) -> Value {
    client
        .send_command(
            "function_set_thunk",
            Some(json!({"target":source, "thunk_target":target})),
        )
        .unwrap()
}

fn clear(client: &BridgeClient, source: &str) -> Value {
    client
        .send_command("function_clear_thunk", Some(json!({"target":source})))
        .unwrap()
}

fn assert_snapshot(snapshot: &Value, read: &Value) {
    for key in [
        "name",
        "address",
        "signature",
        "calling_convention",
        "no_return",
        "stack_purge",
    ] {
        assert_eq!(snapshot[key], read[key], "{key}: {snapshot}");
    }
    assert!(snapshot["namespace"].is_string(), "{snapshot}");
    let mut details = read["signature_details"].clone();
    let thunk = details.get("thunk_address").is_some();
    assert_eq!(snapshot["is_thunk"], thunk);
    if !thunk {
        details["thunk_function"] = Value::Null;
        details["thunk_address"] = Value::Null;
        details["effective_function"] = read["name"].clone();
        details["effective_address"] = read["address"].clone();
    }
    assert_eq!(snapshot["signature_details"], details);
}

fn assert_relation(snapshot: &Value, direct: &Value, effective: &Value) {
    assert_eq!(snapshot["is_thunk"], true);
    let details = &snapshot["signature_details"];
    assert_eq!(details["thunk_function"], direct["name"]);
    assert_eq!(details["thunk_address"], direct["address"]);
    assert_eq!(details["effective_function"], effective["name"]);
    assert_eq!(details["effective_address"], effective["address"]);
}

fn decompile(client: &BridgeClient) -> String {
    client
        .decompile("caller".to_owned(), false, false, false)
        .unwrap()["code"]
        .as_str()
        .expect("caller C code")
        .to_owned()
}

#[test]
#[serial]
fn set_clear_are_idempotent_restore_saved_metadata_and_refresh_caller() {
    require_ghidra!();
    with_fixture(|client, program| {
        let before = command(program, &["function", "get", "source", "--with-signature"]);
        let destination = get(client, "dynamic_target");
        let original_caller = decompile(client);
        assert!(
            original_caller.contains("= 0x22222222;")
                || original_caller.contains("return 0x22222222;"),
            "{original_caller}"
        );
        let receipt = command(
            program,
            &[
                "function",
                "set-thunk",
                "0x1101",
                "--target",
                "dynamic_target",
            ],
        );
        assert_eq!(receipt["status"], "updated");
        assert_eq!(receipt["function"], "source");
        assert_eq!(receipt["address"], "0x00001100");
        assert_snapshot(&receipt["before"], &before);
        let after = get(client, "source");
        assert_snapshot(&receipt["after"], &after);
        assert_relation(&receipt["after"], &destination, &destination);
        assert_eq!(after["calling_convention"], "__stdcall");
        assert_eq!(
            after["signature_details"]["params"][0]["name"],
            "target_value"
        );
        assert_eq!(get(client, "dynamic_target"), destination);
        let thunk_caller = decompile(client);
        assert!(
            thunk_caller.contains("= 0x11111111;") || thunk_caller.contains("return 0x11111111;"),
            "{thunk_caller}"
        );
        let unchanged = set(client, "source", "dynamic_target");
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["before"], receipt["after"]);
        assert_eq!(unchanged["after"], receipt["after"]);

        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "source"), after);
        assert_eq!(decompile(client), thunk_caller);
        let cleared = command(program, &["function", "clear-thunk", "source"]);
        assert_eq!(cleared["status"], "updated");
        assert_eq!(cleared["before"], receipt["after"]);
        assert_eq!(cleared["after"], receipt["before"]);
        assert_eq!(get(client, "source"), before);
        assert_eq!(decompile(client), original_caller);
        assert_eq!(get(client, "dynamic_target"), destination);
        let unchanged = clear(client, "source");
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["before"], cleared["after"]);
        assert_eq!(unchanged["after"], cleared["after"]);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "source"), before);
    });
}

#[test]
#[serial]
fn retarget_edits_selected_source_and_keeps_direct_destination_chain() {
    require_ghidra!();
    with_fixture(|client, program| {
        let original = get(client, "chain_source");
        let middle = get(client, "chain_middle");
        let dynamic = get(client, "dynamic_target");
        let target_link = get(client, "target_link");
        let custom = get(client, "custom_target");
        let receipt = set(client, "0x1601", "target_link");
        assert_eq!(receipt["status"], "updated");
        assert_eq!(receipt["function"], "chain_source");
        assert_eq!(receipt["address"], original["address"]);
        assert_snapshot(&receipt["before"], &original);
        assert_relation(&receipt["before"], &middle, &dynamic);
        assert_relation(&receipt["after"], &target_link, &custom);
        assert_snapshot(&receipt["after"], &get(client, "chain_source"));
        assert_eq!(
            receipt["after"]["signature_details"]["storage_mode"],
            "custom"
        );
        assert_eq!(
            receipt["after"]["signature_details"]["return"]["storage"],
            "EDX:4,EAX:4"
        );
        assert_eq!(
            receipt["after"]["signature_details"]["params"][0]["storage"],
            "EAX:4"
        );
        for (name, expected) in [
            ("chain_middle", &middle),
            ("dynamic_target", &dynamic),
            ("target_link", &target_link),
            ("custom_target", &custom),
        ] {
            assert_eq!(&get(client, name), expected);
        }
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_snapshot(&receipt["after"], &get(client, "chain_source"));
        let unchanged = set(client, "chain_source", "target_link");
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["before"], unchanged["after"]);

        // A different direct edge is an edit even when its final owner is identical.
        let direct = set(client, "chain_source", "custom_target");
        assert_eq!(direct["status"], "updated");
        assert_relation(&direct["before"], &target_link, &custom);
        assert_relation(&direct["after"], &custom, &custom);
        let cleared = clear(client, "chain_source");
        assert_eq!(cleared["after"]["is_thunk"], false);
        assert_eq!(
            cleared["after"]["signature_details"]["storage_mode"],
            "dynamic"
        );
        assert_eq!(
            cleared["after"]["signature_details"]["params"][0]["name"],
            "saved_value"
        );
        assert_eq!(get(client, "chain_middle"), middle);
        assert_eq!(get(client, "target_link"), target_link);
        assert_eq!(get(client, "custom_target"), custom);
    });
}

#[test]
#[serial]
fn custom_saved_storage_and_class_this_specialization_follow_native_thunks() {
    require_ghidra!();
    with_fixture(|client, program| {
        let custom_before = get(client, "custom_source");
        assert_eq!(custom_before["signature_details"]["storage_mode"], "custom");
        assert_eq!(
            custom_before["signature_details"]["return"]["storage"],
            "AX:2"
        );
        assert_eq!(
            custom_before["signature_details"]["params"][0]["storage"],
            "ECX:4"
        );
        assert_eq!(custom_before["signature_details"]["variadic"], true);
        let receipt = set(client, "custom_source", "dynamic_target");
        assert_eq!(receipt["after"]["namespace"], "Saved");
        assert_eq!(
            receipt["after"]["signature_details"]["storage_mode"],
            "dynamic"
        );
        assert_snapshot(&receipt["before"], &custom_before);
        assert_snapshot(&receipt["after"], &get(client, "custom_source"));
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        let cleared = clear(client, "custom_source");
        assert_eq!(cleared["after"], receipt["before"]);
        assert_eq!(get(client, "custom_source"), custom_before);

        let method_before = get(client, "method_source");
        let target = get(client, "method_target");
        assert_eq!(target["signature_details"]["params"][0]["type"], "Target *");
        let receipt = set(client, "method_source", "method_target");
        assert_eq!(receipt["after"]["namespace"], "Wrapper");
        assert_relation(&receipt["after"], &target, &target);
        let params = &receipt["after"]["signature_details"]["params"];
        assert_eq!(params[0]["auto_parameter"], "THIS");
        assert_eq!(params[0]["type"], "Wrapper *");
        assert_eq!(
            params[0]["storage"],
            target["signature_details"]["params"][0]["storage"]
        );
        assert_snapshot(&receipt["after"], &get(client, "method_source"));
        assert_eq!(get(client, "method_target"), target);
        let cleared = clear(client, "method_source");
        assert_snapshot(&cleared["after"], &method_before);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "custom_source"), custom_before);
        assert_eq!(get(client, "method_source"), method_before);
    });
}

#[test]
#[serial]
fn external_destinations_are_allowed_and_invalid_edges_roll_back_without_wrong_target_edits() {
    require_ghidra!();
    with_fixture(|client, program| {
        let source = get(client, "0x1c00");
        let external = get(client, "outside_target");
        let external_address = external["address"].as_str().unwrap();
        let receipt = set(client, "0x1c00", "outside_target");
        assert_eq!(receipt["status"], "updated");
        assert_relation(&receipt["after"], &external, &external);
        assert_snapshot(&receipt["before"], &source);
        assert_snapshot(&receipt["after"], &get(client, "0x1c00"));
        assert_eq!(receipt["after"]["name"], "outside_target");
        assert_eq!(receipt["after"]["namespace"], "library");
        assert_eq!(get(client, external_address), external);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_snapshot(&receipt["after"], &get(client, "0x1c00"));
        let cleared = clear(client, "0x1c00");
        assert_eq!(cleared["after"], receipt["before"]);
        assert_eq!(get(client, "0x1c00"), source);

        let targets = [
            "source",
            "dynamic_target",
            "custom_target",
            "chain_source",
            "chain_middle",
            "target_link",
            "0x1a00",
            "0x1b00",
            external_address,
        ];
        let before: Vec<_> = targets.iter().map(|target| get(client, target)).collect();
        for (name, args) in [
            (
                "function_set_thunk",
                json!({"target":"source", "thunk_target":"source"}),
            ),
            (
                "function_set_thunk",
                json!({"target":"dynamic_target", "thunk_target":"chain_source"}),
            ),
            (
                "function_set_thunk",
                json!({"target":"chain_source", "thunk_target":"missing_destination"}),
            ),
            (
                "function_set_thunk",
                json!({"target":"ambiguous", "thunk_target":"custom_target"}),
            ),
            (
                "function_set_thunk",
                json!({"target":"source", "thunk_target":"ambiguous"}),
            ),
            (
                "function_set_thunk",
                json!({"target":external_address, "thunk_target":"source"}),
            ),
            ("function_clear_thunk", json!({"target":external_address})),
            ("function_clear_thunk", json!({"target":"ambiguous"})),
        ] {
            let error = client
                .send_command(name, Some(args.clone()))
                .expect_err(&format!("Invalid thunk edit accepted: {name} {args}"));
            let error = error.downcast_ref::<BridgeCommandError>().unwrap();
            assert_eq!(
                error.detail["rolled_back"], true,
                "{name} {args}: {error:?}"
            );
            let after: Vec<_> = targets.iter().map(|target| get(client, target)).collect();
            assert_eq!(after, before, "{name} {args}");
        }
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        let reopened: Vec<_> = targets.iter().map(|target| get(client, target)).collect();
        assert_eq!(reopened, before);
    });
}
