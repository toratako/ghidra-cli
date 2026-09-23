//! Stack purge metadata, saved values, and caller stack interpretation on x86.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};

#[macro_use]
mod common;

fn function(client: &BridgeClient, target: &str) -> Value {
    client
        .send_command("get_function", Some(json!({"address": target})))
        .unwrap()
}

fn command(harness: &common::DaemonTestHarness, target: &str, edit: &[&str]) -> Value {
    let result = common::ghidra(harness)
        .args(["function", "set-stack-purge", target])
        .args(edit.iter().copied())
        .arg("--json")
        .run();
    result.assert_success();
    let rows: Value = result.data();
    rows.clone()
}

fn decompile(client: &BridgeClient) -> String {
    let result = client
        .decompile("caller".to_owned(), false, false, false, false)
        .expect("decompile caller");
    result["code"].as_str().expect("caller C code").to_owned()
}

#[test]
fn stack_purge_changes_caller_interpretation_and_persists_without_convention_edits() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-stack-purge-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("stack-purge.bin");
    let mut bytes = vec![0xcc; 0x160];
    let caller = [
        0x68, 0x11, 0x11, 0x11, 0x11, // push 0x11111111 (saved caller value)
        0x68, 0x22, 0x22, 0x22, 0x22, // push 0x22222222 (callee argument)
        0xe8, 0xf1, 0x00, 0x00, 0x00, // call callee at 0x1100
        0x8b, 0x04, 0x24, // mov eax, [esp]
        0x83, 0xc4, 0x04, // add esp, 4
        0xc3, // ret
    ];
    bytes[..caller.len()].copy_from_slice(&caller);
    bytes[0x100..0x103].copy_from_slice(&[0xc2, 0x04, 0x00]); // ret 4
    bytes[0x120] = 0xc3;
    bytes[0x140..0x145].copy_from_slice(&[0xe9, 0xbb, 0xff, 0xff, 0xff]); // jmp callee
    std::fs::write(&binary, bytes).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_install_dir()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:32:default".to_owned()),
            compiler_spec: Some("windows".to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw stack-purge fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/stack_purge/CreateStackPurgeFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();

    let unknown = json!({"state": "unknown", "bytes": null});
    let invalid = json!({"state": "invalid", "bytes": null});
    let known = |bytes: i32| json!({"state": "known", "bytes": bytes});
    assert_eq!(function(&client, "callee")["stack_purge"], unknown);
    assert_eq!(function(&client, "invalid_purge")["stack_purge"], invalid);
    let conventions =
        ["callee", "caller"].map(|target| function(&client, target)["calling_convention"].clone());

    // Wrong explicit metadata must affect the caller before the correction;
    // otherwise a stale decompiler cache could make this test pass accidentally.
    assert_eq!(
        command(&harness, "callee", &["--bytes", "0"])["stack_purge"],
        known(0)
    );
    let wrong = decompile(&client);
    assert!(
        wrong.contains("= 0x22222222;") || wrong.contains("return 0x22222222;"),
        "{wrong}"
    );
    assert!(!wrong.contains("0x11111111"), "{wrong}");
    let receipt = command(&harness, "0x1101", &["--bytes", "4"]);
    assert_eq!(receipt["status"], "stack_purge_set");
    assert_eq!(receipt["function"], "callee");
    assert_eq!(receipt["address"], "0x00001100");
    assert_eq!(receipt["stack_purge"], known(4));
    let corrected = decompile(&client);
    assert!(
        corrected.contains("= 0x11111111;") || corrected.contains("return 0x11111111;"),
        "{corrected}"
    );

    // Save and reopen the database, not just the client connection.
    let before = function(&client, "callee");
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(&client, "callee"), before);
    assert_eq!(decompile(&client), corrected);

    for edit in [
        json!({"bytes": 4.5}),
        json!({"bytes": 4294967300_u64}),
        json!({"bytes": 2147483647}),
        json!({"bytes": 4, "unknown": true}),
        json!({"unknown": "true"}),
        json!({}),
    ] {
        let mut args = edit;
        args["target"] = json!("callee");
        let error = client
            .send_command("function_set_stack_purge", Some(args.clone()))
            .expect_err(&format!("invalid stack purge accepted: {args}"));
        let error = error.downcast_ref::<BridgeCommandError>().unwrap();
        assert_eq!(error.detail["rolled_back"], true, "{error:?}");
        assert_eq!(function(&client, "callee"), before, "{args}");
    }

    // Thunk requests disclose the shared metadata owner and update it once.
    let receipt = command(&harness, "callee_thunk", &["--bytes", "-4"]);
    assert_eq!(receipt["function"], "callee_thunk");
    assert_eq!(receipt["effective_function"], "callee");
    assert_eq!(receipt["effective_address"], "0x00001100");
    assert_eq!(function(&client, "callee")["stack_purge"], known(-4));
    assert_eq!(function(&client, "callee_thunk")["stack_purge"], known(-4));

    assert_eq!(
        command(&harness, "callee", &["--unknown"])["stack_purge"],
        unknown
    );
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(function(&client, "callee")["stack_purge"], unknown);
    assert_eq!(
        ["callee", "caller"].map(|target| function(&client, target)["calling_convention"].clone()),
        conventions
    );

    let listed = common::ghidra(&harness)
        .args(["function", "list", "--limit", "0"])
        .json_format()
        .run();
    listed.assert_success();
    let listed: Value = listed.data();
    for (name, expected) in [("callee", unknown), ("invalid_purge", invalid)] {
        let row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        assert_eq!(row["stack_purge"], expected);
    }
}
