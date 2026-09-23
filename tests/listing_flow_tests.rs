//! Native instruction flow/fallthrough interpretation, references, delay slots, and rollback.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};

#[macro_use]
mod common;

fn fixture(language: &str, bytes: &[u8], check: impl FnOnce(&common::DaemonTestHarness, &str)) {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-listing-flow-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("flow.bin");
    std::fs::write(&binary, bytes).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_installation()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some(language.to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw flow fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("listing_flow/CreateFlowFixture.java"),
            &[],
            &[],
            false,
        )
        .expect("define flow fixture instructions/functions and check native normalization");
    check(&harness, &program);
}

fn get(client: &BridgeClient, address: &str) -> Value {
    client
        .send_command("listing_flow_get", Some(json!({"address": address})))
        .unwrap()
}

fn edit(client: &BridgeClient, operation: &str, address: &str, mut args: Value) -> Value {
    args["address"] = json!(address);
    client
        .send_command(&format!("listing_flow_{operation}"), Some(args))
        .unwrap()
}

fn bytes(client: &BridgeClient, size: usize) -> Value {
    client
        .send_command(
            "read_memory",
            Some(json!({"address": "0x1000", "size": size})),
        )
        .unwrap()["hex"]
        .clone()
}

fn decompile(client: &BridgeClient) -> String {
    client
        .decompile("flow_caller".to_owned(), false, false, false, false)
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn reference_types(result: &Value) -> Vec<&str> {
    result["flow_references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reference| reference["type"].as_str().unwrap())
        .collect()
}

fn x86_bytes() -> Vec<u8> {
    let mut bytes = vec![0xcc; 0x80];
    for (offset, code) in [
        (0, &[0xe8, 0x3b, 0, 0, 0, 0xb8, 7, 0, 0, 0, 0xc3][..]),
        (0x10, &[0x75, 0x0e, 0xb8, 1, 0, 0, 0, 0xc3]),
        (0x20, &[0xb8, 2, 0, 0, 0, 0xc3]),
        (0x30, &[0xe9, 0x0b, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xc3]),
        (0x40, &[0xb8, 42, 0, 0, 0, 0xc3]),
        (0x50, &[0xc3]),
        (0x60, &[0x66, 0x90, 0xc3]),
        (0x70, &[0x0f, 0x44, 0xc1, 0xc3]), // cmovz eax,ecx; ret
        (0x74, &[0xf3, 0xa4, 0xc3]),       // rep movsb; ret
        (0x78, &[0xf4]), // hlt, whose internal loop is not an overridable transfer
        (0x7a, &[0xeb, 0xfe]), // real jmp to itself, unlike hlt's p-code loop
    ] {
        bytes[offset..offset + code.len()].copy_from_slice(code);
    }
    bytes
}

#[test]
fn flow_edits_preserve_independent_settings_references_bytes_and_saved_interpretation() {
    fixture("x86:LE:32:default", &x86_bytes(), |harness, program| {
        let client = harness.client().unwrap();
        let original_bytes = bytes(&client, 0x80);
        let original = get(&client, "0x1000");
        assert_eq!(original["raw_flow"], "UNCONDITIONAL_CALL");
        assert_eq!(original["effective_flow"], original["raw_flow"]);
        assert_eq!(original["override"], "none");
        assert_eq!(
            original["fallthrough"],
            json!({
                "raw":"0x00001005", "default":"0x00001005", "effective":"0x00001005", "overridden":false
            })
        );
        assert_eq!(reference_types(&original), ["UNCONDITIONAL_CALL"]);
        let baseline_code = decompile(&client);
        assert!(baseline_code.contains("7"), "{baseline_code}");

        let output = common::ghidra(harness)
            .args(["listing", "flow", "set", "0x1000", "--no-fallthrough"])
            .json_format()
            .run();
        output.assert_success();
        let suppressed: Value = output.data();
        assert_eq!(suppressed["before"], original);
        assert_eq!(suppressed["changed"], true);
        assert_eq!(suppressed["after"]["fallthrough"]["overridden"], true);
        assert!(suppressed["after"]["fallthrough"]["effective"].is_null());
        // The native decompiler's InstructionPcodeOverride encodes nonnull redirect
        // targets only. Listing fallthrough suppression alone does not remove the
        // raw CALL's sequential p-code execution, unlike the explicit redirect below.
        assert_eq!(decompile(&client), baseline_code);
        assert_eq!(
            edit(&client, "set", "0x1000", json!({"no_fallthrough":true}))["changed"],
            false
        );

        let output = common::ghidra(harness)
            .args(["listing", "flow", "set", "0x1000", "--override", "branch"])
            .json_format()
            .run();
        output.assert_success();
        let branch: Value = output.data();
        assert_eq!(branch["after"]["override"], "branch");
        assert_eq!(branch["after"]["raw_flow"], "UNCONDITIONAL_CALL");
        assert_eq!(branch["after"]["effective_flow"], "UNCONDITIONAL_JUMP");
        assert_eq!(reference_types(&branch["after"]), ["UNCONDITIONAL_JUMP"]);
        assert!(branch["after"]["fallthrough"]["default"].is_null());
        assert_eq!(branch["after"]["fallthrough"]["overridden"], true);
        assert!(branch["after"]["fallthrough"]["effective"].is_null());
        let reset_flow = edit(&client, "clear", "0x1000", json!({"override":true}));
        assert_eq!(reset_flow["after"], suppressed["after"]);
        let reset_fallthrough = edit(&client, "clear", "0x1000", json!({"fallthrough":true}));
        assert_eq!(reset_fallthrough["after"], original);
        assert_eq!(decompile(&client), baseline_code);
        assert_eq!(
            edit(&client, "clear", "0x1000", json!({"fallthrough":true}))["changed"],
            false
        );

        let output = common::ghidra(harness)
            .args([
                "listing",
                "flow",
                "set",
                "0x1000",
                "--fallthrough",
                "0x100a",
            ])
            .json_format()
            .run();
        output.assert_success();
        let redirect: Value = output.data();
        assert_eq!(redirect["after"]["fallthrough"]["effective"], "0x0000100a");
        assert!(reference_types(&redirect["after"]).contains(&"FALL_THROUGH"));
        let redirected_code = decompile(&client);
        assert!(!redirected_code.contains("7"), "{redirected_code}");
        assert_ne!(redirected_code, baseline_code);
        let compound = edit(
            &client,
            "set",
            "0x1000",
            json!({"override":"return", "fallthrough":"0x1005"}),
        );
        assert_eq!(compound["after"]["override"], "return");
        assert!(compound["after"]["fallthrough"]["default"].is_null());
        assert_eq!(compound["after"]["fallthrough"]["effective"], "0x00001005");
        assert_eq!(compound["after"]["fallthrough"]["overridden"], true);
        let clear_fallthrough = edit(&client, "clear", "0x1000", json!({"fallthrough":true}));
        assert_eq!(clear_fallthrough["after"]["override"], "return");
        assert!(clear_fallthrough["after"]["fallthrough"]["effective"].is_null());
        assert_eq!(
            clear_fallthrough["after"]["fallthrough"]["overridden"],
            false
        );
        assert!(!reference_types(&clear_fallthrough["after"]).contains(&"FALL_THROUGH"));

        let retained = edit(
            &client,
            "set",
            "0x1000",
            json!({"override":"call-return", "fallthrough":"0x100a"}),
        )["after"]
            .clone();
        assert_eq!(retained["override"], "call-return");
        assert_eq!(retained["effective_flow"], "CALL_TERMINATOR");
        let untouched_target = client
            .send_command("get_function", Some(json!({"address":"flow_target"})))
            .unwrap();
        assert_eq!(untouched_target["no_return"], false);
        assert_eq!(bytes(&client, 0x80), original_bytes);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(&client, "0x1000"), retained);
        assert_eq!(bytes(&client, 0x80), original_bytes);
        let output = common::ghidra(harness)
            .args([
                "listing",
                "flow",
                "clear",
                "0x1000",
                "--override",
                "--fallthrough",
            ])
            .json_format()
            .run();
        output.assert_success();
        assert_eq!(output.data::<Value>()["after"], original);
        assert_eq!(decompile(&client), baseline_code);
        let output = common::ghidra(harness)
            .args(["listing", "flow", "get", "0x1000"])
            .json_format()
            .run();
        output.assert_success();
        assert_eq!(output.data::<Value>(), original);
    });
}

#[test]
fn flow_validates_native_targets_and_rolls_back_compound_native_failure() {
    fixture("x86:LE:32:default", &x86_bytes(), |harness, program| {
        let client = harness.client().unwrap();
        let original_bytes = bytes(&client, 0x80);
        let jump = get(&client, "0x1030");
        assert!(jump["fallthrough"]["raw"].is_null());
        assert_eq!(jump["fallthrough"]["overridden"], false);
        let conditional = edit(&client, "set", "0x1010", json!({"override":"call"}));
        assert_eq!(conditional["after"]["raw_flow"], "CONDITIONAL_JUMP");
        assert_eq!(conditional["after"]["effective_flow"], "CONDITIONAL_CALL");
        assert_eq!(conditional["after"]["fallthrough"]["raw"], "0x00001012");
        assert_eq!(
            conditional["after"]["fallthrough"]["effective"],
            "0x00001012"
        );
        assert_eq!(reference_types(&conditional["after"]), ["CONDITIONAL_CALL"]);

        for (operation, args) in [
            (
                "set",
                json!({"address":"0x1030", "override":"call", "no_fallthrough":true}),
            ),
            (
                "set",
                json!({"address":"0x1030", "override":"call", "fallthrough":"0x1031"}),
            ),
            (
                "set",
                json!({"address":"0x1030", "fallthrough":"flow_overlay:0x1000"}),
            ),
            ("set", json!({"address":"0x1030", "fallthrough":"0x1080"})),
            ("set", json!({"address":"0x1031", "override":"call"})),
            ("set", json!({"address":"0x1060", "override":"call"})),
            ("set", json!({"address":"0x1070", "override":"call"})),
            ("set", json!({"address":"0x1074", "override":"call"})),
            ("set", json!({"address":"0x1078", "override":"call"})),
            (
                "set",
                json!({"address":"0x1030", "fallthrough":"0x1035", "no_fallthrough":true}),
            ),
            ("set", json!({"address":"0x1030", "override":true})),
            ("set", json!({"address":"0x1030", "no_fallthrough":"true"})),
            ("clear", json!({"address":"0x1030", "override":"true"})),
            ("clear", json!({"address":"0x1030"})),
            ("set", json!({"address":"0x1030"})),
            ("set", json!({"address":"0x1050", "no_fallthrough":true})),
        ] {
            let target = args["address"].as_str().unwrap();
            let before = if target == "0x1031" {
                None
            } else {
                Some(get(&client, target))
            };
            let error = client
                .send_command(&format!("listing_flow_{operation}"), Some(args.clone()))
                .expect_err(&format!("invalid flow edit: {args}"));
            let error = error.downcast_ref::<BridgeCommandError>().unwrap();
            assert_eq!(error.detail["rolled_back"], true, "{args}: {error:?}");
            if let Some(before) = before {
                assert_eq!(get(&client, target), before, "{args}");
            }
            assert_eq!(get(&client, "0x1030"), jump, "{args}");
        }
        let call = edit(&client, "set", "0x1030", json!({"override":"call"}));
        let self_branch = edit(&client, "set", "0x107a", json!({"override":"call"}));
        assert_eq!(self_branch["after"]["effective_flow"], "UNCONDITIONAL_CALL");
        assert!(call["after"]["fallthrough"]["raw"].is_null());
        assert_eq!(call["after"]["fallthrough"]["default"], "0x00001035");
        assert_eq!(call["after"]["fallthrough"]["effective"], "0x00001035");
        assert_eq!(call["after"]["fallthrough"]["overridden"], false);
        assert_eq!(
            edit(
                &client,
                "clear",
                "0x1030",
                json!({"override":true, "fallthrough":true})
            )["after"],
            jump
        );
        assert_eq!(bytes(&client, 0x80), original_bytes);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(&client, "0x1030"), jump);
        assert_eq!(get(&client, "0x1010"), conditional["after"]);
    });
}

#[test]
fn flow_uses_mips_delay_slot_fallthrough_and_preserves_the_slot() {
    let sample = [
        0x14, 0x85, 0, 3, // bne a0,a1,0x1010
        0x24, 2, 0, 1, // addiu v0,zero,1 (delay slot)
        3, 0xe0, 0, 8, // jr ra
        0, 0, 0, 0, // nop (return delay slot)
        3, 0xe0, 0, 8, // target: jr ra
        0x24, 2, 0, 2, // addiu v0,zero,2 (return delay slot)
    ];
    fixture("MIPS:BE:32:default", &sample, |harness, program| {
        let client = harness.client().unwrap();
        let original_bytes = bytes(&client, sample.len());
        let original = get(&client, "0x1000");
        assert_eq!(original["raw_flow"], "CONDITIONAL_JUMP");
        assert_eq!(original["delay_slot_depth"], 1);
        assert_eq!(original["fallthrough"]["raw"], "0x00001008");
        assert_eq!(original["fallthrough"]["effective"], "0x00001008");
        let slot = get(&client, "0x1004");
        assert_eq!(slot["in_delay_slot"], true);
        let call = edit(
            &client,
            "set",
            "0x1000",
            json!({"override":"call", "fallthrough":"0x1010"}),
        );
        assert_eq!(call["after"]["effective_flow"], "CONDITIONAL_CALL");
        assert_eq!(call["after"]["fallthrough"]["default"], "0x00001008");
        assert_eq!(call["after"]["fallthrough"]["effective"], "0x00001010");
        assert!(reference_types(&call["after"]).contains(&"CONDITIONAL_CALL"));
        assert!(reference_types(&call["after"]).contains(&"FALL_THROUGH"));
        assert_eq!(get(&client, "0x1004"), slot);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(&client, "0x1000"), call["after"]);
        let cleared = edit(
            &client,
            "clear",
            "0x1000",
            json!({"override":true, "fallthrough":true}),
        );
        assert_eq!(cleared["after"], original);
        let none = edit(&client, "set", "0x1000", json!({"no_fallthrough":true}));
        assert!(none["after"]["fallthrough"]["effective"].is_null());
        assert_eq!(none["after"]["fallthrough"]["overridden"], true);
        assert_eq!(
            edit(&client, "clear", "0x1000", json!({"fallthrough":true}))["after"],
            original
        );
        assert_eq!(get(&client, "0x1004"), slot);
        assert_eq!(bytes(&client, sample.len()), original_bytes);
    });
}
