//! Whole function bodies, native annotation side effects, and persistence.

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
        DaemonTestHarness::new(test_project(), common::FIXTURE_PROGRAM)
            .expect("start function body bridge")
    })
}

fn with_fixture(language: &str, check: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    let program = format!("function-body-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("function_body/CreateFunctionBodyFixture.java"),
            &[program.clone(), language.into()],
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&client, &program)));
    client.open_program(common::FIXTURE_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn get(client: &BridgeClient, target: &str) -> Value {
    client
        .send_command("get_function", Some(json!({"address":target})))
        .unwrap()
}

fn set(client: &BridgeClient, target: &str, ranges: Value) -> Value {
    client
        .send_command(
            "function_set_body",
            Some(json!({"target":target, "ranges":ranges})),
        )
        .unwrap()
}

fn state(client: &BridgeClient) -> Value {
    let response = client
        .script_run_source(
            include_str!("function_body/ReadFunctionBodyState.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    serde_json::from_str(
        response["stdout"]
            .as_str()
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("body-state="))
            .unwrap(),
    )
    .unwrap()
}

fn zero_effects() -> Value {
    json!({"deleted_labels":0,"deleted_references":0,"disassociated_variable_references":0})
}

#[test]
#[serial]
fn body_preflight_preserves_annotations_and_shrink_reports_actual_native_losses() {
    require_ghidra!();
    with_fixture("x86:LE:32:default", |client, program| {
        let before = state(client);
        let detail = get(client, "subject");
        let refs = before["references"].as_array().unwrap();
        assert_eq!(refs.len(), 3);
        assert!(refs.iter().any(
            |reference| reference["operand"] == 2 && reference["symbol"].as_i64().unwrap() >= 0
        ));

        for args in [
            json!({"target":"subject","ranges":[]}),
            json!({"target":"subject","ranges":[{"start":"0x1005","end":"0x101f"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":"0x1101"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":"0x1002"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":"0x1005"},{"start":"0x1011","end":"0x101f"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":"0x2000"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":"body_overlay:0x101f"}]}),
            json!({"target":"subject","ranges":[{"start":"0x1000","end":4096}]}),
            json!({"target":"external_body","ranges":[{"start":"0x1000","end":"0x1005"}]}),
        ] {
            let error = client
                .send_command("function_set_body", Some(args.clone()))
                .expect_err(&format!("Invalid body accepted: {args}"));
            let error = error.downcast_ref::<BridgeCommandError>().unwrap();
            assert_eq!(error.detail["rolled_back"], true, "{args}: {error:?}");
            assert_eq!(state(client), before, "{args}");
            assert_eq!(get(client, "subject"), detail, "{args}");
        }

        let receipt = set(client, "0x1002", json!([{"start":"0x1000","end":"0x1005"}]));
        assert_eq!(receipt["function"], "subject");
        assert_eq!(receipt["address"], "0x00001000");
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["before"]["body_ranges"], detail["body_ranges"]);
        assert_eq!(receipt["after"]["size"], 6);
        assert_eq!(
            receipt["effects"],
            json!({"deleted_labels":1,"deleted_references":2,"disassociated_variable_references":1})
        );
        let after = state(client);
        assert_eq!(after["instruction_count"], before["instruction_count"]);
        assert_eq!(after["references"].as_array().unwrap().len(), 1);
        assert_eq!(after["references"][0]["symbol"], -1);
        let labels = after["labels"].as_array().unwrap();
        assert!(!labels
            .iter()
            .any(|label| label["name"] == "subject::removed_label"));
        for expected in [
            "subject::kept_label",
            "global_label",
            "subject::child::child_label",
        ] {
            assert!(
                labels.iter().any(|label| label["name"] == expected),
                "{after}"
            );
        }
        // The dedicated child namespace survives removal of its call from the body.
        let overrides = |value: &Value| {
            value["labels"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|label| label["name"].as_str().unwrap().contains("::override::"))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert!(!overrides(&before).is_empty(), "{before}");
        assert_eq!(overrides(&after), overrides(&before));
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(state(client), after);
        assert_eq!(
            get(client, "subject")["body_ranges"],
            receipt["after"]["body_ranges"]
        );
        let unchanged = set(client, "subject", receipt["after"]["body_ranges"].clone());
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["effects"], zero_effects());

        // Restoring addresses cannot reconstruct labels and references that were deleted.
        set(client, "subject", detail["body_ranges"].clone());
        let restored = state(client);
        assert_eq!(restored["body"], before["body"]);
        assert_eq!(restored["labels"], after["labels"]);
        assert_eq!(restored["references"], after["references"]);
    });
}

#[test]
#[serial]
fn body_union_preserves_gaps_and_thunk_selection_without_defining_code() {
    require_ghidra!();
    with_fixture("x86:LE:32:default", |client, program| {
        let before = state(client);
        assert_eq!(before["extension_defined"], false);
        let result = common::ghidra(harness())
            .args([
                "function", "set-body", "subject", "--range", "0x1020", "0x1022", "--range",
                "0x1000", "0x1002", "--range", "0x1003", "0x1005", "--range", "0x1021", "0x1025",
            ])
            .with_project(test_project(), program)
            .json_format()
            .run();
        result.assert_success();
        let receipt: Value = result.data();
        assert_eq!(
            receipt["after"],
            json!({"size":12,"body_ranges":[
                {"start":"0x00001000","end":"0x00001005"},
                {"start":"0x00001020","end":"0x00001025"}
            ]})
        );
        assert_eq!(
            state(client)["instruction_count"],
            before["instruction_count"]
        );
        assert_eq!(state(client)["extension_defined"], false);
        let other = get(client, "other");
        let thunk = set(
            client,
            "body_thunk",
            json!([{"start":"0x1140","end":"0x1145"}]),
        );
        assert_eq!(thunk["address"], "0x00001140");
        assert_eq!(thunk["after"]["size"], 6);
        assert_eq!(get(client, "other"), other);
    });
}

#[test]
#[serial]
fn body_endpoints_round_trip_overlay_and_segmented_address_spaces() {
    require_ghidra!();
    for language in ["x86:LE:32:default", "x86:LE:16:Real Mode"] {
        with_fixture(language, |client, program| {
            let segmented = language.contains("Real Mode");
            let ranges = if segmented {
                json!([
                    {"start":"ram:0x0100:0x0000","end":"ram:0x0100:0x0005"},
                    {"start":"ram:0x0100:0x0020","end":"ram:0x0100:0x0025"}
                ])
            } else {
                json!([
                    {"start":"body_overlay:0x1000","end":"body_overlay:0x1005"},
                    {"start":"body_overlay:0x1020","end":"body_overlay:0x1025"}
                ])
            };
            let target = if segmented {
                "subject"
            } else {
                "overlay_subject"
            };
            let receipt = set(client, target, ranges);
            assert_eq!(receipt["after"]["size"], 12);
            assert_eq!(receipt["after"]["body_ranges"].as_array().unwrap().len(), 2);
            assert_eq!(receipt["effects"], zero_effects());
            let round_trip = set(client, target, receipt["after"]["body_ranges"].clone());
            assert_eq!(round_trip["changed"], false);
            client.program_close().unwrap();
            client.open_program(program).unwrap();
            assert_eq!(
                get(client, target)["body_ranges"],
                receipt["after"]["body_ranges"]
            );
        });
    }
}
