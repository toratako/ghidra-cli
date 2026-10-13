use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serde_json::json;
use serial_test::serial;

#[test]
#[serial]
fn dormant_type_preview_cancellation_failures_and_save_recovery_preserve_native_state() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let folder = format!("dormant-preview-{}", uuid::Uuid::new_v4());
    let result = client
        .script_run_source(
            include_str!("../fixtures/types/CheckDormantMutationPreviewFailures.java"),
            std::slice::from_ref(&folder),
            &[],
            false,
        )
        .unwrap();
    let modes = [
        "edge-cancel",
        "verify-cancel",
        "verify-scan-cancel",
        "error",
        "throw",
        "success",
        "save-recovery",
    ];
    for mode in modes {
        assert!(
            result["stdout"]
                .as_str()
                .unwrap()
                .contains(&format!("dormant-preview-ok:{mode}")),
            "{result}"
        );
    }
    drop(harness);

    // A fresh bridge independently reads the saved native definitions, including
    // each thunk's own parameter/local types after explicitly clearing its edge.
    let restarted = start_daemon();
    let client = restarted.client().unwrap();
    for mode in modes {
        let program = format!("/{folder}/{mode}");
        client.open_program(&program).unwrap();
        let expected = if mode == "success" {
            "accepted"
        } else {
            "baseline"
        };
        assert_eq!(
            client.type_get("/Audit/DormantCell").unwrap()["description"],
            expected
        );
        if mode == "save-recovery" {
            assert_eq!(
                client.type_get("/Audit/DormantCell").unwrap()["components"][0]["name"],
                "accepted_field"
            );
        }
        let comments = client.comment_get("0x1000").unwrap();
        let rows = comments["comments"].as_array().unwrap();
        assert_eq!(
            rows.len(),
            usize::from(matches!(mode, "success" | "save-recovery"))
        );
        if mode == "success" {
            assert_eq!(rows[0]["text"], "native-call-2");
        } else if mode == "save-recovery" {
            assert_eq!(rows[0]["text"], "pending-before-preview");
        }
        for (address, target) in [("0x1020", "0x00001000"), ("0x1040", "0x00001020")] {
            let function = client
                .send_command(
                    "get_function",
                    Some(json!({
                        "address": address, "with_signature": true,
                    })),
                )
                .unwrap();
            assert_eq!(
                function["signature_details"]["thunk_address"], target,
                "{mode}: {function}"
            );
        }
        client
            .send_command("function_clear_thunk", Some(json!({"target": "0x1020"})))
            .unwrap();
        let own = client
            .send_command(
                "get_function",
                Some(json!({
                    "address": "0x1020", "with_signature": true, "with_frame": true,
                })),
            )
            .unwrap();
        let parameters = own["signature_details"]["params"].as_array().unwrap();
        assert_eq!(parameters.len(), 1, "{mode}: {own}");
        assert_eq!(parameters[0]["name"], "saved_input");
        assert_eq!(parameters[0]["type_path"], "/Audit/DormantCell");
        let inspected = client
            .script_run_source(
                include_str!("../fixtures/types/CheckDormantMutationPreviewFailures.java"),
                &[folder.clone(), "inspect".to_owned()],
                &[],
                false,
            )
            .unwrap();
        assert!(
            inspected["stdout"]
                .as_str()
                .unwrap()
                .contains("dormant-preview-reopened-ok"),
            "{inspected}"
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
    }
}
