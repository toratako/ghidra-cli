use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, get_function_address, test_project};
use serde_json::json;
use serial_test::serial;

#[test]
#[serial]
fn native_failure_without_message_preserves_rollback_and_retained_error() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/runtime/CheckNullMessageFailure.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn malformed_mutation_arguments_preserve_saved_tags() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let address = get_function_address(&harness, test_project(), TEST_PROGRAM, "main");
    let name = format!("protocol-{}", uuid::Uuid::new_v4());
    client
        .send_command("tag_create", Some(json!({"name": name})))
        .unwrap();
    client
        .send_command(
            "tag_attach",
            Some(json!({"function": address, "tags": [name]})),
        )
        .unwrap();
    let before = client.tag_list(None, Some(&address)).unwrap();

    // Gson coerces singleton containers, and the old array helper silently
    // discarded a scalar. None may broaden or retarget a destructive request.
    for (command, args, diagnostic) in [
        (
            "tag_delete",
            json!({"name": [name]}),
            "name must be a string",
        ),
        (
            "tag_detach",
            json!({"function": address, "all": [true]}),
            "all must be a boolean",
        ),
        (
            "tag_detach",
            json!({"function": address, "tags": [[name]]}),
            "tags must be an array of strings",
        ),
        (
            "tag_detach",
            json!({"function": address, "tags": name, "all": true}),
            "tags must be an array of strings",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(diagnostic), "{error:#}");
        assert_eq!(client.tag_list(None, Some(&address)).unwrap(), before);
    }

    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_list(None, Some(&address)).unwrap(), before);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}
