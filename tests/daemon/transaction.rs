use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;

// Exercise the production dispatcher against a separate, real Ghidra database.
// Java interface proxies inject failures after real edits or iterator reads,
// without bridge test switches or nesting under the enclosing script's request.
const TRANSACTION_PROBE: &str = include_str!("../fixtures/daemon/RequestTransactionProbe.java");

#[test]
#[serial]
fn test_program_selection_distinguishes_same_paths_in_different_projects() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let result = harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/daemon/CheckCrossProjectSessionIdentity.java"),
            &[format!("cross-project-session-{}", uuid::Uuid::new_v4())],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains("cross-project-session-ok"),
        "{result}"
    );
}

fn run_transaction_probe(mode: &str) {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address;
    let original_name = function.name;
    let folder = format!("transaction-{}", uuid::Uuid::new_v4());
    let result = client
        .script_run_source(
            TRANSACTION_PROBE,
            &[folder.clone(), address.clone(), mode.to_owned()],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("contract-ok:{mode}")),
        "{result}"
    );
    drop(harness);

    // A new bridge and normal public requests independently verify durability.
    let restarted = start_daemon();
    let client = restarted.client().unwrap();
    let program = format!("/{folder}/{TEST_PROGRAM}");
    client.open_program(&program).unwrap();
    let comments = client.comment_get(&address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["type"] == "EOL" && row["text"] == format!("prior:{folder}")),
        "Prior successful edit was lost: {comments}"
    );
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": address})),
        )
        .unwrap();
    assert_eq!(function["name"], original_name);
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn test_late_error_rolls_back_only_the_failed_request() {
    run_transaction_probe("late-error");
}

#[test]
#[serial]
fn test_late_assertion_rolls_back_only_the_failed_request() {
    run_transaction_probe("late-assertion");
}

#[test]
#[serial]
fn test_memory_write_late_failure_restores_bytes_definitions_and_references() {
    run_transaction_probe("memory-error");
}

#[test]
#[serial]
fn test_memory_write_cancellation_restores_bytes_definitions_and_references() {
    run_transaction_probe("memory-cancel");
}

#[test]
#[serial]
fn test_memory_write_reference_failure_restores_bytes_definitions_and_references() {
    run_transaction_probe("pointer-error");
}

#[test]
#[serial]
fn test_cancellation_after_edit_rolls_back_only_the_cancelled_request() {
    run_transaction_probe("cancel");
}

#[test]
#[serial]
fn test_program_stats_cancellation_stops_scanning_and_preserves_later_requests() {
    run_transaction_probe("stats-cancel");
}

#[test]
#[serial]
fn test_non_atomic_cancelled_script_retains_cancellation_and_saved_changes_diagnostics() {
    run_transaction_probe("non-atomic-cancel");
}

#[test]
#[serial]
fn test_non_atomic_cancelled_script_save_failure_keeps_cancellation_and_pending_edits() {
    run_transaction_probe("non-atomic-cancel-save");
}

#[test]
#[serial]
fn test_non_atomic_script_native_abort_reports_rollback_and_preserves_saved_state() {
    run_transaction_probe("script-native-abort");
}

#[test]
#[serial]
fn test_non_atomic_analysis_native_abort_reports_rollback_and_preserves_saved_state() {
    run_transaction_probe("analysis-native-abort");
}

#[test]
#[serial]
fn test_native_abort_explicit_save_preserves_earlier_pending_edits() {
    run_transaction_probe("native-abort-save");
}

#[test]
#[serial]
fn test_native_abort_explicit_save_listener_failure_preserves_earlier_pending_edits() {
    run_transaction_probe("native-abort-save-listener");
}

#[test]
#[serial]
fn test_explicit_save_commit_failure_is_not_retried_during_request_completion() {
    run_transaction_probe("explicit-save-commit-failure");
}

#[test]
#[serial]
fn test_preview_rollback_listener_failures_preserve_earlier_pending_edits() {
    run_transaction_probe("preview-rollback-listener-failure");
}

#[test]
#[serial]
fn test_native_false_rolls_back_changes_before_the_failure() {
    run_transaction_probe("native-false");
}

#[test]
#[serial]
fn test_transient_save_failure_is_not_retried_and_pending_edits_survive_rollback() {
    run_transaction_probe("save-recovery");
}

#[test]
#[serial]
fn test_native_save_assertion_is_not_retried_and_pending_edits_survive_rollback() {
    run_transaction_probe("save-assertion");
}

#[test]
#[serial]
fn test_description_save_failure_retains_receipt_and_recovers_without_replay() {
    run_transaction_probe("description-save");
}

#[test]
#[serial]
fn test_storage_late_error_rolls_back_native_abi_update() {
    run_transaction_probe("storage-error");
}

#[test]
#[serial]
fn test_storage_cancellation_rolls_back_native_abi_update() {
    run_transaction_probe("storage-cancel");
}

#[test]
#[serial]
fn test_storage_save_failure_retains_receipt_and_pending_abi() {
    run_transaction_probe("storage-save");
}

#[test]
#[serial]
fn test_foreign_transaction_rejection_preserves_its_edits_and_owner() {
    run_transaction_probe("foreign-transaction");
}

#[test]
#[serial]
fn test_transaction_start_failure_does_not_poison_later_requests() {
    run_transaction_probe("start-failure");
}

#[test]
#[serial]
fn test_mutation_leaked_child_defers_rollback_to_its_owner_without_saving() {
    run_transaction_probe("mutation-leaked-child");
}

#[test]
#[serial]
fn test_preview_leaked_child_defers_rollback_to_its_owner_without_saving() {
    run_transaction_probe("preview-leaked-child");
}

#[test]
#[serial]
fn test_preview_cannot_commit_prior_edits_in_the_same_request() {
    run_transaction_probe("preview");
}

#[test]
#[serial]
fn test_preview_transaction_start_failures_do_not_save_earlier_pending_edits() {
    run_transaction_probe("preview-start-failure");
}

#[test]
#[serial]
fn test_cancelled_deletion_refusal_restores_selection_and_preserves_consumers() {
    run_transaction_probe("cancelled-delete-refusal");
}

#[test]
#[serial]
fn test_cancellation_during_save_prevents_deletion_and_restores_selection() {
    run_transaction_probe("cancelled-delete-save");
}

#[test]
#[serial]
fn test_failed_program_open_releases_its_consumer_and_preserves_selection() {
    run_transaction_probe("failed-open");
}

#[test]
#[serial]
fn test_cancelled_selector_reports_saved_pending_edits_and_preserves_selection() {
    run_transaction_probe("selector-save-receipt");
}

#[test]
#[serial]
fn test_selector_assertion_reports_saved_pending_edits_and_preserves_selection() {
    run_transaction_probe("selector-assertion");
}

#[test]
#[serial]
fn test_native_finish_assertion_preserves_prior_saved_receipt_and_command_response() {
    run_transaction_probe("selector-finish-assertion");
}

#[test]
#[serial]
fn test_native_commit_assertion_retains_pending_edits_and_reports_blocked_selection() {
    run_transaction_probe("selector-commit-assertion");
}

#[test]
#[serial]
fn test_rejected_target_edit_reports_previous_program_saved_by_selector() {
    run_transaction_probe("selector-rollback");
}

#[test]
#[serial]
fn test_selector_save_receipt_survives_later_target_save_failure() {
    run_transaction_probe("selector-save-failure");
}
