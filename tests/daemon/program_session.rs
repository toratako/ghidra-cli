use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use serial_test::serial;

/// Read a separate database object from the saved file while the bridge stays
/// running. A normal comment_get would only prove the in-memory edit exists.
fn assert_saved_comment(client: &ghidra_cli::ipc::client::BridgeClient, address: &str, text: &str) {
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
public class CheckAutoSavedComment extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.isChanged()) throw new IllegalStateException("Program is still dirty");
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            String actual = saved.getListing().getComment(CodeUnit.EOL_COMMENT,
                saved.getAddressFactory().getAddress(getScriptArgs()[0]));
            if (!getScriptArgs()[1].equals(actual)) {
                throw new IllegalStateException("Saved comment differs: " + actual);
            }
        } finally {
            saved.release(consumer);
        }
    }
}
"#,
            &[address.to_owned(), text.to_owned()],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn test_analyzer_enable_disable_in_bridge() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().expect("bridge client");
    let listing = client.analyzer_list().expect("list analyzers");
    let analyzer = listing["analyzers"]
        .as_array()
        .expect("analyzer array")
        .first()
        .expect("fixture must have analyzers");
    let name = analyzer["name"].as_str().expect("analyzer name");
    let original = analyzer["enabled"].as_bool().expect("enabled flag");

    // Exercise both explicit values and verify actual Ghidra state, not only
    // the command's response. End with the original setting restored.
    for enabled in [!original, original] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "analyzer",
                "set",
                name,
                if enabled { "true" } else { "false" },
            ])
            .args(["--project", test_project(), "--program", TEST_PROGRAM])
            .assert()
            .success();
        let updated = client.analyzer_list().expect("list updated analyzers");
        let actual = updated["analyzers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"].as_str() == Some(name))
            .expect("analyzer still exists");
        assert_eq!(actual["enabled"].as_bool(), Some(enabled));
    }
}

#[test]
#[serial]
fn test_failed_mutation_preserves_prior_edits_after_restart() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().expect("function address");
    let text = format!("persist-before-failure-{}", uuid::Uuid::new_v4());
    client.comment_set(address, &text, Some("EOL")).unwrap();
    assert_saved_comment(&client, address, &text);

    // The address parses, but is outside every memory block. Preflight must
    // reject it while retaining the previously saved comment.
    let error = client
        .send_command(
            "patch_bytes",
            Some(serde_json::json!({"address": "0", "hex": "00"})),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("fully mapped and initialized"),
        "{error}"
    );
    assert_saved_comment(&client, address, &text);
    drop(harness);

    let restarted = start_daemon();
    let comments = restarted.client().unwrap().comment_get(address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|comment| comment["text"] == text),
        "prior edit lost after failed mutation: {comments}"
    );
}

#[test]
#[serial]
fn test_handlers_follow_program_switch_and_close() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let folder = format!("switch-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class CopyBridgeProgram extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("alternate");
    }
}
"#, std::slice::from_ref(&folder), &[], false).unwrap();
    let alternate = format!("/{folder}/alternate");
    client.open_program(&alternate).unwrap();
    // Copying/renaming the project file retains the original internal Program
    // name. Switching back must compare project files, not that internal name.
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);
    let programs = client.send_command("list_programs", None).unwrap();
    assert!(programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|program| program["current"] == false));
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().unwrap();
    let marker = format!("alternate-only-{}", uuid::Uuid::new_v4());
    client.comment_set(address, &marker, Some("EOL")).unwrap();
    assert_saved_comment(&client, address, &marker);
    assert!(client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);
    let programs = client.send_command("list_programs", None).unwrap();
    assert!(programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|program| program["name"] == TEST_PROGRAM && program["current"] == true));
    assert!(!client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.open_program(&alternate).unwrap();
    common::ghidra(&harness)
        .arg("comment")
        .arg("get")
        .arg(address)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run()
        .assert_success()
        .assert_stdout_not_contains(&marker);
    client.open_program(&alternate).unwrap();
    client
        .send_command(
            "analyze",
            Some(serde_json::json!({"program": TEST_PROGRAM})),
        )
        .unwrap();
    assert!(!client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.program_close().unwrap();
    assert!(client
        .comment_get(address)
        .unwrap_err()
        .to_string()
        .contains("No program loaded"));
    client.open_program(TEST_PROGRAM).unwrap();
    client.comment_get(address).unwrap();
}

#[test]
#[serial]
fn test_failed_script_saves_partial_changes() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().unwrap();
    let text = format!("failed-script-autosave-{}", uuid::Uuid::new_v4());
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class EditThenFailAutoSave extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), getScriptArgs()[1]);
        throw new IllegalStateException("intentional failure after editing");
    }
}
"#,
            &[address.to_owned(), text.clone()],
            &[],
            false,
        )
        .unwrap_err();
    let error = error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap();
    assert!(error.message.contains("intentional failure after editing"));
    assert_eq!(error.detail["partial_changes_saved"], true);
    assert_saved_comment(&client, address, &text);
}

#[test]
#[serial]
fn test_save_failure_preserves_program_and_does_not_replay_edit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let key = uuid::Uuid::new_v4().to_string();
    // Deliberately leave a script-owned transaction open: the edit completes,
    // but a durable save cannot acquire the program lock.
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class PreventAutoSave extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions("AutoSaveTest");
        String key = getScriptArgs()[0];
        options.setInt(key, options.getInt(key, 0) + 1);
        println(Integer.toString(currentProgram.startTransaction("deliberately left open")));
    }
}
"#,
            std::slice::from_ref(&key),
            &[],
            false,
        )
        .unwrap_err();
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["save_failed"], true);
    assert_eq!(detail["saved"], false);
    assert_eq!(detail["command_response"]["status"], "success");
    let transaction = detail["command_response"]["data"]["stdout"]
        .as_str()
        .unwrap()
        .trim()
        .to_owned();
    assert!(client.program_save().is_err());
    assert!(client.program_close().is_err());
    let deletion = client.program_delete(TEST_PROGRAM).unwrap_err();
    assert_eq!(
        deletion
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap()
            .detail["save_failed"],
        true
    );
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], true);

    let batch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(batch.path(), "program save\nprogram info\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let batch_error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(batch_error["detail"]["save_failed"], true);
    assert_eq!(batch_error["detail"]["not_executed"], 1);
    assert_eq!(
        batch_error["detail"]["results"][0]["detail"]["command_response"]["status"],
        "success"
    );

    let repaired = client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class AllowAutoSave extends GhidraScript {
    public void run() throws Exception {
        currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
        println("edit-count:" + currentProgram.getOptions("AutoSaveTest").getInt(getScriptArgs()[1], 0));
    }
}
"#, &[transaction, key], &[], false).unwrap();
    assert!(repaired["stdout"]
        .as_str()
        .unwrap()
        .contains("edit-count:1"));
    assert_eq!(client.program_save().unwrap()["saved"], true);
    assert!(client.ping().unwrap());
}
