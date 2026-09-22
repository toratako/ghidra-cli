use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateAnalysisModesFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("analysis modes fixture");
            try {
                for (int i = 1; i <= 4; i++) {
                    var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(i * 0x1000);
                    program.getMemory().createInitializedBlock("text_" + i, start,
                        0x100, (byte) 0, monitor, false);
                    program.getMemory().setBytes(start,
                        "The quick brown fox\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                }
                program.getMemory().createInitializedBlock("overlay",
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x6000),
                    0x100, (byte) 0, monitor, true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#;

// The public native queue APIs make work/cancellation deterministic without
// production test hooks or timing a large analyzer. The actual string analyzer
// distinguishes reanalysis seeds from an empty queue and from full analysis.
const QUEUE_ANALYSIS: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public class QueueAnalysisModesFixture extends GhidraScript {
    public void run() {
        String mode = getScriptArgs()[0];
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.blockAdded(new AddressSet(space.getAddress(0x2000), space.getAddress(0x20ff)));
        if (mode.equals("native")) return;
        var analyzer = new AbstractAnalyzer("CLI Analysis Mode Probe", "Deterministic native analysis work",
                AnalyzerType.BYTE_ANALYZER) {
            { setPriority(AnalysisPriority.HIGHEST_PRIORITY); }
            public boolean added(Program program, AddressSetView set, TaskMonitor taskMonitor, MessageLog log) {
                if (mode.equals("cancel")) {
                    program.getListing().setComment(space.getAddress(0x1000), CodeUnit.EOL_COMMENT, "saved-partial-analysis");
                    taskMonitor.cancel();
                    return false;
                }
                program.getListing().setComment(space.getAddress(0x3000), CodeUnit.EOL_COMMENT, "derived-analysis");
                // Enqueue fresh native work while draining this pass. Its seed
                // is outside both the CLI range and the earlier pending range.
                manager.blockAdded(new AddressSet(space.getAddress(0x3000), space.getAddress(0x30ff)));
                return true;
            }
        };
        manager.scheduleOneTimeAnalysis(analyzer, new AddressSet(space.getAddress(0x1000)));
    }
}
"#;

fn create_fixture(client: &BridgeClient) -> String {
    let name = format!("analysis-modes-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, std::slice::from_ref(&name), &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    client.analysis_option_set("ASCII Strings", "true").unwrap();
    client
        .analysis_option_set("ASCII Strings.Minimum String Length", "LEN_4")
        .unwrap();
    name
}

fn queue(client: &BridgeClient, mode: &str) {
    client
        .script_run_source(QUEUE_ANALYSIS, &[mode.to_owned()], &[], false)
        .unwrap();
}

fn run(client: &BridgeClient, args: Value, mode: &str) -> Value {
    let receipt = client.send_command("analysis_run", Some(args)).unwrap();
    assert_eq!(receipt["mode"], mode, "{receipt}");
    assert_eq!(receipt["completed"], true, "{receipt}");
    assert_eq!(receipt["saved"], true, "{receipt}");
    receipt
}

fn string_addresses(client: &BridgeClient) -> Vec<String> {
    client.list_strings(None, None, None).unwrap()["strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["address"].as_str().unwrap().to_owned())
        .collect()
}

fn assert_analyzed(client: &BridgeClient, name: &str, expected: bool) {
    let listing = client.list_programs().unwrap();
    let row = listing["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap();
    if expected {
        assert_eq!(row["analyzed"], true, "{row}");
    } else {
        assert!(
            row["analyzed"].is_null() || row["analyzed"] == false,
            "{row}"
        );
    }
}

fn remove_fixture(client: &BridgeClient, name: &str) {
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(name).unwrap();
}

#[test]
#[serial]
fn analysis_modes_apply_saved_settings_and_only_full_marks_analyzed() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client);

    run(&client, json!({"pending": true}), "pending");
    assert!(string_addresses(&client).is_empty());
    assert_analyzed(&client, &name, false);
    let range = json!({"start": "0x0", "end": "0x10ff"});
    client
        .analysis_option_set("ASCII Strings", "false")
        .unwrap();
    run(&client, range.clone(), "range");
    assert!(string_addresses(&client).is_empty());
    client.analysis_option_set("ASCII Strings", "true").unwrap();
    client
        .analysis_option_set("ASCII Strings.Minimum String Length", "LEN_25")
        .unwrap();
    run(&client, range.clone(), "range");
    assert!(string_addresses(&client).is_empty());
    client
        .analysis_option_set("ASCII Strings.Minimum String Length", "LEN_4")
        .unwrap();
    let receipt = run(&client, range, "range");
    // Receipt reports the requested bounds, including the unmapped prefix.
    assert_eq!(receipt["start"], "0x00000000");
    assert_eq!(receipt["end"], "0x000010ff");
    assert_eq!(string_addresses(&client), ["0x00001000"]);
    assert_analyzed(&client, &name, false);

    queue(&client, "native");
    client
        .analysis_option_set("ASCII Strings.Minimum String Length", "LEN_25")
        .unwrap();
    run(&client, json!({"pending": true}), "pending");
    assert_eq!(string_addresses(&client), ["0x00001000"]);
    client
        .analysis_option_set("ASCII Strings.Minimum String Length", "LEN_4")
        .unwrap();
    run(&client, json!({"pending": true}), "pending");
    assert_eq!(string_addresses(&client), ["0x00001000"]);
    queue(&client, "native");
    run(&client, json!({"pending": true}), "pending");
    assert_eq!(string_addresses(&client), ["0x00001000", "0x00002000"]);
    assert_analyzed(&client, &name, false);

    client
        .analysis_option_set("ASCII Strings", "false")
        .unwrap();
    run(&client, json!({}), "full");
    assert_eq!(string_addresses(&client).len(), 2);
    assert_analyzed(&client, &name, true);
    client.analysis_option_set("ASCII Strings", "true").unwrap();
    run(&client, json!({}), "full");
    let addresses = string_addresses(&client);
    assert_eq!(addresses.len(), 4);
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    assert_eq!(string_addresses(&client), addresses);
    assert_analyzed(&client, &name, true);
    remove_fixture(&client, &name);
}

#[test]
#[serial]
fn analysis_range_drains_outside_pending_and_derived_work_but_reopen_loses_queue() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client);
    queue(&client, "derived");
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    run(&client, json!({"pending": true}), "pending");
    assert!(
        string_addresses(&client).is_empty(),
        "reopen must not restore the queue"
    );
    queue(&client, "derived");
    run(
        &client,
        json!({"start": "0x1000", "end": "0x10ff"}),
        "range",
    );
    assert_eq!(
        string_addresses(&client),
        ["0x00001000", "0x00002000", "0x00003000"]
    );
    assert_analyzed(&client, &name, false);
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    assert_eq!(string_addresses(&client).len(), 3);
    assert!(client.comment_get("0x3000").unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == "derived-analysis"));
    assert_analyzed(&client, &name, false);
    remove_fixture(&client, &name);
}

#[test]
#[serial]
fn analysis_rejects_invalid_wire_ranges_without_expanding_to_full() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client);
    for (args, message) in [
        (json!({"start": "0x1000"}), "together"),
        (json!({"pending": "true"}), "boolean"),
        (json!({"start": null, "end": "0x10ff"}), "string"),
        (
            json!({"pending": true, "start": "0x1000", "end": "0x10ff"}),
            "cannot be combined",
        ),
        (
            json!({"start": "entry", "end": "0x10ff"}),
            "explicit addresses",
        ),
        (
            json!({"start": "0x1100", "end": "0x1000"}),
            "must not exceed",
        ),
        (
            json!({"start": "0x1000", "end": "overlay:0x6000"}),
            "same address space",
        ),
        (
            json!({"start": "0x100000000", "end": "0x100000001"}),
            "Invalid address",
        ),
        (
            json!({"start": "0x5000", "end": "0x50ff"}),
            "no program memory",
        ),
    ] {
        let error = client
            .send_command("analysis_run", Some(args.clone()))
            .unwrap_err();
        assert!(error.to_string().contains(message), "{args}: {error}");
        assert!(string_addresses(&client).is_empty(), "{args}");
        assert_analyzed(&client, &name, false);
    }
    // Inclusive single-address seeds are valid, including the final memory byte.
    run(
        &client,
        json!({"start": "0x10ff", "end": "0x10ff"}),
        "range",
    );
    assert!(string_addresses(&client).is_empty());
    remove_fixture(&client, &name);
}

#[test]
#[serial]
fn analysis_cancellation_saves_partial_work_and_pending_does_not_resume_it() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    for (args, mode) in [
        (json!({}), "full"),
        (json!({"start": "0x1000", "end": "0x10ff"}), "range"),
        (json!({"pending": true}), "pending"),
    ] {
        let name = create_fixture(&client);
        queue(&client, "cancel");
        let error = client.send_command("analysis_run", Some(args)).unwrap_err();
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(detail["mode"], mode, "{error:#}");
        assert_eq!(detail["completed"], false);
        assert_eq!(detail["cancelled"], true);
        assert_eq!(detail["saved"], true);
        assert_eq!(detail["partial_changes_saved"], true);
        if mode == "range" {
            assert_eq!(detail["start"], "0x00001000");
            assert_eq!(detail["end"], "0x000010ff");
        }
        assert_analyzed(&client, &name, false);
        run(&client, json!({"pending": true}), "pending");
        assert!(
            string_addresses(&client).is_empty(),
            "cancelled native work must be dropped"
        );
        assert_analyzed(&client, &name, false);
        client.program_close().unwrap();
        client.open_program(&name).unwrap();
        assert!(client.comment_get("0x1000").unwrap()["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|comment| comment["text"] == "saved-partial-analysis"));
        assert_analyzed(&client, &name, false);
        run(
            &client,
            json!({"start": "0x1000", "end": "0x10ff"}),
            "range",
        );
        assert_eq!(string_addresses(&client), ["0x00001000"]);
        assert_analyzed(&client, &name, false);
        remove_fixture(&client, &name);
    }
}
