use super::Project;
use serde_json::Value;

#[test]
fn analysis_run_reanalyzes_with_changed_settings() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    let text = "The quick brown fox";
    std::fs::write(&raw, format!("{text}\0")).unwrap();
    project.ok(&[
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
        "strings-raw",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
        "--no-analyze",
    ]);
    let client = project.client();
    let strings = || project.ok(&["string", "list", "--limit", "0"]);
    assert_eq!(strings(), serde_json::json!([]));
    project.ok(&["analysis", "option", "set", "ASCII Strings", "false"]);
    let first = project.ok(&["analysis", "run"]);
    assert_eq!(first["command"], "analysis run");
    assert_eq!(first["status"], "success");
    assert_eq!(first["data"]["status"], "success");
    assert_eq!(first["data"]["program"], "strings-raw");
    assert!(first["data"]["function_count"].is_u64());
    assert_eq!(strings(), serde_json::json!([]));
    assert_eq!(
        client.list_programs().unwrap()["programs"][0]["analyzed"],
        true
    );

    project.ok(&["analysis", "option", "set", "ASCII Strings", "true"]);
    assert_eq!(
        strings(),
        serde_json::json!([]),
        "setting alone must not analyze"
    );
    let minimum = "ASCII Strings.Minimum String Length";
    let option = project.ok(&["analysis", "option", "get", minimum]);
    assert_eq!(option["type"], "enum");
    assert!(option["choices"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("LEN_25")));
    project.ok(&["analysis", "option", "set", minimum, "LEN_25"]);
    project.ok(&["analysis", "run"]);
    assert_eq!(
        strings(),
        serde_json::json!([]),
        "detailed settings must affect analysis"
    );
    project.ok(&["analysis", "option", "set", minimum, "LEN_4"]);
    assert_eq!(
        strings(),
        serde_json::json!([]),
        "setting alone must not reanalyze"
    );
    let second = project.ok(&["analysis", "run"]);
    assert_eq!(second["data"]["status"], "success");
    let rows = strings();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["value"] == text),
        "reanalyzing an already-analyzed program must use the new settings: {rows}"
    );
    client.program_close().unwrap();
    assert_eq!(
        client.list_programs().unwrap()["programs"][0]["analyzed"],
        true
    );
    client.open_program("strings-raw").unwrap();
    assert_eq!(strings(), rows, "analysis results must survive reopening");
}

#[test]
fn analysis_completion_flags_survive_import_reanalysis_and_cancellation() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    // No entry point or function is needed to record a completed analysis.
    project.ok(&[
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
        "analyzed-raw",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
    ]);
    let client = project.client();
    let assert_flag = |name: &str, expected: Value| {
        let listing = project.client().list_programs().unwrap();
        let row = listing["programs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        assert!(row["function_count"].as_u64().unwrap() <= 1, "{row}");
        assert_eq!(row.get("analyzed"), Some(&expected), "{row}");
    };
    assert_flag("analyzed-raw", serde_json::json!(true));
    client.program_close().unwrap();
    assert_flag("analyzed-raw", serde_json::json!(true));
    project.ok(&[
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
        "skipped-raw",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
        "--no-analyze",
    ]);
    // Imports with explicit loader settings restart the bridge.
    let client = project.client();
    let skipped = client.list_programs().unwrap();
    let skipped = skipped["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "skipped-raw")
        .unwrap();
    // Opening initializes Ghidra's default false option; an unregistered or
    // unavailable saved flag remains null. Neither records completed analysis.
    assert!(
        skipped["analyzed"].is_null() || skipped["analyzed"] == false,
        "{skipped}"
    );
    client.analysis_run().unwrap();
    assert_flag("skipped-raw", serde_json::json!(true));

    let prepare = |flag: &str, cancel: bool| {
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public class PrepareAnalysisCompletionTest extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions(Program.PROGRAM_INFO);
        options.removeOption(Program.ANALYZED_OPTION_NAME);
        String flag = getScriptArgs()[0];
        if (!flag.equals("missing")) options.setBoolean(Program.ANALYZED_OPTION_NAME, Boolean.parseBoolean(flag));
        if (Boolean.parseBoolean(getScriptArgs()[1])) {
            var analyzer = new AbstractAnalyzer("Cancel Completion Test", "Cancel analysis deterministically", AnalyzerType.BYTE_ANALYZER) {
                { setPriority(AnalysisPriority.HIGHEST_PRIORITY); }
                public boolean added(Program program, AddressSetView set, TaskMonitor taskMonitor, MessageLog log) {
                    taskMonitor.cancel();
                    return false;
                }
            };
            AutoAnalysisManager.getAnalysisManager(currentProgram)
                .scheduleOneTimeAnalysis(analyzer, currentProgram.getMemory());
        }
    }
}
"#, &[flag.to_owned(), cancel.to_string()], &[], false).unwrap();
    };
    prepare("false", false);
    assert_flag("skipped-raw", serde_json::json!(false));
    client.analysis_run().unwrap();
    assert_flag("skipped-raw", serde_json::json!(true));
    client.program_close().unwrap();
    assert_flag("skipped-raw", serde_json::json!(true));
    client.open_program("skipped-raw").unwrap();

    for (flag, expected) in [
        ("missing", Value::Null),
        ("false", serde_json::json!(false)),
        ("true", serde_json::json!(true)),
    ] {
        prepare(flag, true);
        let error = client
            .analysis_run()
            .expect_err("cancelled analysis must fail");
        assert!(
            error.to_string().contains("Operation cancelled"),
            "{flag}: {error}"
        );
        assert_flag("skipped-raw", expected.clone());
        client.program_close().unwrap();
        assert_flag("skipped-raw", expected);
        client.open_program("skipped-raw").unwrap();
    }
    // Per-job cancellation must not affect the next completed analysis or save.
    client.analysis_run().unwrap();
    project.ok(&["bridge", "stop"]);
    project.ok(&["bridge", "start", "--program", "skipped-raw"]);
    let listing = project.client().list_programs().unwrap();
    assert!(
        listing["programs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["analyzed"] == true),
        "{listing}"
    );
}
