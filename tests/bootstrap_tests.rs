//! Durable import checkpoints, saved names, and real doctor startup.
use ghidra_cli::ghidra::bridge;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

#[macro_use]
mod common;

struct Project {
    root: tempfile::TempDir,
    path: PathBuf,
}
impl Project {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("bootstrap tests ")
            .tempdir()
            .unwrap();
        let path = root.path().join("project");
        Self { root, path }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .args(args)
            .arg("--project")
            .arg(&self.path)
            .arg("--json");
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        common::run_command_with_output(&mut self.command(args), Duration::from_secs(240)).unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn raw(&self) -> PathBuf {
        let path = self.root.path().join("original's file.bin");
        std::fs::write(&path, [0x31, 0xc0, 0xc3]).unwrap();
        path
    }
    fn client(&self) -> ghidra_cli::ipc::client::BridgeClient {
        ghidra_cli::ipc::client::BridgeClient::new(
            bridge::is_bridge_running(&self.path).expect("test bridge is running"),
        )
    }
    fn assert_program_identity(&self, name: &str) {
        let path = format!("/{name}");
        let command = ["program", "info"];
        let result = self.ok(&command);
        assert_eq!(result[0]["name"], name, "{command:?}: {result}");
        assert_eq!(result[0]["path"], path, "{command:?}: {result}");
        let client = self.client();
        assert_eq!(
            client.list_programs().unwrap()["current_program_name"],
            name
        );
        let state = client.bridge_info().unwrap();
        assert_eq!(state["current_program"], name);
        assert_eq!(state["current_program_path"], path);
        assert_eq!(client.stats().unwrap()["stats"]["program_name"], name);
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        bridge::stop_bridge(&self.path).expect("stop test bridge before deleting its project");
    }
}

#[test]
fn configured_startup_targets_apply_to_all_entry_points() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    project.ok(&[
        "import",
        raw.to_str().unwrap(),
        "--program",
        "configured-program",
        "--language",
        "x86:LE:32:default",
        "--no-analyze",
    ]);
    let config = project.root.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    // Preserve runtime settings and exercise config-only installation lookup,
    // even when the test runner selects Ghidra through the environment.
    test_config.ghidra_install_dir = Some(test_config.get_ghidra_install_dir().unwrap());
    test_config.default_project = Some(project.path.to_str().unwrap().to_owned());
    test_config.default_program = Some("configured-program".to_owned());
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    let batch = project.root.path().join("batch.txt");
    std::fs::write(&batch, "program imports\nprogram exports\n").unwrap();
    for args in [
        vec!["bridge", "start"],
        vec!["program", "imports"],
        vec!["batch", batch.to_str().unwrap()],
    ] {
        project.ok(&["bridge", "stop"]);
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .args(&args)
            .arg("--json")
            .env("GHIDRA_CLI_CONFIG", &config)
            .env_remove("GHIDRA_INSTALL_DIR");
        let output =
            common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        project.assert_program_identity("configured-program");
    }
}

#[test]
fn import_names_are_saved_and_selected_across_all_routes() {
    require_ghidra!();
    let project = Project::new();
    let binary = common::fixture_binary();
    for name in ["fresh-name", "running-name", "stopped-name"] {
        if name == "stopped-name" {
            project.ok(&["bridge", "stop"]);
        }
        let result = project.ok(&[
            "import",
            binary.to_str().unwrap(),
            "--program",
            name,
            "--no-analyze",
        ]);
        assert_eq!(result[0]["program"], name);
        project.assert_program_identity(name);
        let programs = project.ok(&["program", "list"]);
        assert!(
            programs
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == name && p["current"] == true),
            "{programs}"
        );
    }
    let raw = project.raw();
    let args = [
        "import",
        raw.to_str().unwrap(),
        "--program",
        "raw-name",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
    ];
    let result = project.ok(&args);
    assert_eq!(result[0]["program"], "raw-name");
    let info = project.ok(&["program", "info"]);
    assert_eq!(info[0]["name"], "raw-name");
    let executable_path = info[0]["executable_path"].as_str().unwrap();
    // Ghidra's local FSRL paths use /C:/... for Windows drive paths.
    #[cfg(windows)]
    let executable_path = executable_path
        .strip_prefix('/')
        .filter(|path| {
            matches!(
                path.as_bytes(),
                [drive, b':', b'/', ..] if drive.is_ascii_alphabetic()
            )
        })
        .unwrap_or(executable_path);
    assert_eq!(
        dunce::canonicalize(executable_path).unwrap_or_else(|error| {
            panic!("Cannot resolve executable_path {executable_path:?}: {error}; info={info}")
        }),
        dunce::canonicalize(&raw).unwrap()
    );
    project.assert_program_identity("raw-name");
    let client = project.client();
    assert_eq!(client.program_save().unwrap()["program"], "raw-name");
    assert_eq!(client.program_close().unwrap()["program"], "raw-name");
    let closed = client.bridge_info().unwrap();
    assert_eq!(closed["has_current_program"], false);
    assert!(closed["current_program_path"].is_null());
    assert!(closed.get("current_program").is_none());
    assert_eq!(
        client.open_program("/raw-name").unwrap()["program"],
        "raw-name"
    );
    assert_eq!(
        client
            .send_command("analyze", Some(serde_json::json!({"program": "/raw-name"})))
            .unwrap()["program"],
        "raw-name"
    );
    assert_eq!(client.analyze().unwrap()["program"], "raw-name");
    let artifact = project.root.path().join("internal-name.txt");
    let result = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
public class CheckProgramIdentity extends GhidraScript {
    public void run() throws Exception {
        Files.writeString(Path.of(getScriptArgs()[0]), currentProgram.getName());
    }
}
"#,
            &[artifact.to_str().unwrap().to_owned()],
            &[serde_json::json!({"path": artifact})],
            false,
        )
        .unwrap();
    assert_eq!(result["artifacts"][0]["program"], "raw-name");
    assert_eq!(
        std::fs::read_to_string(&artifact).unwrap(),
        raw.file_name().unwrap().to_str().unwrap()
    );
    project.ok(&["bridge", "stop"]);
    project.ok(&["bridge", "start", "--program", "raw-name"]);
    project.assert_program_identity("raw-name");
    let receipt = project.ok(&["define-code", "0x8000", "--end", "0x8002"]);
    assert_eq!(receipt[0]["landed"], true);
    let disassembly = project.ok(&["disassemble", "0x8000", "--limit", "2"]);
    assert_eq!(disassembly[0]["mnemonic"], "XOR");
    let duplicate = project.run(&args);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("Program already exists"));
    let programs = project.ok(&["program", "list"]);
    let names: Vec<_> = programs
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 4, "{programs}");
    assert!(!names.contains(&raw.file_name().unwrap().to_str().unwrap()));
    // Without an explicit name, Ghidra may choose a suffix; return and select
    // the real saved file rather than the original input name.
    for _ in 0..2 {
        let result = project.ok(&["import", binary.to_str().unwrap(), "--no-analyze"]);
        let name = result[0]["program"].as_str().unwrap();
        project.assert_program_identity(name);
        let selected = project.ok(&["program", "list"]);
        assert!(
            selected
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == name && row["current"] == true),
            "{selected}"
        );
    }
}

#[test]
fn import_symlinks_preserve_input_names_and_collision_rules() {
    require_ghidra!();
    let project = Project::new();
    let inputs = project.root.path().join("input files' directory");
    std::fs::create_dir(&inputs).unwrap();
    let binary = inputs.join("actual.bin");
    std::fs::copy(common::fixture_binary(), &binary).unwrap();
    let name = "release binary.bin";
    let link = inputs.join(name);
    #[cfg(unix)]
    std::os::unix::fs::symlink("actual.bin", &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("actual.bin", &link)
        .expect("file symlink creation requires Developer Mode or symlink privileges");

    // A fresh project takes the one-shot route. Resolve this relative input
    // against the CLI's CWD while preserving the link's name for saving.
    let mut command = project.command(&["import", name, "--no-analyze"]);
    command.current_dir(&inputs);
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result[0]["program"], name);
    project.assert_program_identity(name);

    // The running bridge takes the TCP route. An implicit name collision must
    // still get Ghidra's suffix, rather than behave like an explicit --program.
    let result = project.ok(&["import", link.to_str().unwrap(), "--no-analyze"]);
    let suffixed = result[0]["program"].as_str().unwrap();
    assert_ne!(suffixed, name);
    assert_ne!(suffixed, "actual.bin");
    project.assert_program_identity(suffixed);

    let explicit = [
        "import",
        link.to_str().unwrap(),
        "--program",
        "chosen-name",
        "--no-analyze",
    ];
    let result = project.ok(&explicit);
    assert_eq!(result[0]["program"], "chosen-name");
    project.assert_program_identity("chosen-name");
    let duplicate = project.run(&explicit);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("Program already exists"));
    let programs = project.ok(&["program", "list"]);
    let programs = programs.as_array().unwrap();
    assert_eq!(programs.len(), 3);
    assert!(programs
        .iter()
        .all(|program| program["name"] != "actual.bin"));
}

#[test]
fn analyze_reanalyzes_with_changed_settings() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    let text = "The quick brown fox jumps over the lazy dog.";
    std::fs::write(&raw, format!("{text}\0")).unwrap();
    project.ok(&[
        "import",
        raw.to_str().unwrap(),
        "--program",
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
    project.ok(&["analyzer", "set", "ASCII Strings", "false"]);
    let first = project.ok(&["analyze"]);
    assert_eq!(first[0]["command"], "analyze");
    assert_eq!(first[0]["status"], "success");
    assert_eq!(first[0]["data"]["status"], "success");
    assert_eq!(first[0]["data"]["program"], "strings-raw");
    assert!(first[0]["data"]["function_count"].is_u64());
    assert_eq!(strings(), serde_json::json!([]));
    assert_eq!(
        client.list_programs().unwrap()["programs"][0]["analyzed"],
        true
    );

    project.ok(&["analyzer", "set", "ASCII Strings", "true"]);
    assert_eq!(
        strings(),
        serde_json::json!([]),
        "setting alone must not analyze"
    );
    let second = project.ok(&["analyze"]);
    assert_eq!(second[0]["data"]["status"], "success");
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
        "import",
        raw.to_str().unwrap(),
        "--program",
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
        "import",
        raw.to_str().unwrap(),
        "--program",
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
    client.analyze().unwrap();
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
    client.analyze().unwrap();
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
        let error = client.analyze().expect_err("cancelled analysis must fail");
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
    client.analyze().unwrap();
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

#[cfg(target_os = "linux")]
#[test]
fn saved_import_survives_bridge_state_directory_failure() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    let blocked = project.root.path().join("blocked-data");
    std::fs::write(&blocked, "retain").unwrap();
    let mut command = project.command(&[
        "import",
        raw.to_str().unwrap(),
        "--program",
        "saved-name",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
        "--no-analyze",
    ]);
    command.env("XDG_DATA_HOME", &blocked);
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let detail = &error["detail"];
    assert_eq!(detail["stage"], "bridge.state_directory", "{error}");
    assert_eq!(detail["path"], blocked.join("ghidra-cli").to_str().unwrap());
    assert_eq!(detail["import_status"], "saved");
    assert_eq!(detail["analysis_status"], "skipped");
    assert_eq!(detail["program"], "saved-name");
    assert_eq!(detail["recovery"][1], "bridge");
    assert_eq!(detail["recovery"][2], "start");
    project.ok(&["bridge", "start", "--program", "saved-name"]);
    let programs = project.ok(&["program", "list"]);
    assert!(
        programs
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "saved-name" && p["current"] == true),
        "{programs}"
    );
    assert_eq!(std::fs::read_to_string(blocked).unwrap(), "retain");
    project.ok(&["bridge", "stop"]);
    let missing = project.run(&["bridge", "start", "--program", "missing-program"]);
    assert!(!missing.status.success());
    let error: Value = serde_json::from_slice(&missing.stderr).unwrap();
    assert_eq!(error["detail"]["stage"], "bridge.program_open", "{error}");
    assert_eq!(error["detail"]["path"], "missing-program");
    assert!(bridge::is_bridge_running(&project.path).is_none());
}

#[test]
fn unsupported_loader_options_never_save_a_program() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    for name in ["fresh-invalid", "existing-invalid"] {
        let output = project.run(&[
            "import",
            raw.to_str().unwrap(),
            "--program",
            name,
            "--loader",
            "BinaryLoader",
            "--language",
            "x86:LE:32:default",
            "--loader-option",
            "baseAdrr=0x9000",
            "--no-analyze",
        ]);
        assert!(!output.status.success(), "{output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["detail"]["stage"], "import.options", "{error}");
        assert_eq!(error["detail"]["import_status"], "not_started");
        assert_eq!(error["detail"]["option"], "-loader-baseAdrr");
        if name == "fresh-invalid" {
            project.ok(&[
                "import",
                raw.to_str().unwrap(),
                "--program",
                "valid",
                "--loader",
                "BinaryLoader",
                "--language",
                "x86:LE:32:default",
                "--loader-option",
                "baseAddr=0x9000",
                "--no-analyze",
            ]);
        } else {
            project.ok(&["bridge", "start", "--program", "valid"]);
        }
        let programs = project.ok(&["program", "list"]);
        assert_eq!(programs.as_array().unwrap().len(), 1, "{programs}");
        assert_eq!(programs[0]["name"], "valid");
        assert_eq!(
            project.ok(&["program", "info"])[0]["min_address"],
            "0x00009000"
        );
    }
}

#[test]
fn doctor_runtime_checks_real_jvm_and_removes_disposable_project() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("doctor tests ")
        .tempdir()
        .unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--runtime", "--json"])
        .env("GHIDRA_PROJECT_DIR", root.path());
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["runtime"]["status"], "success", "{result}");
    assert_eq!(result["loopback"]["ok"], true);
    assert!(Path::new(
        result["runtime"]["paths"]["ghidra_settings"]
            .as_str()
            .unwrap()
    )
    .is_dir());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
