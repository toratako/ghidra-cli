use super::{common, Project};
#[cfg(target_os = "linux")]
use ghidra_cli::ghidra::bridge;
use serde_json::Value;
use std::time::Duration;

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
            "--program",
            "unrelated-selection",
            "program",
            "import",
            binary.to_str().unwrap(),
            "--name",
            name,
            "--no-analyze",
        ]);
        assert_eq!(result["command"], "program import");
        assert_eq!(result["program"], name);
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
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
        "raw-name",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
    ];
    let result = project.ok(&args);
    assert_eq!(result["program"], "raw-name");
    let info = project.ok(&["program", "info"]);
    assert_eq!(info["name"], "raw-name");
    let executable_path = info["executable_path"].as_str().unwrap();
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
            .send_command(
                "analysis_run",
                Some(serde_json::json!({"program": "/raw-name"}))
            )
            .unwrap()["program"],
        "raw-name"
    );
    assert_eq!(client.analysis_run().unwrap()["program"], "raw-name");
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
    let receipt = project.ok(&["listing", "define-code", "0x8000", "--end", "0x8002"]);
    assert_eq!(receipt["landed"], true);
    let disassembly = project.ok(&["disassemble", "0x8000", "--limit", "2"]);
    assert_eq!(disassembly[0]["mnemonic"], "XOR");
    let duplicate = project.run(&args);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("Program already exists"));
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("choose another --name"));
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
        let result = project.ok(&[
            "program",
            "import",
            binary.to_str().unwrap(),
            "--no-analyze",
        ]);
        let name = result["program"].as_str().unwrap();
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
    let mut command = project.command(&["program", "import", name, "--no-analyze"]);
    command.current_dir(&inputs);
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(result["program"], name);
    project.assert_program_identity(name);

    // The running bridge takes the TCP route. An implicit name collision must
    // still get Ghidra's suffix, rather than behave like an explicit --name.
    let result = project.ok(&["program", "import", link.to_str().unwrap(), "--no-analyze"]);
    let suffixed = result["program"].as_str().unwrap();
    assert_ne!(suffixed, name);
    assert_ne!(suffixed, "actual.bin");
    project.assert_program_identity(suffixed);

    let explicit = [
        "program",
        "import",
        link.to_str().unwrap(),
        "--name",
        "chosen-name",
        "--no-analyze",
    ];
    let result = project.ok(&explicit);
    assert_eq!(result["program"], "chosen-name");
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

#[cfg(target_os = "linux")]
#[test]
fn saved_import_survives_bridge_state_directory_failure() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    let blocked = project.root.path().join("blocked-data");
    std::fs::write(&blocked, "retain").unwrap();
    let mut command = project.command(&[
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
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
            "program",
            "import",
            raw.to_str().unwrap(),
            "--name",
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
                "program",
                "import",
                raw.to_str().unwrap(),
                "--name",
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
            project.ok(&["program", "info"])["min_address"],
            "0x00009000"
        );
    }
}
