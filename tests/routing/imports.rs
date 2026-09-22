use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};
use std::path::PathBuf;

#[test]
fn program_import_keeps_saved_names_and_selection_separate_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_program: configured-target\n",
    )
    .unwrap();
    for name in [None, Some("saved name")] {
        for no_analyze in [false, true] {
            let mut args = vec!["program", "import", "binary"];
            if let Some(name) = name {
                args.extend(["--name", name]);
            }
            if no_analyze {
                args.push("--no-analyze");
            }
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                format!("{}\nprogram info\n", batch_arguments(&args)),
            )
            .unwrap();
            for batched in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let mut command = bridge.command();
                command.args(["--program", "existing-target"]);
                if batched {
                    command.args(["batch", "batch.txt"]);
                } else {
                    command.args(&args);
                }
                let output = command.output().unwrap();
                assert!(output.status.success(), "{args:?}: {output:?}");
                assert!(output.stderr.is_empty(), "JSON modes suppress progress");
                let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
                let receipt = if batched {
                    assert_eq!(result["failed"], 0, "{result}");
                    assert_eq!(
                        result["results"][1]["result"]["data"]["observed_program"],
                        "imported"
                    );
                    &result["results"][0]["result"]["data"]
                } else {
                    &result
                };
                assert_eq!(receipt["command"], "program import");
                assert_eq!(receipt["program"], "imported");
                assert_eq!(receipt["status"], "success");
                assert_eq!(receipt["data"]["analyze"].is_null(), no_analyze);
                if !no_analyze {
                    assert_eq!(receipt["data"]["analyze"]["program"], "imported");
                }

                let requests = bridge.requests.lock().unwrap();
                let import_index = requests
                    .iter()
                    .position(|r| r["command"] == "import")
                    .unwrap();
                let import = &requests[import_index];
                assert_eq!(import["args"]["program"], json!(name));
                let selected: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] == "open_program")
                    .map(|r| r["args"]["program"].as_str().unwrap())
                    .collect();
                assert_eq!(
                    selected,
                    if batched {
                        vec!["existing-target", "imported"]
                    } else {
                        vec!["imported"]
                    }
                );
                assert_eq!(requests[import_index + 1]["command"], "open_program");
                assert_eq!(
                    requests
                        .iter()
                        .filter(|r| r["command"] == "analysis_run")
                        .count(),
                    usize::from(!no_analyze)
                );
            }
        }
    }
}

#[test]
fn invalid_import_name_fails_before_bridge_changes() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    let output = bridge
        .command()
        .args([
            "program",
            "import",
            "binary",
            "--name",
            "../outside",
            "--language",
            "x86:LE:32:default",
            "--no-analyze",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("--name must be a single non-empty file name"),
        "{error}"
    );
    assert_eq!(error["detail"]["import_status"], "not_started");
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn os_file_paths_are_resolved_in_the_cli_working_directory() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    bridge.run(&["program", "import", "binary", "--no-analyze"]);
    bridge.run(&["program", "export", "c", "-o", "export.c"]);
    let requests = bridge.requests.lock().unwrap();
    for (command, key, filename) in [
        ("import", "binary_path", "binary"),
        ("program_export", "output", "export.c"),
    ] {
        let request = requests.iter().find(|r| r["command"] == command).unwrap();
        let actual = PathBuf::from(request["args"][key].as_str().unwrap());
        assert!(actual.is_absolute(), "{request}");
        assert!(
            !actual.to_string_lossy().starts_with(r"\\?\"),
            "Ghidra must receive an ordinary Windows path: {request}"
        );
        assert_eq!(actual.file_name().unwrap(), filename);
        assert_eq!(
            actual.parent().unwrap().canonicalize().unwrap(),
            bridge.root.path().canonicalize().unwrap()
        );
    }
}

#[test]
fn explicit_address_import_bases_are_checked_before_import_or_bridge_changes() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    for flags in [
        vec!["--base-address", "8000"],
        vec!["--base-address", "FUN_00008000"],
        vec!["--loader-option", "baseAddr=8000"],
        vec!["--loader-option", "BASEADDR=8000"],
        vec!["--loader-option", "baseAddr=ram:8000"],
    ] {
        let output = bridge
            .command()
            .args(["program", "import", "binary", "--no-analyze"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{flags:?}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let message = error["message"].as_str().unwrap();
        assert!(
            message.contains("Invalid base address"),
            "{flags:?}: {error}"
        );
        assert!(message.contains("0x-prefixed"), "{flags:?}: {error}");
        assert!(
            bridge.requests.lock().unwrap().is_empty(),
            "Invalid base addresses must not stop the running bridge or start an import"
        );
    }
}
