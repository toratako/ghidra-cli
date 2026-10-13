use super::RecordedBridge;
use serde_json::{json, Value};

#[cfg(target_os = "linux")]
#[test]
fn script_symlinks_cannot_redirect_execution_through_lossy_paths() {
    use std::os::unix::ffi::OsStrExt;

    let bridge = RecordedBridge::new();
    let target = bridge
        .root
        .path()
        .join(std::ffi::OsStr::from_bytes(b"Script\xff.java"));
    std::fs::write(&target, "int intended;").unwrap();
    std::fs::write(bridge.root.path().join("Script\u{fffd}.java"), "int wrong;").unwrap();
    std::os::unix::fs::symlink(&target, bridge.root.path().join("alias.java")).unwrap();

    let output = bridge
        .command()
        .args(["script", "run", "alias.java"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(diagnostic["message"].as_str().unwrap().contains("UTF-8"));
    assert!(!bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["command"] == "script_run"));
}

#[cfg(target_os = "linux")]
#[test]
fn unrepresentable_artifact_paths_fail_before_running_a_script() {
    use std::os::unix::ffi::OsStrExt;

    let bridge = RecordedBridge::new();
    let directory = bridge
        .root
        .path()
        .join(std::ffi::OsStr::from_bytes(b"artifacts\xff"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::create_dir(bridge.root.path().join("artifacts\u{fffd}")).unwrap();
    let script = bridge.root.path().join("Example.java");
    std::fs::write(&script, "int intended;").unwrap();

    for option in ["--expect", "--expect-rows"] {
        let mut command = bridge.command();
        command
            .current_dir(&directory)
            .args(["script", "run"])
            .arg(&script);
        command.args([option, "rows.jsonl"]);
        if option == "--expect-rows" {
            command.arg("1");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{option}: {output:?}");
        let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(diagnostic["message"].as_str().unwrap().contains("UTF-8"));
    }
    assert!(!bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["command"] == "script_run"));
}

#[test]
fn script_inputs_and_artifact_paths_are_prepared_by_the_client() {
    let bridge = RecordedBridge::new();
    let source = "// Java source with `literal` $text\n";
    std::fs::write(bridge.root.path().join("Example.java"), source).unwrap();
    let canonical_script = bridge
        .root
        .path()
        .join("Example.java")
        .canonicalize()
        .unwrap();
    for path in [
        "Example.java",
        "missing.java",
        "-",
        canonical_script.to_str().unwrap(),
    ] {
        let output = bridge
            .command()
            .args([
                "script",
                "run",
                path,
                "--expect-rows",
                "rows.jsonl",
                "0x2",
                "--expect-rows",
                "more rows.ndjson",
                "000",
                "--expect",
                "artifact:10",
                "--allow-empty",
                "--",
                "argument with spaces",
            ])
            .write_stdin(source)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let requests = bridge.requests.lock().unwrap();
        let request = requests.last().unwrap();
        assert_eq!(request["command"], "script_run");
        let mut expected = json!({
            "args": ["argument with spaces"],
            "expect": [
                {"path": bridge.root.path().join("artifact:10")},
                {"path": bridge.root.path().join("rows.jsonl"), "min_rows": 2},
                {"path": bridge.root.path().join("more rows.ndjson"), "min_rows": 0},
            ],
            "allow_empty": true,
        });
        if path == "-" {
            expected["source"] = json!(source);
        } else {
            let path = bridge.root.path().join(path);
            expected["path"] = json!(dunce::canonicalize(&path).unwrap_or(path));
        }
        assert_eq!(request["args"], expected);
    }
}

#[test]
fn script_expect_row_bounds_are_checked_before_sending_the_script() {
    let bridge = RecordedBridge::new();
    for minimum in [
        "1.5",
        "9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        for path in ["missing.java", "-"] {
            let output = bridge
                .command()
                .args([
                    "script",
                    "run",
                    path,
                    "--expect-rows",
                    "rows.jsonl",
                    minimum,
                ])
                .write_stdin("must not execute")
                .output()
                .unwrap();
            assert!(!output.status.success(), "{minimum}: {output:?}");
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"].as_str().unwrap().contains("MIN_ROWS"),
                "{error}"
            );
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("9223372036854775807"),
                "{error}"
            );
        }
    }
    assert!(!bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["command"] == "script_run"));
    for minimum in [0, i64::MAX] {
        bridge.run(&[
            "script",
            "run",
            "missing.java",
            "--expect-rows",
            "rows.jsonl",
            &minimum.to_string(),
        ]);
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests.last().unwrap()["args"]["expect"][0]["min_rows"],
            minimum
        );
    }
}
