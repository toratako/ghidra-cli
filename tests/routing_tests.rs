//! CLI routing contracts, verified against recorded requests without Ghidra.

use ghidra_cli::ghidra::bridge;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn batch_path_argument(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

struct RecordedBridge {
    root: tempfile::TempDir,
    project: PathBuf,
    port: u16,
    requests: Arc<Mutex<Vec<Value>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RecordedBridge {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("routing tests' ")
            .tempdir()
            .unwrap();
        // Match CLI normalization before hashing the discovery path on Windows.
        let project = std::path::absolute(root.path().join("projects/project")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(bridge::port_file_path(&project).unwrap(), port.to_string()).unwrap();
        std::fs::write(
            bridge::pid_file_path(&project).unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(
            root.path().join("config.yaml"),
            "aliases: {}\ndefault_limit: 1\n",
        )
        .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let worker = std::thread::spawn(move || {
            let mut program = String::from("A");
            for connection in listener.incoming() {
                let mut connection = connection.unwrap();
                connection
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(&connection).read_line(&mut line).unwrap();
                if line.is_empty() {
                    continue;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                if request["command"] == "test_stop" {
                    break;
                }
                captured.lock().unwrap().push(request.clone());
                let args = &request["args"];
                let data = match request["command"].as_str().unwrap() {
                    "bridge_info" => json!({"auto_save": true}),
                    "open_program" => {
                        program = args["program"].as_str().unwrap().to_owned();
                        json!({"program": program})
                    }
                    "import" => json!({"program": "imported"}),
                    "symbol_get" => json!({"symbols": if args["name"] == "missing" {
                        vec![]
                    } else {
                        vec![
                            json!({"name": "shared", "address": "00AB", "kind": "label"}),
                            json!({"name": "shared", "address": "00CD", "kind": "function"}),
                        ]
                    }}),
                    "list_imports" | "list_exports" => {
                        let mut rows = vec![json!({"name": "first"}), json!({"name": "second"})];
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        let key = if request["command"] == "list_imports" {
                            "imports"
                        } else {
                            "exports"
                        };
                        json!({key: rows, "count": rows.len()})
                    }
                    _ => json!({"observed_program": program}),
                };
                writeln!(connection, "{}", json!({"status": "success", "data": data})).unwrap();
            }
        });
        Self {
            root,
            project,
            port,
            requests,
            worker: Some(worker),
        }
    }

    fn command(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        cmd.current_dir(self.root.path())
            .env("GHIDRA_CLI_CONFIG", self.root.path().join("config.yaml"))
            .env(
                "GHIDRA_INSTALL_DIR",
                self.root.path().join("unused-install"),
            )
            .env_remove("GHIDRA_DEFAULT_PROJECT")
            .env_remove("GHIDRA_DEFAULT_PROGRAM")
            .arg("--project")
            .arg(&self.project)
            .timeout(std::time::Duration::from_secs(15));
        cmd
    }

    fn run(&self, args: &[&str]) -> Value {
        let output = self.command().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for RecordedBridge {
    fn drop(&mut self) {
        if let Ok(mut connection) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = writeln!(connection, "{{\"command\":\"test_stop\"}}");
        }
        let _ = self.worker.take().unwrap().join();
        let _ = std::fs::remove_file(bridge::port_file_path(&self.project).unwrap());
        let _ = std::fs::remove_file(bridge::pid_file_path(&self.project).unwrap());
    }
}

#[test]
fn variable_edits_send_one_request_with_only_requested_attributes() {
    let bridge = RecordedBridge::new();
    for (flags, name, data_type) in [
        (
            vec!["--name", "header", "--type", "Header *"],
            json!("header"),
            json!("Header *"),
        ),
        (vec!["--name", "header"], json!("header"), Value::Null),
        (vec!["--type", "Header *"], Value::Null, json!("Header *")),
    ] {
        let mut args = vec![
            "function",
            "edit-var",
            "parse_header",
            "--var",
            "local_10",
            "--program",
            "B",
        ];
        args.extend(flags);
        bridge.run(&args);
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "function_edit_var")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({
                "target": "parse_header", "var_name": "local_10", "new_name": name, "type_name": data_type,
            })
        );
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        requests.clear();
    }
}

#[test]
fn batch_preserves_quoted_signatures_types_and_comments() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        r#"function set-signature parse_header --signature "int parse_header(char *buf, int len)"
function set-return-type parse_header --type 'unsigned long'
comment set 1000 'Header length includes the prefix'
"#,
    )
    .unwrap();
    let result = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(result[0]["commands_executed"], 3);
    let requests = bridge.requests.lock().unwrap();
    let edits: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .map(|r| (r["command"].clone(), r["args"].clone()))
        .collect();
    assert_eq!(
        edits,
        vec![
            (
                json!("function_set_signature"),
                json!({"target": "parse_header", "signature": "int parse_header(char *buf, int len)"}),
            ),
            (
                json!("function_set_return_type"),
                json!({"target": "parse_header", "return_type": "unsigned long"}),
            ),
            (
                json!("comment_set"),
                json!({"address": "1000", "text": "Header length includes the prefix", "comment_type": null}),
            ),
        ]
    );
}

#[test]
fn batch_unescapes_arguments_without_expanding_shell_syntax() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        concat!(
            r#"comment set 1000 "say \"hello\"; path C:\temp; slash \\; \$value"
comment set 1001 escaped\ spaces\ and\ \'quotes\'
comment set 1002 '$HOME $(echo expanded) `echo expanded` *.bin > out | cat # literal'
comment set 1003 ""
"#,
            "comment set 1004 trailing\\ \n",
        ),
    )
    .unwrap();
    bridge.run(&["batch", "batch.txt"]);
    let requests = bridge.requests.lock().unwrap();
    let comments: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "comment_set")
        .map(|r| r["args"]["text"].as_str().unwrap())
        .collect();
    assert_eq!(
        comments,
        vec![
            r#"say "hello"; path C:\temp; slash \; $value"#,
            "escaped spaces and 'quotes'",
            "$HOME $(echo expanded) `echo expanded` *.bin > out | cat # literal",
            "",
            "trailing ",
        ]
    );
}

#[test]
fn batch_reports_malformed_quoting_and_continues_with_later_lines() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "# commands\ncomment set 1000 'unfinished\ncomment set 1001 \"unfinished\ncomment set 1002 trailing\\\ncomment set 1003 'valid after errors'\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let detail = &error["detail"];
    assert_eq!(detail["commands_parsed"], 4);
    assert_eq!(detail["commands_executed"], 4);
    assert_eq!(detail["failed"], 3);
    assert_eq!(detail["not_executed"], 0);
    for (index, diagnostic) in [
        "unterminated single quote",
        "unterminated double quote",
        "trailing escape",
    ]
    .iter()
    .enumerate()
    {
        let row = &detail["results"][index];
        assert_eq!(row["line"], index + 2);
        assert_eq!(row["exit_code"], 1);
        assert!(row["error"].as_str().unwrap().contains(diagnostic), "{row}");
    }
    assert!(detail["results"][3]["result"].is_object());
    let requests = bridge.requests.lock().unwrap();
    let comments: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "comment_set")
        .collect();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0]["args"]["address"], "1003");
    assert_eq!(comments[0]["args"]["text"], "valid after errors");
}

#[test]
fn batch_on_error_controls_command_and_syntax_failures() {
    for failing_line in [
        "symbol rename missing renamed",
        "comment set 1000 'unfinished",
        "comment set",
    ] {
        for policy in [None, Some("continue"), Some("stop")] {
            let bridge = RecordedBridge::new();
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                format!("comment set 1000 before\n{failing_line}\ncomment set 1001 after\n"),
            )
            .unwrap();
            let mut command = bridge.command();
            command.args(["batch", "batch.txt"]);
            if let Some(policy) = policy {
                command.args(["--on-error", policy]);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{policy:?}: {output:?}");
            assert!(output.stdout.is_empty());
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            let detail = &error["detail"];
            let stopped = policy == Some("stop");
            assert_eq!(detail["commands_parsed"], 3);
            assert_eq!(detail["commands_executed"], if stopped { 2 } else { 3 });
            assert_eq!(detail["failed"], 1);
            assert_eq!(detail["not_executed"], usize::from(stopped));
            assert!(detail["results"][0]["result"].is_object());
            assert_eq!(detail["results"][1]["line"], 2);
            assert_eq!(detail["results"][1]["exit_code"], 1);
            let requests = bridge.requests.lock().unwrap();
            let comments: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "comment_set")
                .map(|r| r["args"]["text"].as_str().unwrap())
                .collect();
            assert_eq!(
                comments,
                if stopped {
                    vec!["before"]
                } else {
                    vec!["before", "after"]
                }
            );
        }
    }
}

#[test]
fn nested_batch_inherits_on_error_unless_overridden() {
    for (parent_policy, child_policy, expected_comments, child_stopped) in [
        ("stop", None, vec!["before"], true),
        (
            "continue",
            None,
            vec!["before", "inner-after", "outer-after"],
            false,
        ),
        (
            "stop",
            Some("continue"),
            vec!["before", "inner-after"],
            false,
        ),
        (
            "continue",
            Some("stop"),
            vec!["before", "outer-after"],
            true,
        ),
    ] {
        let bridge = RecordedBridge::new();
        let child_option = child_policy
            .map(|policy| format!(" --on-error {policy}"))
            .unwrap_or_default();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            format!(
                "comment set 1000 before\nbatch nested.txt{child_option}\ncomment set 1003 outer-after\n"
            ),
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            "symbol rename missing renamed\ncomment set 1002 inner-after\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt", "--on-error", parent_policy])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let detail = &error["detail"];
        assert_eq!(detail["failed"], 1);
        assert_eq!(detail["not_executed"], usize::from(parent_policy == "stop"));
        let nested = &detail["results"][1]["detail"];
        assert_eq!(nested["failed"], 1);
        assert_eq!(nested["not_executed"], usize::from(child_stopped));
        let requests = bridge.requests.lock().unwrap();
        let comments: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "comment_set")
            .map(|r| r["args"]["text"].as_str().unwrap())
            .collect();
        assert_eq!(comments, expected_comments);
    }
}

#[test]
fn batch_routes_each_target_and_keeps_explicit_program_switches() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(
        first.root.path().join("nested.txt"),
        "comment set 1000 nested --program C\n",
    )
    .unwrap();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "comment set 1000 marker --program B\nprogram info\nbatch nested.txt\nprogram info --project {} --program D\n",
        batch_path_argument(&second.project),
    )).unwrap();
    let result = first.run(&["batch", "batch.txt", "--program", "A"]);
    let rows = &result[0]["results"];
    assert_eq!(rows[0]["result"]["observed_program"], "B");
    assert_eq!(rows[1]["result"]["observed_program"], "B");
    assert_eq!(
        rows[2]["result"]["results"][0]["result"]["observed_program"],
        "C"
    );
    assert_eq!(rows[3]["result"]["observed_program"], "D");
    assert_eq!(
        second.requests.lock().unwrap().last().unwrap()["command"],
        "program_info"
    );
}

#[test]
fn batch_inherits_a_relative_project_directory_without_joining_it_twice() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("batch.txt"), "program info\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(bridge.root.path())
        .env("GHIDRA_CLI_CONFIG", bridge.root.path().join("config.yaml"))
        .env(
            "GHIDRA_INSTALL_DIR",
            bridge.root.path().join("unused-install"),
        )
        .env_remove("GHIDRA_PROJECT_DIR")
        .env_remove("GHIDRA_DEFAULT_PROJECT")
        .env_remove("GHIDRA_DEFAULT_PROGRAM")
        .args([
            "--projects-dir",
            "projects",
            "--project",
            "project",
            "batch",
            "batch.txt",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result[0]["results"][0]["result"]["observed_program"], "A");
}

#[test]
fn batch_save_of_a_stopped_project_does_not_start_it() {
    let bridge = RecordedBridge::new();
    let stopped = bridge.root.path().join("stopped");
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        format!("program save --project {}\n", batch_path_argument(&stopped)),
    )
    .unwrap();
    let result = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(result[0]["results"][0]["result"]["state"], "stopped");
    assert_eq!(result[0]["results"][0]["result"]["saved"], false);
}

#[test]
fn imports_and_exports_paginate_after_fetching_for_queries_and_batches() {
    let bridge = RecordedBridge::new();
    for command in ["query", "dump"] {
        for kind in ["imports", "exports"] {
            let args = [command, kind, "--offset", "1", "--limit", "1"];
            assert_eq!(bridge.run(&args), json!([{"name": "second"}]));
            std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
            assert_eq!(
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"],
                json!([{"name": "second"}])
            );
            assert_eq!(bridge.run(&[command, kind, "--count"]), json!(2));
        }
    }
}

#[test]
fn ndjson_contains_exactly_one_document_per_line() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .args(["query", "imports", "--limit", "0", "-o", "ndjson"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let output = String::from_utf8(output.stdout).unwrap();
    let rows = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![json!({"name": "first"}), json!({"name": "second"})]
    );
}

#[test]
fn os_file_paths_are_resolved_in_the_cli_working_directory() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    bridge.run(&["import", "binary", "--no-analyze"]);
    bridge.run(&["program", "export", "json", "-o", "export.json"]);
    bridge.run(&["patch", "export", "-o", "patched.bin"]);
    let requests = bridge.requests.lock().unwrap();
    for (command, key, filename) in [
        ("import", "binary_path", "binary"),
        ("program_export", "output", "export.json"),
        ("patch_export", "output", "patched.bin"),
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
fn symbol_mutations_resolve_targets_before_sending_the_edit() {
    let bridge = RecordedBridge::new();
    for (args, command, addresses) in [
        (
            vec![
                "symbol",
                "rename",
                "shared",
                "renamed",
                "--address",
                "0x00ab",
            ],
            "symbol_rename",
            json!(["00AB"]),
        ),
        (
            vec!["rename", "shared", "renamed", "--filter", "kind=function"],
            "symbol_rename",
            json!(["00CD"]),
        ),
        (
            vec!["symbol", "delete", "shared", "--all"],
            "symbol_delete",
            json!(["00AB", "00CD"]),
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&args);
        let requests = bridge.requests.lock().unwrap();
        let domain: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] != "bridge_info")
            .collect();
        assert_eq!(domain.len(), 2, "{domain:?}");
        assert_eq!(domain[0]["command"], "symbol_get");
        assert_eq!(domain[0]["args"], json!({"name": "shared"}));
        assert_eq!(domain[1]["command"], command);
        let expected = if command == "symbol_delete" {
            json!({"name": "shared", "addresses": addresses})
        } else {
            json!({"old_name": "shared", "new_name": "renamed", "addresses": addresses})
        };
        assert_eq!(domain[1]["args"], expected);
    }
}

#[test]
fn symbol_resolution_errors_never_send_a_mutation() {
    let bridge = RecordedBridge::new();
    for (args, diagnostic) in [
        (
            vec!["symbol", "delete", "missing"],
            "Symbol not found: missing",
        ),
        (
            vec!["rename", "shared", "renamed"],
            "matches 2 symbols at addresses [00AB, 00CD]",
        ),
        (
            vec!["symbol", "delete", "shared", "--address", "FFFF"],
            "No symbol named 'shared' at address FFFF",
        ),
        (
            vec![
                "symbol",
                "rename",
                "shared",
                "renamed",
                "--filter",
                "kind=absent",
            ],
            "No symbol named 'shared' matches filter 'kind=absent'",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge.command().args(args).output().unwrap();
        assert!(!output.status.success(), "{output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"].as_str().unwrap().contains(diagnostic),
            "{error}"
        );
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(requests.last().unwrap()["command"], "symbol_get");
        assert!(!requests.iter().any(|r| matches!(
            r["command"].as_str(),
            Some("symbol_rename" | "symbol_delete")
        )));
    }
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
                "--expect",
                "rows.csv:2",
                "--expect",
                "artifact:name",
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
                {"path": bridge.root.path().join("rows.csv"), "min_rows": 2},
                {"path": bridge.root.path().join("artifact:name")},
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
