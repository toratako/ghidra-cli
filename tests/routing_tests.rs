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

fn batch_arguments(args: &[&str]) -> String {
    args.iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn symbol_fixture(id: &str, address: &str, kind: &str) -> Value {
    json!({
        "id": id, "name": "shared", "address": address, "namespace": "Global",
        "type": kind, "kind": kind, "source": "USER_DEFINED", "is_primary": true,
        "address_space": "ram", "is_default_address_space": true,
    })
}

fn call_rows_fixture() -> Vec<Value> {
    vec![
        json!({"caller": "entry", "caller_address": "0x1000", "callee": "helper", "callee_address": "0x2000", "call_site": "0x1010", "destination": "0x2000", "via": "0x2000", "type": "UNCONDITIONAL_CALL", "depth": 0}),
        json!({"caller": "entry", "caller_address": "0x1000", "callee": null, "callee_address": "0x9000", "call_site": "0x1020", "destination": "0x9000", "via": "0x9000", "type": "UNCONDITIONAL_CALL", "depth": 0}),
        json!({"caller": "helper", "caller_address": "0x2000", "callee": "leaf", "callee_address": "0x3000", "call_site": "0x2010", "destination": "0x3004", "via": "0x3004", "type": "UNCONDITIONAL_CALL", "depth": 1}),
    ]
}

fn call_graph_fixture() -> Value {
    let nodes = vec![
        json!({"id": "0x1000", "address": "0x1000", "name": "zeta"}),
        json!({"id": "0x2000", "address": "0x2000", "name": "alpha"}),
        json!({"id": "0x3000", "address": "0x3000", "name": "beta"}),
        json!({"id": "0x4000", "address": "0x4000", "name": "omega"}),
    ];
    let edges: Vec<_> = [
        (0, Some(1)),
        (1, Some(2)),
        (1, None),
        (2, Some(0)),
        (3, Some(2)),
    ]
    .into_iter()
    .enumerate()
    .map(|(site, (from, to))| {
        let caller = &nodes[from];
        let callee = to.map(|i| &nodes[i]);
        let destination = callee.map(|n| n["id"].clone()).unwrap_or(json!("0x9000"));
        json!({
            "from": caller["id"], "to": destination,
            "caller": caller["name"], "caller_address": caller["id"],
            "callee": callee.map(|n| &n["name"]), "callee_address": destination,
            "call_site": format!("0x{:x}", 0x5000 + site), "destination": destination, "via": destination,
            "type": "UNCONDITIONAL_CALL",
        })
    })
    .collect();
    json!({"node_count": nodes.len(), "edge_count": edges.len(), "nodes": nodes, "edges": edges})
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
        Self::with_info(
            json!({"auto_save": true, "atomic_edits": true, "named_import": true, "explicit_addresses": true}),
        )
    }

    fn with_info(bridge_info: Value) -> Self {
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
        std::fs::write(root.path().join("config.yaml"), "default_limit: 1\n").unwrap();
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
                if args["text"] == "test-save-failure" {
                    writeln!(connection, "{}", json!({"status": "error", "message": "Save failed", "detail": {"save_failed": true}})).unwrap();
                    continue;
                }
                if args["text"] == "test-timeout" {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }
                let data = match request["command"].as_str().unwrap() {
                    "bridge_info" => bridge_info.clone(),
                    "status" => json!({
                        "bridge_state": "running", "queue_depth": 0,
                        "active_job": null, "queued_jobs": [], "recent_jobs": [],
                    }),
                    "job_status" => json!({
                        "found": true,
                        "job": {"id": args["job_id"], "command": "analyze", "state": "complete"},
                    }),
                    "job_cancel" => json!({
                        "job_id": args["job_id"].as_u64().unwrap_or(7),
                        "state": "cancel_requested",
                    }),
                    "open_program" => {
                        program = args["program"].as_str().unwrap().to_owned();
                        json!({"program": program})
                    }
                    "import" => json!({"program": "imported"}),
                    "analyze" => {
                        json!({"status": "success", "program": program, "function_count": 3})
                    }
                    "decompile" => {
                        json!({"name": "main", "address": "0x1000", "code": "int main(void) {\n  return 0;\n}\n"})
                    }
                    "read_memory" => json!({
                        "address": args["address"], "size": 8, "hex": "0000000001000000",
                        "pointers": [
                            {"offset": 0, "address": "0x1000", "value": "0x00000000"},
                            {"offset": 4, "address": "0x1004", "value": "0x00000001"},
                        ],
                    }),
                    "graph_callers" | "graph_callees" => {
                        let mut calls = call_rows_fixture();
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            calls.truncate(limit as usize);
                        }
                        json!({"target": args["function"], "count": calls.len(), "calls": calls})
                    }
                    "graph_calls" => {
                        let mut graph = call_graph_fixture();
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            let nodes = graph["nodes"].as_array_mut().unwrap();
                            nodes.truncate(limit as usize);
                            let ids: Vec<_> = nodes.iter().map(|n| n["id"].clone()).collect();
                            graph["edges"]
                                .as_array_mut()
                                .unwrap()
                                .retain(|edge| ids.contains(&edge["from"]));
                            graph["node_count"] = json!(graph["nodes"].as_array().unwrap().len());
                            graph["edge_count"] = json!(graph["edges"].as_array().unwrap().len());
                        }
                        graph
                    }
                    "disasm" | "disasm_range" | "function_disasm" | "find_instruction" => {
                        let mut rows = vec![
                            json!({"address": "0x1000", "bytes": "90", "mnemonic": "NOP", "operands": [], "disasm": "NOP"}),
                            json!({"address": "0x1001", "bytes": "90", "mnemonic": "NOP", "operands": [], "disasm": "NOP"}),
                            json!({"address": "0x1002", "bytes": "c3", "mnemonic": "RET", "operands": [], "disasm": "RET"}),
                        ];
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        let key = if request["command"] == "find_instruction" {
                            "results"
                        } else {
                            "instructions"
                        };
                        json!({key: rows, "count": rows.len()})
                    }
                    "find_string" | "find_bytes" | "find_bytes_regex" | "find_text" => {
                        let mut rows: Vec<_> = (0..160)
                            .map(|i| json!({"address": format!("0x{i:04x}")}))
                            .collect();
                        if request["command"] == "find_string" {
                            for (i, row) in rows.iter_mut().enumerate() {
                                row["value"] = json!(format!("needle_{i:03}"));
                                row["char_length"] = json!(10);
                                row["byte_length"] = json!(11);
                            }
                            for field in ["pattern", "filter"] {
                                if let Some(needle) = args[field].as_str() {
                                    rows.retain(|row| {
                                        row["value"]
                                            .as_str()
                                            .unwrap()
                                            .to_lowercase()
                                            .contains(&needle.to_lowercase())
                                    });
                                }
                            }
                            let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                            rows.drain(..offset.min(rows.len()));
                        }
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        json!({"results": rows, "count": rows.len()})
                    }
                    "memory_map" => {
                        let rows = vec![
                            json!({"name":"first"}),
                            json!({"name":"second"}),
                            json!({"name":"third"}),
                        ];
                        let key = "blocks";
                        json!({key: rows, "count": rows.len(), "current_program_name": program})
                    }
                    "string_refs" => {
                        let rows = if args["pattern"] == "absent" {
                            vec![]
                        } else {
                            vec![
                                json!({"from": "0x1000", "from_function": "main", "string_value": "needle"}),
                                json!({"from": "0x2000", "from_function": "helper", "string_value": "needle"}),
                            ]
                        };
                        json!({"results": rows, "count": rows.len(), "pattern": args["pattern"]})
                    }
                    "xrefs_to" | "xrefs_from" => json!({"xrefs": [], "count": 0}),
                    "define_code" => json!({"address": args["target"], "end": args["end"],
                        "ok": true, "landed": true, "already_defined": false,
                        "changed": true, "status": "defined"}),
                    "symbol_get" | "symbol_get_by_name" => {
                        json!({"symbols": if args["name"] == "missing" {
                            vec![]
                        } else {
                            vec![
                                symbol_fixture("9007199254740993", "0x00ab", "label"),
                                symbol_fixture("9007199254740994", "0x00cd", "function"),
                            ]
                        }})
                    }
                    "symbol_delete" => {
                        json!({"status": "deleted", "name": args["name"], "count": args["targets"].as_array().unwrap().len()})
                    }
                    "delete_function" => {
                        json!({"status": "deleted", "name": "main", "address": "0x1000"})
                    }
                    "comment_delete" => {
                        json!({"status": "deleted", "address": args["address"]})
                    }
                    "tag_get" => {
                        json!({"name": args["name"], "comment": "Review queue", "use_count": 2})
                    }
                    "list_functions" => {
                        let mut rows = vec![
                            json!({"name": "excluded", "size": 0}),
                            json!({"name": "small", "size": 10}),
                            json!({"name": "large", "size": 30}),
                            json!({"name": "medium", "size": 20}),
                        ];
                        if let Some(filter) = args["filter"].as_str() {
                            rows.retain(|row| {
                                row["name"]
                                    .as_str()
                                    .unwrap()
                                    .to_lowercase()
                                    .contains(&filter.to_lowercase())
                            });
                        }
                        let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                        rows.drain(..offset.min(rows.len()));
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        json!({"functions": rows, "count": rows.len()})
                    }
                    "symbol_externals" | "symbol_entry_points" => {
                        let mut rows = vec![json!({"name": "first"}), json!({"name": "second"})];
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        let key = if request["command"] == "symbol_externals" {
                            "externals"
                        } else {
                            "entry_points"
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
            .env_remove("GHIDRA_CLI_DECOMPILE_TIMEOUT")
            .env(
                "GHIDRA_INSTALL_DIR",
                self.root.path().join("unused-install"),
            )
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
fn renamed_commands_preserve_wire_requests_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (args, wire, key, expected) in [
        (
            vec!["xref", "to", "0x1000", "--limit", "0"],
            "xrefs_to",
            "address",
            "0x1000",
        ),
        (
            vec!["xref", "from", "0x1000", "--limit", "0"],
            "xrefs_from",
            "address",
            "0x1000",
        ),
        (
            vec!["xref", "from", "main", "--function", "--limit", "0"],
            "xrefs_from",
            "address",
            "main",
        ),
        (
            vec!["string", "refs", "needle", "--limit", "0"],
            "string_refs",
            "pattern",
            "needle",
        ),
        (
            vec!["disassemble", "0x1000", "--limit", "0"],
            "disasm",
            "address",
            "0x1000",
        ),
        (
            vec!["function", "disassemble", "main", "--limit", "0"],
            "function_disasm",
            "target",
            "main",
        ),
        (
            vec!["define-code", "0x1000", "--end", "0x1010"],
            "define_code",
            "target",
            "0x1000",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        let standalone = bridge.run(&args);
        let standalone_request = bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|request| request["command"] == wire)
            .unwrap()
            .clone();
        assert_eq!(standalone_request["args"][key], expected);
        if wire == "define_code" {
            assert_eq!(standalone_request["args"]["end"], "0x1010");
        }
        if wire == "xrefs_from" {
            assert_eq!(
                standalone_request["args"]["function"],
                args.contains(&"--function")
            );
        }
        bridge.requests.lock().unwrap().clear();
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(report[0]["failed"], 0, "{args:?}: {report}");
        let requests = bridge.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|request| request["command"] == wire)
            .unwrap();
        assert_eq!(request["args"], standalone_request["args"], "{args:?}");
        let result = &report[0]["results"][0]["result"];
        // Mutations are wrapped as one receipt in standalone JSON output.
        assert_eq!(
            result,
            if wire == "define_code" {
                &standalone[0]
            } else {
                &standalone
            },
            "{args:?}"
        );
    }
}

#[test]
fn type_creation_preserves_wire_requests_and_targets_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (mut args, wire, expected) in [
        (
            vec!["type", "create", "struct", "Header"],
            "type_create",
            json!({"definition": "Header"}),
        ),
        (
            vec![
                "type",
                "create",
                "enum",
                "Mode",
                "--values",
                "Read=1,Write=2",
            ],
            "type_create_enum",
            json!({"name": "Mode", "values": "Read=1,Write=2", "size": 4}),
        ),
        (
            vec![
                "type", "create", "enum", "WideMode", "--values", "Read=1", "--size", "8",
            ],
            "type_create_enum",
            json!({"name": "WideMode", "values": "Read=1", "size": 8}),
        ),
        (
            vec!["type", "create", "typedef", "HeaderPointer", "Header *"],
            "type_typedef",
            json!({"name": "HeaderPointer", "base_type": "Header *"}),
        ),
    ] {
        args.extend([
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
        ]);
        for batch in [false, true] {
            outer.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(outer.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                let report = outer.run(&["batch", "batch.txt"]);
                assert_eq!(report[0]["failed"], 0, "{args:?}: {report}");
                report[0]["results"][0]["result"].clone()
            } else {
                outer.run(&args)[0].clone()
            };
            assert_eq!(result["observed_program"], "B", "{args:?}: {result}");
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|request| request["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{args:?}: {domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], wire);
            assert_eq!(domain[1]["args"], expected, "{args:?}");
            assert!(outer
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request["command"] == "bridge_info"));
        }
    }
}

#[test]
fn analyze_preserves_target_selection_and_results_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let expected = json!({
        "command": "analyze", "status": "success",
        "data": {"status": "success", "program": "B", "function_count": 3},
    });
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "analyze --program B\nanalyze\n",
    )
    .unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args(["analyze", "--program", "B"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "JSON modes suppress progress");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!([expected])
        );
        let requests = bridge.requests.lock().unwrap().clone();
        assert_eq!(requests[requests.len() - 2]["command"], "open_program");
        assert_eq!(requests.last().unwrap()["command"], "analyze");

        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args(["batch", "batch.txt", "--program", "A"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "batch must suppress progress");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report[0]["failed"], 0);
        let rows = report[0]["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row["result"], expected);
        }
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] == "analyze")
                .count(),
            2
        );
        let selections: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .map(|r| r["args"]["program"].as_str().unwrap())
            .collect();
        assert_eq!(selections, ["A", "B"]);
    }
}

#[test]
fn editing_capabilities_are_required_before_program_selection_or_edits() {
    for info in [
        json!({"auto_save": true, "named_import": true}),
        json!({"auto_save": false, "named_import": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": false}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true, "atomic_edits": false}),
        json!({"auto_save": false, "named_import": true, "explicit_addresses": true, "atomic_edits": true}),
    ] {
        let bridge = RecordedBridge::with_info(info);
        std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
        for args in [
            vec!["program", "info", "--program", "B"],
            vec!["comment", "set", "0x1000", "marker", "--program", "B"],
            vec!["import", "binary", "--no-analyze"],
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&args).output().unwrap();
            assert!(!output.status.success(), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("ghidra-cli bridge restart"),
                "{args:?}: {error}"
            );
            let requests = bridge.requests.lock().unwrap();
            assert_eq!(requests.len(), 1, "No fallback or replay: {requests:?}");
            assert_eq!(requests[0]["command"], "bridge_info");
        }
    }
}

#[test]
fn pending_save_recovery_does_not_require_atomic_edit_capability() {
    let bridge = RecordedBridge::with_info(json!({"auto_save": true}));
    let output = bridge.command().args(["program", "save"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let requests = bridge.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "Save must not restart or replay: {requests:?}"
    );
    assert_eq!(requests[0]["command"], "program_save");
}

#[test]
fn management_commands_preserve_control_requests_and_json_output() {
    let bridge = RecordedBridge::new();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, expected_request, expected_args) in [
            (vec!["bridge", "status"], "bridge_info", Value::Null),
            (vec!["bridge", "ping"], "ping", Value::Null),
            (vec!["job", "list"], "status", Value::Null),
            (
                vec!["job", "get", "42"],
                "job_status",
                json!({"job_id": 42}),
            ),
            (vec!["job", "cancel"], "job_cancel", json!({"job_id": null})),
            (
                vec!["job", "cancel", "42"],
                "job_cancel",
                json!({"job_id": 42}),
            ),
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&flags).args(&args).output().unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(result.is_object(), "{args:?}: {result}");
            assert_eq!(
                output.stdout.iter().filter(|&&c| c == b'\n').count() > 1,
                flags == ["--pretty"],
                "{flags:?} {args:?}: {output:?}"
            );
            match args.as_slice() {
                ["bridge", "status"] => {
                    assert_eq!(result["state"], "running");
                    assert_eq!(result["port"], bridge.port);
                    assert_eq!(result["project"], json!(bridge.project));
                    assert_eq!(result["info"]["auto_save"], true);
                }
                ["bridge", "ping"] => {
                    assert_eq!(result["responsive"], true);
                    assert_eq!(result["project"], json!(bridge.project));
                }
                ["job", "list"] => {
                    assert_eq!(result["bridge_state"], "running");
                    assert!(result["active_job"].is_null());
                    assert_eq!(result["queued_jobs"], json!([]));
                }
                ["job", "get", _] => assert_eq!(result["job"]["id"], 42),
                ["job", "cancel"] => assert_eq!(result["job_id"], 7),
                ["job", "cancel", _] => assert_eq!(result["job_id"], 42),
                _ => unreachable!(),
            }
            let requests = bridge.requests.lock().unwrap();
            let request = requests.last().unwrap();
            assert_eq!(request["command"], expected_request, "{requests:?}");
            assert_eq!(request["args"], expected_args, "{request}");
            let expected_commands = if args == ["bridge", "status"] {
                vec!["ping", "bridge_info"]
            } else {
                vec![expected_request]
            };
            assert_eq!(
                requests
                    .iter()
                    .map(|r| r["command"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                expected_commands,
                "management requests must not select a program or enter the program job queue"
            );
        }
    }
}

#[test]
fn management_targets_use_config_or_explicit_project_at_each_command_level() {
    let configured = RecordedBridge::new();
    let explicit = RecordedBridge::new();
    let config = configured.root.path().join("config.yaml");
    std::fs::write(
        &config,
        serde_yaml::to_string(&json!({
            "default_project": configured.project,
            "default_program": "configured-startup-program",
        }))
        .unwrap(),
    )
    .unwrap();
    for args in [
        vec!["bridge", "status"],
        vec!["bridge", "ping"],
        vec!["job", "list"],
        vec!["job", "get", "42"],
        vec!["job", "cancel"],
        vec!["job", "cancel", "42"],
    ] {
        for position in [None, Some(0), Some(1), Some(args.len())] {
            configured.requests.lock().unwrap().clear();
            explicit.requests.lock().unwrap().clear();
            let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
            command
                .env("GHIDRA_CLI_CONFIG", &config)
                .env("GHIDRA_DEFAULT_PROJECT", "unused-environment-project")
                .env("GHIDRA_DEFAULT_PROGRAM", "unused-environment-program")
                .args(["--program", "unused-explicit-program"])
                .timeout(std::time::Duration::from_secs(15));
            if let Some(position) = position {
                command
                    .args(&args[..position])
                    .arg("--project")
                    .arg(&explicit.project)
                    .args(&args[position..]);
            } else {
                command.args(&args);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{args:?} {position:?}: {output:?}");
            let (selected, unused) = if position.is_some() {
                (&explicit, &configured)
            } else {
                (&configured, &explicit)
            };
            assert!(unused.requests.lock().unwrap().is_empty());
            let requests = selected.requests.lock().unwrap();
            assert!(!requests.is_empty(), "{args:?} {position:?}");
            assert!(!requests.iter().any(|r| r["command"] == "open_program"));
        }
    }
}

#[test]
fn clear_routes_only_the_requested_clear_and_optional_redisassembly() {
    let bridge = RecordedBridge::new();
    for disasm_at in [None, Some("0x1000")] {
        bridge.requests.lock().unwrap().clear();
        let mut args = vec!["clear", "0x1000:0x1010"];
        if let Some(address) = disasm_at {
            args.extend(["--disassemble-at", address]);
        }
        bridge.run(&args);
        let requests = bridge.requests.lock().unwrap();
        let clear = requests
            .iter()
            .find(|r| r["command"] == "clear_range")
            .unwrap();
        assert_eq!(
            clear["args"],
            json!({"start": "0x1000", "end": "0x1010", "disasm_at": disasm_at})
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .count(),
            1,
            "clear must not dispatch a separate data creation or disassembly command"
        );
    }
}

#[test]
fn explicit_address_clear_ranges_preserve_spaces_and_segments() {
    let bridge = RecordedBridge::new();
    for (range, start, end) in [
        (
            "overlay:0x1000:overlay:0x1010",
            "overlay:0x1000",
            "overlay:0x1010",
        ),
        ("overlay:0x1000:0x1010", "overlay:0x1000", "overlay:0x1010"),
        (
            "overlay:0x1000:other:0x1010",
            "overlay:0x1000",
            "other:0x1010",
        ),
        (
            "ram:0x1234:0x0005:ram:0x1234:0x0008",
            "ram:0x1234:0x0005",
            "ram:0x1234:0x0008",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&["clear", range]);
        let requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|request| request["command"] != "bridge_info")
            .collect();
        assert_eq!(edits.len(), 1, "{range}: {requests:?}");
        assert_eq!(edits[0]["command"], "clear_range");
        assert_eq!(
            edits[0]["args"],
            json!({"start": start, "end": end, "disasm_at": null}),
            "{range}"
        );
    }

    for range in [
        "1000:1010",
        "overlay::1000:1010",
        "overlay:1000:overlay:1010",
        "0x1234:0x0005:0x0008",
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge.command().args(["clear", range]).output().unwrap();
        assert!(!output.status.success(), "{range}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("Invalid or ambiguous range"),
            "{range}: {error}"
        );
        assert!(bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request["command"] == "bridge_info"));
    }
}

#[test]
fn instruction_queries_forward_ranges_and_apply_query_options_after_fetch() {
    let bridge = RecordedBridge::new();
    for command in [
        vec![
            "find",
            "instruction",
            "NOP",
            "--start",
            "0x1000",
            "--end",
            "0x1002",
            "--case-sensitive",
        ],
        vec!["disassemble", "0x1000", "--end", "0x1002"],
    ] {
        let rows = bridge.run(&command);
        assert_eq!(
            rows.as_array().unwrap().len(),
            1,
            "configured default limit"
        );
        let mut all = command.clone();
        all.extend(["--limit", "0"]);
        assert_eq!(bridge.run(&all).as_array().unwrap().len(), 3);
        let mut filtered = command.clone();
        filtered.extend([
            "--filter",
            "address != '0x1000'",
            "--fields",
            "address",
            "--sort=-address",
            "--offset",
            "1",
            "--limit",
            "1",
        ]);
        assert_eq!(bridge.run(&filtered), json!([{"address": "0x1001"}]));
        let mut count = command.clone();
        count.push("--count");
        assert_eq!(bridge.run(&count), 3);
        let requests = bridge.requests.lock().unwrap();
        let wire = if command[0] == "find" {
            "find_instruction"
        } else {
            "disasm_range"
        };
        let sent: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
        assert_eq!(sent.len(), 4);
        assert_eq!(sent[0]["args"]["limit"], 1);
        for request in &sent {
            assert_eq!(request["args"]["start"], "0x1000");
            assert_eq!(request["args"]["end"], "0x1002");
            if wire == "find_instruction" {
                assert_eq!(request["args"]["pattern"], "NOP");
                assert_eq!(request["args"]["case_sensitive"], true);
            }
        }
        for request in &sent[1..] {
            assert!(request["args"]["limit"].is_null());
        }
    }
}

#[test]
fn disassembly_queries_select_rows_before_paging_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = bridge.run(&["function", "disassemble", "main", "--limit", "0"]);
    assert_eq!(all.as_array().unwrap().len(), 3);
    for (flags, expected, fetch_limit) in [
        (vec![], json!([all[0]]), json!(1)),
        (vec!["--limit", "0"], all.clone(), Value::Null),
        (vec!["--limit", "2"], json!([all[0], all[1]]), json!(2)),
        (vec!["--count"], json!(3), Value::Null),
        (
            vec!["--filter", "mnemonic=RET"],
            json!([all[2]]),
            Value::Null,
        ),
        (
            vec!["--filter", "mnemonic=RET", "--count"],
            json!(1),
            Value::Null,
        ),
        (vec!["--offset", "1"], json!([all[1]]), Value::Null),
        (vec!["--sort=-address"], json!([all[2]]), Value::Null),
        (
            vec![
                "--sort=-address",
                "--offset",
                "1",
                "--limit",
                "1",
                "--fields",
                "address",
            ],
            json!([{"address": "0x1001"}]),
            Value::Null,
        ),
        (
            vec!["--offset", "1", "--limit", "1", "--count"],
            json!(1),
            Value::Null,
        ),
    ] {
        for (command, wire, target_key) in [
            (
                vec!["function", "disassemble", "main"],
                "function_disasm",
                "target",
            ),
            (vec!["disassemble", "main"], "disasm", "address"),
        ] {
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain(flags.iter().copied())
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                // Batch commands without query flags retain the bridge envelope.
                let expected_result = if batch && flags.is_empty() {
                    json!({"instructions": expected, "count": expected.as_array().unwrap().len()})
                } else {
                    expected.clone()
                };
                assert_eq!(result, expected_result, "{args:?}, batch={batch}");
                let requests = bridge.requests.lock().unwrap();
                let disassembly: Vec<_> = requests
                    .iter()
                    .filter(|r| matches!(r["command"].as_str(), Some("disasm" | "function_disasm")))
                    .collect();
                assert_eq!(disassembly.len(), 1);
                assert_eq!(disassembly[0]["command"], wire);
                assert_eq!(
                    disassembly[0]["args"],
                    json!({target_key: "main", "limit": fetch_limit})
                );
            }
        }
    }
}

#[test]
fn define_code_forwards_bounds_and_preserves_receipts_without_query_defaults() {
    let bridge = RecordedBridge::new();
    for config in [
        None,
        Some("{}\n"),
        Some("default_limit: 1\n"),
        Some("default_limit: 0\n"),
    ] {
        let config_path = bridge.root.path().join("config.yaml");
        if let Some(config) = config {
            std::fs::write(&config_path, config).unwrap();
        } else {
            std::fs::remove_file(&config_path).unwrap();
        }
        for (flags, end) in [
            (vec![], Value::Null),
            (vec!["--end", "0x1010"], json!("0x1010")),
        ] {
            let args: Vec<_> = ["define-code", "0x1000", "--program", "B"]
                .into_iter()
                .chain(flags)
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let receipt = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)[0].clone()
                };
                assert!(receipt.is_object(), "{receipt}");
                assert_eq!(
                    receipt,
                    json!({"address": "0x1000", "end": end,
                    "ok": true, "landed": true, "already_defined": false,
                    "changed": true, "status": "defined"})
                );
                let requests = bridge.requests.lock().unwrap();
                let edits: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] == "define_code")
                    .collect();
                assert_eq!(edits.len(), 1);
                assert_eq!(edits[0]["args"], json!({"target": "0x1000", "end": end}));
                assert!(requests
                    .iter()
                    .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
            }
        }
    }
}

#[test]
fn graph_calls_queries_select_nodes_and_keep_outgoing_edges_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = call_graph_fixture();
    let graph = |nodes: &[usize], edges: &[usize]| {
        json!([{
            "nodes": nodes.iter().map(|&i| all["nodes"][i].clone()).collect::<Vec<_>>(),
            "edges": edges.iter().map(|&i| all["edges"][i].clone()).collect::<Vec<_>>(),
            "node_count": nodes.len(),
            "edge_count": edges.len(),
        }])
    };
    let mut projected = graph(&[1, 2], &[1, 2, 3]);
    projected[0]["nodes"] = json!([{"name": "alpha"}, {"name": "beta"}]);
    for (flags, expected, fetch_limit) in [
        (vec![], graph(&[0], &[0]), json!(1)),
        (vec!["--limit", "0"], json!([all]), Value::Null),
        (vec!["--limit", "2"], graph(&[0, 1], &[0, 1, 2]), json!(2)),
        (vec!["--sort", "name"], graph(&[1], &[1, 2]), Value::Null),
        (
            vec!["--sort", "name", "--limit", "2"],
            graph(&[1, 2], &[1, 2, 3]),
            Value::Null,
        ),
        (vec!["--offset", "1"], graph(&[1], &[1, 2]), Value::Null),
        (
            vec!["--filter", "name=beta"],
            graph(&[2], &[3]),
            Value::Null,
        ),
        (
            vec![
                "--filter", "name~a", "--sort", "name", "--offset", "1", "--limit", "2",
            ],
            graph(&[2, 3], &[3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort=-name", "--offset", "1", "--limit", "0"],
            graph(&[3, 2, 1], &[1, 2, 3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort", "name", "--limit", "2", "--fields", "name"],
            projected.clone(),
            Value::Null,
        ),
        (
            vec!["--sort", "name", "--limit", "2", "--fields=-id,address"],
            projected,
            Value::Null,
        ),
        (vec!["--offset", "99"], graph(&[], &[]), Value::Null),
        (
            vec!["--filter", "name=absent"],
            graph(&[], &[]),
            Value::Null,
        ),
        (vec!["--count"], json!(4), Value::Null),
        (
            vec!["--offset", "1", "--limit", "2", "--count"],
            json!(2),
            Value::Null,
        ),
        (
            vec!["--filter", "name=absent", "--count"],
            json!(0),
            Value::Null,
        ),
    ] {
        let args: Vec<_> = ["graph", "calls"].into_iter().chain(flags).collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            let expected = if batch && args.len() == 2 {
                &expected[0]
            } else {
                &expected
            };
            assert_eq!(&result, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let graphs: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "graph_calls")
                .collect();
            assert_eq!(graphs.len(), 1);
            assert_eq!(graphs[0]["args"], json!({"limit": fetch_limit}), "{args:?}");
        }
    }
}

#[test]
fn explicit_code_formats_override_json_without_changing_output_defaults() {
    let bridge = RecordedBridge::new();
    let command = vec!["decompile", "main"];
    let rows = bridge.run(&command);
    assert_eq!(rows[0]["name"], "main", "non-TTY default stays JSON");
    for flag in ["--json", "--pretty"] {
        let output = bridge
            .command()
            .args(&command)
            .args([flag, "--format", "c"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "int main(void) {\n  return 0;\n}\n"
        );
    }
    for command in [
        vec!["disassemble", "0x1000"],
        vec!["disassemble", "0x1000", "--end", "0x1002"],
        vec!["function", "disassemble", "main"],
    ] {
        assert!(bridge.run(&command).is_array());
        let output = bridge
            .command()
            .args(&command)
            .args(["--pretty", "--format", "asm"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("0x1000  90           NOP\n"));
    }
}

#[test]
fn configured_format_applies_to_query_rows_and_explicit_flags_override_it() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 1\ndefault_output_format: csv\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["symbol", "externals"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "name\nfirst\n");
    for flags in [vec!["--json"], vec!["--pretty"], vec!["-o", "json-compact"]] {
        let output = bridge
            .command()
            .args(["symbol", "externals"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flags:?}: {output:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!([{"name": "first"}])
        );
    }
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_output_format: auto\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["symbol", "externals"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn type_import_reads_code_files_and_stdin_in_the_client() {
    let bridge = RecordedBridge::new();
    let code = "// 日本語\nstruct Header { int size; };\n";
    std::fs::write(bridge.root.path().join("recovered types.h"), code).unwrap();
    for (args, input) in [
        (
            vec!["type", "import-c", code, "--category", "/Recovered"],
            None,
        ),
        (
            vec![
                "type",
                "import-c",
                "--file",
                "recovered types.h",
                "--category",
                "/Recovered",
            ],
            None,
        ),
        (
            vec!["type", "import-c", "--stdin", "--category", "/Recovered"],
            Some(code),
        ),
    ] {
        let mut command = bridge.command();
        command.args(args);
        if let Some(input) = input {
            command.write_stdin(input);
        }
        command.assert().success();
        let mut requests = bridge.requests.lock().unwrap();
        let imports: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_import_c")
            .collect();
        assert_eq!(imports.len(), 1);
        assert_eq!(
            imports[0]["args"],
            json!({"code": code, "category": "/Recovered"})
        );
        requests.clear();
    }
    for file in ["missing.h", "empty.h", "invalid.h"] {
        if file == "empty.h" {
            std::fs::write(bridge.root.path().join(file), " \n").unwrap();
        }
        if file == "invalid.h" {
            std::fs::write(bridge.root.path().join(file), [0xff]).unwrap();
        }
        bridge
            .command()
            .args(["type", "import-c", "--file", file])
            .assert()
            .failure();
    }
    bridge
        .command()
        .args(["type", "import-c", "--stdin"])
        .write_stdin(" ")
        .assert()
        .failure();
    assert!(!bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["command"] == "type_import_c"));
}

#[test]
fn field_edits_route_offsets_and_preserve_omitted_attributes() {
    let bridge = RecordedBridge::new();
    for (offset, flags, name, field_type, comment, size) in [
        (
            "0x1c",
            vec![
                "--name",
                "hook",
                "--type",
                "Hook *",
                "--comment",
                "callback",
            ],
            json!("hook"),
            json!("Hook *"),
            json!("callback"),
            Value::Null,
        ),
        (
            "28",
            vec!["--name", "hook"],
            json!("hook"),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        (
            "0X1C",
            vec!["--type", "Hook *"],
            Value::Null,
            json!("Hook *"),
            Value::Null,
            Value::Null,
        ),
        (
            "28",
            vec!["--comment", ""],
            Value::Null,
            Value::Null,
            json!(""),
            Value::Null,
        ),
        (
            "0x1c",
            vec!["--type", "string", "--size", "8"],
            Value::Null,
            json!("string"),
            Value::Null,
            json!(8),
        ),
    ] {
        let mut args = vec![
            "type",
            "set-field",
            "/Recovered/Manager",
            "--offset",
            offset,
            "--program",
            "B",
        ];
        args.extend(flags);
        bridge.run(&args);
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_set_field")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({
                "type_name": "/Recovered/Manager", "offset": 28,
                "field_name": name, "field_type": field_type, "comment": comment, "size": size,
            })
        );
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        requests.clear();
    }
    bridge.run(&[
        "type",
        "clear-field",
        "/Recovered/Manager",
        "--offset",
        "0x1c",
        "--program",
        "B",
    ]);
    {
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_clear_field")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({"type_name": "/Recovered/Manager", "offset": 28})
        );
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        requests.clear();
    }
    bridge.run(&[
        "type",
        "add-field",
        "Manager",
        "--name",
        "hook",
        "--type",
        "Hook *",
    ]);
    let requests = bridge.requests.lock().unwrap();
    let added = requests
        .iter()
        .find(|r| r["command"] == "type_add_field")
        .unwrap();
    assert_eq!(
        added["args"],
        json!({
            "type_name": "Manager", "field_name": "hook", "field_type": "Hook *", "size": null,
        })
    );
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
                "timeout_secs": 0,
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
comment set 0x1000 'Header length includes the prefix'
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
                json!({"address": "0x1000", "text": "Header length includes the prefix", "comment_type": null}),
            ),
        ]
    );
}

#[test]
fn decompiler_commands_share_native_timeout_configuration() {
    let bridge = RecordedBridge::new();
    for (args, wire) in [
        (vec!["decompile", "main"], "decompile"),
        (
            vec!["pcode", "function", "main", "--high"],
            "pcode_function",
        ),
        (
            vec![
                "function", "edit-var", "main", "--var", "param_1", "--name", "input",
            ],
            "function_edit_var",
        ),
    ] {
        for (configured, expected) in [
            (None, 0),
            (Some("0"), 0),
            (Some("47"), 47),
            (Some("2147483"), 2147483),
        ] {
            bridge.requests.lock().unwrap().clear();
            let mut command = bridge.command();
            command.args(&args);
            if let Some(value) = configured {
                command.env("GHIDRA_CLI_DECOMPILE_TIMEOUT", value);
            }
            command.assert().success();
            let requests = bridge.requests.lock().unwrap();
            let request = requests
                .iter()
                .find(|request| request["command"] == wire)
                .unwrap();
            assert_eq!(request["args"]["timeout_secs"], expected, "{args:?}");
        }
        for configured in [
            "-1",
            "2147484",
            "2147483648",
            "4294967297",
            "1.5",
            "invalid",
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge
                .command()
                .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", configured)
                .args(&args)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{args:?}, {configured}: {output:?}"
            );
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("GHIDRA_CLI_DECOMPILE_TIMEOUT"),
                "{error}"
            );
            assert!(
                bridge
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request["command"] != wire),
                "Invalid configuration must not dispatch {wire}"
            );
        }
    }
}

#[test]
fn call_traversal_queries_share_rows_and_preserve_selection_before_limits() {
    let bridge = RecordedBridge::new();
    for direction in ["callers", "callees"] {
        let wire = format!("graph_{direction}");
        for (flags, expected, fetch_limit) in [
            (vec![], json!(&call_rows_fixture()[..1]), json!(1)),
            (
                vec!["--limit", "0"],
                json!(call_rows_fixture()),
                Value::Null,
            ),
            (vec!["--count"], json!(3), Value::Null),
            (vec!["--limit", "2", "--count"], json!(2), Value::Null),
            (
                vec!["--filter", "callee=leaf", "--fields", "caller,callee,via"],
                json!([{"caller": "helper", "callee": "leaf", "via": "0x3004"}]),
                Value::Null,
            ),
            (
                vec!["--sort", "-call_site", "--offset", "1", "--limit", "1"],
                json!([call_rows_fixture()[1].clone()]),
                Value::Null,
            ),
        ] {
            let mut args = vec!["graph", direction, "entry", "--depth", "3"];
            args.extend(flags);
            bridge.requests.lock().unwrap().clear();
            assert_eq!(bridge.run(&args), expected, "{args:?}");
            let standalone = {
                let requests = bridge.requests.lock().unwrap();
                let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(operations.len(), 1);
                let request = operations[0]["args"].clone();
                assert_eq!(request["function"], "entry");
                assert_eq!(request["depth"], 3);
                assert_eq!(request["limit"], fetch_limit, "{args:?}");
                request
            };
            bridge.requests.lock().unwrap().clear();
            std::fs::write(bridge.root.path().join("calls.txt"), batch_arguments(&args)).unwrap();
            let batch = bridge.run(&["batch", "calls.txt"]);
            let actual = &batch[0]["results"][0]["result"];
            if args.len() == 5 {
                assert_eq!(actual["calls"], expected);
                assert_eq!(actual["count"], 1);
            } else {
                assert_eq!(*actual, expected, "{args:?}: {batch}");
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["args"], standalone);
        }
    }
}

#[test]
fn bounded_queries_reject_oversized_limits_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["symbol", "externals"],
        vec!["symbol", "entry-points"],
        vec!["tag", "list"],
        vec!["graph", "calls"],
        vec!["graph", "callers", "main"],
        vec!["graph", "callees", "main"],
        vec!["find", "instruction", "CALL"],
    ] {
        for limit in ["2147483648", "4294967297"] {
            for selection in [vec![], vec!["--filter", "name~item"], vec!["--count"]] {
                let output = bridge
                    .command()
                    .args(&args)
                    .args(["--limit", limit])
                    .args(&selection)
                    .output()
                    .unwrap();
                assert!(
                    !output.status.success(),
                    "{args:?}, {selection:?}: {output:?}"
                );
                let error: Value = serde_json::from_slice(&output.stderr).unwrap();
                assert!(
                    error["message"]
                        .as_str()
                        .unwrap()
                        .contains("--limit must be between 0 and 2147483647"),
                    "{error}"
                );
                assert!(bridge.requests.lock().unwrap().is_empty());
            }
        }
    }
    for subcommand in ["callers", "callees"] {
        let output = bridge
            .command()
            .args(["graph", subcommand, "main", "--depth", "4294967297"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("--depth must be between 0 and 2147483647"),
            "{error}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn bounded_query_defaults_respect_count_and_explicit_unlimited() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 2147483648\n",
    )
    .unwrap();
    for selection in [vec![], vec!["--filter", "name~a"]] {
        let output = bridge
            .command()
            .args(["graph", "calls"])
            .args(selection)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("--limit must be between 0 and 2147483647"),
            "{error}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
    assert_eq!(bridge.run(&["graph", "calls", "--count"]), 4);
    for limit in ["0", "2147483647"] {
        let result = bridge.run(&["graph", "calls", "--limit", limit]);
        assert_eq!(result[0]["node_count"], 4);
    }
    // The list planner already supports checked 64-bit paging; keep that contract.
    bridge.run(&["function", "list", "--limit", "2147483648"]);
    let requests = bridge.requests.lock().unwrap();
    let list = requests
        .iter()
        .find(|request| request["command"] == "list_functions")
        .unwrap();
    assert_eq!(list["args"]["limit"], 2147483648_u64);
}

#[test]
fn batch_unescapes_arguments_without_expanding_shell_syntax() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        concat!(
            r#"comment set 0x1000 "say \"hello\"; path C:\temp; slash \\; \$value"
comment set 0x1001 escaped\ spaces\ and\ \'quotes\'
comment set 0x1002 '$HOME $(echo expanded) `echo expanded` *.bin > out | cat # literal'
comment set 0x1003 ""
"#,
            "comment set 0x1004 trailing\\ \n",
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
        "# commands\ncomment set 0x1000 'unfinished\ncomment set 0x1001 \"unfinished\ncomment set 0x1002 trailing\\\ncomment set 0x1003 'valid after errors'\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["detail"].get("results").is_none());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let detail = &report[0];
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
    assert_eq!(comments[0]["args"]["address"], "0x1003");
    assert_eq!(comments[0]["args"]["text"], "valid after errors");
}

#[test]
fn batch_on_error_controls_command_and_syntax_failures() {
    for failing_line in [
        "symbol rename missing renamed",
        "comment set 0x1000 'unfinished",
        "comment set",
    ] {
        for policy in [None, Some("continue"), Some("stop")] {
            let bridge = RecordedBridge::new();
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                format!("comment set 0x1000 before\n{failing_line}\ncomment set 0x1001 after\n"),
            )
            .unwrap();
            let mut command = bridge.command();
            command.args(["batch", "batch.txt"]);
            if let Some(policy) = policy {
                command.args(["--on-error", policy]);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{policy:?}: {output:?}");
            assert!(!output.stdout.is_empty());
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(error["detail"].get("results").is_none());
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let detail = &report[0];
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
                "comment set 0x1000 before\nbatch nested.txt{child_option}\ncomment set 0x1003 outer-after\n"
            ),
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            "symbol rename missing renamed\ncomment set 0x1002 inner-after\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt", "--on-error", parent_policy])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["detail"].get("results").is_none());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let detail = &report[0];
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
        "comment set 0x1000 nested --program C\n",
    )
    .unwrap();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "comment set 0x1000 marker --program B\nprogram info\nbatch nested.txt\nprogram info --project {} --program D\n",
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
        .env(
            "GHIDRA_PROJECT_DIR",
            bridge.root.path().join("wrong-projects"),
        )
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
fn external_symbols_and_entry_points_paginate_after_fetching_for_queries_and_batches() {
    let bridge = RecordedBridge::new();
    let command = "symbol";
    for kind in ["externals", "entry-points"] {
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

#[test]
fn string_reference_queries_process_rows_in_standalone_and_batch_results() {
    let bridge = RecordedBridge::new();
    let all = json!([
        {"from": "0x1000", "from_function": "main", "string_value": "needle"},
        {"from": "0x2000", "from_function": "helper", "string_value": "needle"},
    ]);
    for (pattern, flags, expected) in [
        ("needle", vec!["--limit", "0"], all.clone()),
        ("needle", vec!["--count"], json!(2)),
        ("absent", vec!["--count"], json!(0)),
        ("absent", vec!["--limit", "0"], json!([])),
        (
            "needle",
            vec!["--fields", "from", "--limit", "0"],
            json!([{"from": "0x1000"}, {"from": "0x2000"}]),
        ),
        (
            "needle",
            vec!["--filter", "from_function=main"],
            json!([all[0].clone()]),
        ),
        (
            "needle",
            vec!["--sort", "-from", "--offset", "1", "--limit", "1"],
            json!([all[0].clone()]),
        ),
    ] {
        let args: Vec<_> = ["string", "refs", pattern]
            .into_iter()
            .chain(flags)
            .collect();
        assert_eq!(bridge.run(&args), expected, "{args:?}");
        std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(
            report[0]["results"][0]["result"], expected,
            "batch {args:?}"
        );
    }
}

#[test]
fn project_directory_overrides_are_local_to_each_batch_line() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "program info --program first\nprogram info --project project --projects-dir {} --program second\nprogram info --project project\n",
        batch_path_argument(second.project.parent().unwrap()),
    )).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(first.root.path())
        .env("GHIDRA_CLI_CONFIG", first.root.path().join("config.yaml"))
        .env(
            "GHIDRA_INSTALL_DIR",
            first.root.path().join("unused-install"),
        )
        .env(
            "GHIDRA_PROJECT_DIR",
            first.root.path().join("wrong-projects"),
        )
        .arg("--projects-dir")
        .arg(first.project.parent().unwrap())
        .args(["--project", "project", "batch", "batch.txt"])
        .timeout(std::time::Duration::from_secs(15))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let observed: Vec<_> = report[0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["result"]["observed_program"].as_str().unwrap())
        .collect();
    assert_eq!(observed, ["first", "second", "first"]);
}

#[test]
fn ndjson_contains_exactly_one_document_per_line() {
    let bridge = RecordedBridge::new();
    bridge
        .command()
        .args(["config", "set", "default_output_format", "ndjson"])
        .assert()
        .success();
    let config = bridge.run(&["config", "list", "--json"]);
    assert_eq!(config["default_output_format"], "ndjson");
    for flags in [vec![], vec!["--format", "ndjson"]] {
        let output = bridge
            .command()
            .args(["symbol", "externals", "--limit", "0"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flags:?}: {output:?}");
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
}

#[test]
fn os_file_paths_are_resolved_in_the_cli_working_directory() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
    bridge.run(&["import", "binary", "--no-analyze"]);
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
            .args(["import", "binary", "--no-analyze"])
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

#[test]
fn symbol_mutations_resolve_targets_before_sending_the_edit() {
    let bridge = RecordedBridge::new();
    for (args, command, targets) in [
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
            json!([symbol_fixture("9007199254740993", "0x00ab", "label")]),
        ),
        (
            vec![
                "symbol",
                "rename",
                "shared",
                "renamed",
                "--filter",
                "kind=function",
            ],
            "symbol_rename",
            json!([symbol_fixture("9007199254740994", "0x00cd", "function")]),
        ),
        (
            vec!["symbol", "delete", "shared", "--all"],
            "symbol_delete",
            json!([
                symbol_fixture("9007199254740993", "0x00ab", "label"),
                symbol_fixture("9007199254740994", "0x00cd", "function")
            ]),
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
        assert_eq!(domain[0]["command"], "symbol_get_by_name");
        assert_eq!(domain[0]["args"], json!({"name": "shared"}));
        assert_eq!(domain[1]["command"], command);
        let expected = if command == "symbol_delete" {
            json!({"name": "shared", "targets": targets})
        } else {
            json!({"old_name": "shared", "new_name": "renamed", "targets": targets})
        };
        assert_eq!(domain[1]["args"], expected);
    }
}

#[test]
fn symbol_deletion_filters_select_targets_and_preserve_receipts() {
    let bridge = RecordedBridge::new();
    for filter in [
        "kind=label",
        "address=0xab",
        "address=0XAB",
        "address IN ['0X000AB']",
        "address IN [0XAB]",
    ] {
        for fields in [None, Some("status,count")] {
            let mut args = vec!["symbol", "delete", "shared", "--filter", filter];
            let mut receipt = json!({"status": "deleted", "name": "shared", "count": 1});
            if let Some(fields) = fields {
                args.extend(["--fields", fields]);
                receipt.as_object_mut().unwrap().remove("name");
            }
            assert_eq!(bridge.run(&args), json!([receipt]));
            std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
            let report = bridge.run(&["batch", "batch.txt"]);
            let expected = if fields.is_some() {
                json!([receipt])
            } else {
                receipt
            };
            assert_eq!(report[0]["results"][0]["result"], expected);
            for request in bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["command"] == "symbol_delete")
            {
                assert_eq!(
                    request["args"]["targets"],
                    json!([symbol_fixture("9007199254740993", "0x00ab", "label")])
                );
            }
        }
    }
}

#[test]
fn symbol_deletion_rejects_invalid_filters_before_selecting_a_program() {
    let bridge = RecordedBridge::new();
    for filter in [
        "invalid",
        "address=171",
        "address!='ab'",
        "address IN ['0xab', 'cd']",
        "address='0xnothex'",
    ] {
        let output = bridge
            .command()
            .args([
                "symbol",
                "delete",
                "shared",
                "--filter",
                filter,
                "--program",
                "B",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{filter}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("invalid --filter expression"),
            "{filter}: {error}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty(), "{filter}");
    }
}

#[test]
fn explicit_address_symbol_selectors_reject_bare_values_before_mutation() {
    let bridge = RecordedBridge::new();
    for command in [
        vec!["symbol", "rename", "shared", "renamed"],
        vec!["symbol", "delete", "shared"],
    ] {
        for address in ["00ab", "dead", "FUN_00ab", "ram:00ab", "overlay::0xab"] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge
                .command()
                .args(&command)
                .args(["--address", address])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{command:?} {address}: {output:?}"
            );
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            let message = error["message"].as_str().unwrap();
            assert!(message.contains("Invalid --address"), "{error}");
            assert!(message.contains("0x-prefixed"), "{error}");
            assert!(bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request["command"] == "bridge_info"));
        }
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
            vec!["symbol", "rename", "shared", "renamed"],
            "matches 2 symbols at addresses [0x00ab, 0x00cd]",
        ),
        (
            vec!["symbol", "delete", "shared", "--address", "0xffff"],
            "No symbol named 'shared' at address 0xffff",
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
        assert_eq!(requests.last().unwrap()["command"], "symbol_get_by_name");
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

#[test]
fn script_expect_row_bounds_are_checked_before_sending_the_script() {
    let bridge = RecordedBridge::new();
    for minimum in [
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
                    "--expect",
                    &format!("rows.jsonl:{minimum}"),
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
            "--expect",
            &format!("rows.jsonl:{minimum}"),
        ]);
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests.last().unwrap()["args"]["expect"][0]["min_rows"],
            minimum
        );
    }
}

#[test]
fn batch_queries_inherit_targets_and_keep_program_selection() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "memory map\ncomment set 0x1000 marker --program B\nmemory map\nmemory map --program C\nmemory map --project {} --program D\nmemory map\n",
        batch_path_argument(&second.project),
    )).unwrap();
    let output = first
        .command()
        .args(["batch", "batch.txt", "--program", "A"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, program) in [(0, "A"), (1, "B"), (2, "B"), (3, "C"), (4, "D"), (5, "C")] {
        let key = if index == 1 {
            "observed_program"
        } else {
            "current_program_name"
        };
        assert_eq!(result[0]["results"][index]["result"][key], program);
    }
    for (bridge, expected) in [(&first, vec!["A", "B", "C"]), (&second, vec!["D"])] {
        let requests = bridge.requests.lock().unwrap();
        let opened: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .map(|r| r["args"]["program"].as_str().unwrap())
            .collect();
        assert_eq!(opened, expected);
    }
}

#[test]
fn default_limit_is_applied_after_client_row_selection_for_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let command = ["function", "list"];
    for (flags, expected) in [
        (
            vec!["--filter", "size>0"],
            json!([{"name": "small", "size": 10}]),
        ),
        (vec!["--sort=-size"], json!([{"name": "large", "size": 30}])),
        (
            vec!["--offset", "1"],
            json!([{"name": "small", "size": 10}]),
        ),
        (
            vec!["--filter", "size>0", "--sort=-size", "--offset", "1"],
            json!([{"name": "medium", "size": 20}]),
        ),
        (
            vec![
                "--filter",
                "size>0",
                "--sort=-size",
                "--offset",
                "1",
                "--limit",
                "0",
            ],
            json!([{"name": "medium", "size": 20}, {"name": "small", "size": 10}]),
        ),
        (vec!["--filter", "size>0", "--count"], json!(3)),
    ] {
        let args: Vec<_> = command.iter().chain(flags.iter()).copied().collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let lists: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "list_functions")
                .collect();
            assert_eq!(lists.len(), 1);
            if flags == ["--offset", "1"] {
                assert_eq!(lists[0]["args"]["offset"], 1);
                assert_eq!(lists[0]["args"]["limit"], 1);
            } else {
                assert!(lists[0]["args"]["limit"].is_null(), "{lists:?}");
            }
        }
    }
}

#[test]
fn invalid_mutation_arguments_fail_before_bridge_or_config_errors() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("invalid.yaml"), "default_limit: [").unwrap();
    for args in [
        vec!["function", "delete"],
        vec!["comment", "set", "0x1000", "marker", "--unknown-option"],
    ] {
        for invalid_config in [false, true] {
            let mut command = bridge.command();
            command.args(&args).args(["--program", "must-not-open"]);
            if invalid_config {
                command.env("GHIDRA_CLI_CONFIG", bridge.root.path().join("invalid.yaml"));
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(bridge.requests.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn positional_targets_preserve_requests_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (args, wire, key) in [
        (
            vec![
                "function",
                "set-signature",
                "entry",
                "--signature",
                "int entry(void)",
            ],
            "function_set_signature",
            "target",
        ),
        (
            vec![
                "function",
                "set-return-type",
                "entry",
                "--type",
                "unsigned long",
            ],
            "function_set_return_type",
            "target",
        ),
        (
            vec![
                "function",
                "set-calling-convention",
                "entry",
                "--convention",
                "__cdecl",
            ],
            "function_set_calling_convention",
            "target",
        ),
        (
            vec!["function", "set-noreturn", "entry", "--value", "false"],
            "function_set_noreturn",
            "target",
        ),
        (
            vec![
                "function", "edit-var", "entry", "--var", "local_10", "--name", "value",
            ],
            "function_edit_var",
            "target",
        ),
        (vec!["function", "get", "entry"], "get_function", "address"),
        (vec!["decompile", "entry"], "decompile", "address"),
        (
            vec!["graph", "callers", "entry"],
            "graph_callers",
            "function",
        ),
        (
            vec!["graph", "callees", "entry"],
            "graph_callees",
            "function",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&args);
        let standalone = {
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1, "{args:?}: {requests:?}");
            assert_eq!(operations[0]["args"][key], "entry", "{args:?}");
            operations[0]["args"].clone()
        };
        bridge.requests.lock().unwrap().clear();
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(report[0]["failed"], 0, "{args:?}: {report}");
        let requests = bridge.requests.lock().unwrap();
        let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
        assert_eq!(operations.len(), 1, "{args:?}: {requests:?}");
        assert_eq!(operations[0]["args"], standalone, "{args:?}");
    }
}

#[test]
fn batch_continues_after_invalid_arguments_without_selecting_their_programs() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "function delete --program must-not-open\ncomment set 0x1000 after\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt", "--on-error", "continue"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["commands_executed"], 2);
    assert_eq!(report[0]["failed"], 1);
    assert_eq!(report[0]["not_executed"], 0);
    assert!(report[0]["results"][0]["error"].is_string());
    let requests = bridge.requests.lock().unwrap();
    let domain: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .collect();
    assert_eq!(domain.len(), 1, "{domain:?}");
    assert_eq!(domain[0]["command"], "comment_set");
    assert_eq!(domain[0]["args"]["text"], "after");
}

#[test]
fn deletion_preserves_targets_and_receipt_output_in_standalone_and_batch() {
    for (command, wire) in [
        (vec!["function", "delete", "main"], "delete_function"),
        (vec!["function", "delete", "0x1000"], "delete_function"),
        (
            vec!["comment", "delete", "0x1000", "--all"],
            "comment_delete",
        ),
        (
            vec!["comment", "delete", "0x1000", "--comment-type", "pre"],
            "comment_delete",
        ),
    ] {
        for batch in [false, true] {
            let bridge = RecordedBridge::new();
            let mut args = command.clone();
            args.extend([
                "--program",
                "B",
                "--fields",
                "status,address",
                "--format",
                "json-compact",
                "--json",
            ]);
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, json!([{"status": "deleted", "address": "0x1000"}]));
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], wire);
            assert_eq!(
                domain[1]["args"],
                if wire == "comment_delete" {
                    json!({"address": "0x1000", "comment_type": if command.contains(&"--all") { None } else { Some("pre") }, "all": command.contains(&"--all")})
                } else {
                    json!({"address": command.last().unwrap()})
                }
            );
        }
    }
}

#[test]
fn single_objects_and_mutations_reject_list_flags_before_program_dispatch() {
    let bridge = RecordedBridge::new();
    let flags = [
        "--filter name=other",
        "--sort name",
        "--offset 1",
        "--limit 0",
        "--count",
    ];
    let mut lines: Vec<_> = [
        "function delete main",
        "define-code 0x1000",
        "comment delete 0x1000 --all",
        "memory read 0x1000 8",
        "program info",
        "program stats",
    ]
    .into_iter()
    .flat_map(|command| {
        flags
            .iter()
            .map(move |flag| format!("{command} --program must-not-open {flag}"))
    })
    .collect();
    let rejected = lines.len();
    for line in &lines {
        let output = bridge
            .command()
            .args(line.split_whitespace())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
    lines.push("program info".into());
    std::fs::write(bridge.root.path().join("batch.txt"), lines.join("\n")).unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for result in report[0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .take(rejected)
    {
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("unexpected argument"),
            "{result}"
        );
    }
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["detail"]["failed"], rejected);
    let requests = bridge.requests.lock().unwrap();
    let domain: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .collect();
    assert_eq!(domain.len(), 1, "{domain:?}");
    assert_eq!(domain[0]["command"], "program_info");
}

#[test]
fn batch_reports_results_on_stdout_and_stops_on_save_failure_or_timeout() {
    for (failure, code) in [("test-save-failure", 1), ("test-timeout", 75)] {
        let bridge = RecordedBridge::new();
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            format!("comment set 0x1000 {failure}\ncomment set 0x1000 must-not-run\n"),
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            "program info\nbatch nested.txt\ncomment set 0x1000 must-not-run\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_READ_TIMEOUT", "1")
            .args(["batch", "batch.txt", "--on-error", "continue"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report[0]["commands_executed"], 2);
        assert_eq!(report[0]["not_executed"], 1);
        assert_eq!(report[0]["results"][1]["exit_code"], code);
        assert_eq!(report[0]["results"][1]["detail"]["not_executed"], 1);
        let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(diagnostic["detail"].get("results").is_none());
        assert_eq!(diagnostic["exit_code"], code);
        assert!(!bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["args"]["text"] == "must-not-run"));
    }
}

#[test]
fn contains_and_offset_share_one_plan_for_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let command = ["function", "list"];
    for (flags, expected, server_limit, server_offset) in [
        (
            vec!["--filter", "name~L", "--offset", "1"],
            json!([{"name":"small", "size":10}]),
            json!(1),
            json!(1),
        ),
        (
            vec!["--filter", "name~L", "--offset", "1", "--limit", "0"],
            json!([{"name":"small", "size":10}, {"name":"large", "size":30}]),
            json!(null),
            json!(1),
        ),
        (
            vec!["--filter", "name~L", "--offset", "1", "--count"],
            json!(2),
            json!(null),
            json!(null),
        ),
        (
            vec![
                "--filter",
                "name~L",
                "--sort=-size",
                "--fields",
                "name",
                "--offset",
                "1",
            ],
            json!([{"name":"small"}]),
            json!(null),
            json!(null),
        ),
    ] {
        let args: Vec<_> = command.iter().chain(flags.iter()).copied().collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let actual = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(actual, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let list = requests
                .iter()
                .find(|r| r["command"] == "list_functions")
                .unwrap();
            assert_eq!(list["args"]["filter"], "L");
            assert_eq!(list["args"]["limit"], server_limit);
            assert_eq!(list["args"]["offset"], server_offset);
        }
    }
}

#[test]
fn unsupported_list_offset_fetches_enough_rows() {
    let bridge = RecordedBridge::new();
    for command in [vec!["symbol", "externals"], vec!["symbol", "entry-points"]] {
        let args: Vec<_> = command
            .into_iter()
            .chain(["--offset", "1", "--limit", "1"])
            .collect();
        assert_eq!(bridge.run(&args), json!([{"name":"second"}]));
    }
    for list in bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["command"] == "symbol_externals" || r["command"] == "symbol_entry_points")
    {
        assert!(list["args"]["limit"].is_null());
    }
}

#[test]
fn search_queries_use_planned_limits_without_truncating_selection() {
    let bridge = RecordedBridge::new();
    for (command, wire) in [
        (vec!["find", "string", "needle"], "find_string"),
        (vec!["find", "text", "needle"], "find_text"),
        (vec!["find", "bytes", "90"], "find_bytes"),
        (
            vec!["find", "bytes", "--regex", r"\x90.{2}"],
            "find_bytes_regex",
        ),
    ] {
        for (flags, expected_len, first, fetch_limit) in [
            (vec![], 1, "0x0000", json!(1)),
            (vec!["--fields", "address"], 1, "0x0000", json!(1)),
            (vec!["--limit", "0"], 160, "0x0000", Value::Null),
            (vec!["--limit", "120"], 120, "0x0000", json!(120)),
            (
                vec!["--filter", "address='0x009f'"],
                1,
                "0x009f",
                Value::Null,
            ),
            (vec!["--sort=-address"], 1, "0x009f", Value::Null),
            (
                vec!["--offset", "100", "--limit", "2"],
                2,
                "0x0064",
                Value::Null,
            ),
            (vec!["--count"], 160, "", Value::Null),
            (
                vec!["--count", "--offset", "100", "--limit", "2"],
                2,
                "",
                Value::Null,
            ),
        ] {
            for batch in [false, true] {
                let mut args = command.clone();
                args.extend(&flags);
                bridge.requests.lock().unwrap().clear();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                if flags.contains(&"--count") {
                    assert_eq!(result, expected_len, "{args:?}, batch={batch}");
                } else {
                    let rows = if batch && flags.is_empty() {
                        assert_eq!(result["count"], expected_len);
                        &result["results"]
                    } else {
                        &result
                    };
                    assert_eq!(
                        rows.as_array().unwrap().len(),
                        expected_len,
                        "{args:?}, batch={batch}"
                    );
                    assert_eq!(rows[0]["address"], first);
                }
                let requests = bridge.requests.lock().unwrap();
                let sent: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(sent.len(), 1);
                let server_page = wire == "find_string"
                    && flags.contains(&"--offset")
                    && !flags.contains(&"--count");
                assert_eq!(
                    sent[0]["args"]["limit"],
                    if server_page {
                        json!(2)
                    } else {
                        fetch_limit.clone()
                    },
                    "{args:?}"
                );
                assert_eq!(
                    sent[0]["args"]["offset"],
                    if server_page { json!(100) } else { Value::Null },
                    "{args:?}"
                );
            }
        }
    }
}

#[test]
fn string_search_pages_after_pattern_and_filter_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let rows = json!([
        {"value":"needle_115", "char_length":10, "byte_length":11},
        {"value":"needle_125", "char_length":10, "byte_length":11}
    ]);
    for (flags, expected, fetch_filter, fetch_offset, fetch_limit) in [
        (
            vec!["--filter", "value~'5'", "--offset", "1", "--limit", "2"],
            rows.clone(),
            json!("5"),
            json!(1),
            json!(2),
        ),
        (
            vec![
                "--filter",
                "value~'5' AND byte_length>10",
                "--offset",
                "1",
                "--limit",
                "2",
            ],
            rows.clone(),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "value~'5'",
                "--sort=-value",
                "--offset",
                "12",
                "--limit",
                "2",
            ],
            json!([rows[1], rows[0]]),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "value~'5'",
                "--offset",
                "1",
                "--limit",
                "2",
                "--count",
            ],
            json!(2),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
        (
            vec!["--filter", "value~'5'", "--count"],
            json!(15),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
    ] {
        let args: Vec<_> = [
            "find",
            "string",
            "NEEDLE_1",
            "--fields",
            "value,char_length,byte_length",
        ]
        .into_iter()
        .chain(flags)
        .collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let actual = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(actual, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let sent = requests
                .iter()
                .find(|r| r["command"] == "find_string")
                .unwrap();
            assert_eq!(
                sent["args"],
                json!({
                    "pattern":"NEEDLE_1", "filter":fetch_filter,
                    "offset":fetch_offset, "limit":fetch_limit,
                }),
                "{args:?}, batch={batch}"
            );
        }
    }
}

#[test]
fn byte_regex_preserves_pattern_and_program_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let pattern = r"\x00(?:A B|'quote')\xff.{2,4}";
    let args = [
        "find",
        "bytes",
        "--regex",
        pattern,
        "--program",
        "B",
        "--limit",
        "2",
    ];
    for batch in [false, true] {
        bridge.requests.lock().unwrap().clear();
        if batch {
            std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
            bridge.run(&["batch", "batch.txt"]);
        } else {
            bridge.run(&args);
        }
        let requests = bridge.requests.lock().unwrap();
        let search = requests
            .iter()
            .find(|r| r["command"] == "find_bytes_regex")
            .unwrap();
        assert_eq!(search["args"], json!({"pattern": pattern, "limit": 2}));
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        assert!(!requests.iter().any(|r| r["command"] == "find_bytes"));
    }
}

#[test]
fn text_search_routes_encoding_text_and_program_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for encoding in [None, Some("utf-16le"), Some("shift_jis")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "find",
                "text",
                "日本 text",
                "--program",
                "B",
                "--limit",
                "1",
            ];
            if let Some(encoding) = encoding {
                args.extend(["--encoding", encoding]);
            }
            if batch {
                std::fs::write(bridge.root.path().join("text.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "text.txt"]);
            } else {
                bridge.run(&args);
            }
            let requests = bridge.requests.lock().unwrap();
            assert!(requests
                .iter()
                .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
            let sent: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "find_text")
                .collect();
            assert_eq!(sent.len(), 1);
            assert_eq!(
                sent[0]["args"],
                json!({"text": "日本 text", "encoding": encoding.unwrap_or("utf-8"), "limit": 1})
            );
        }
    }
}

#[test]
fn client_only_queries_apply_defaults_with_and_without_query_flags() {
    let bridge = RecordedBridge::new();
    for (configured, cap) in [("2", 2), ("0", 3), ("null", 3)] {
        std::fs::write(
            bridge.root.path().join("config.yaml"),
            format!("default_limit: {configured}\n"),
        )
        .unwrap();
        let (command, wire, key) = (vec!["memory", "map"], "memory_map", "blocks");
        for (flags, count, first) in [
            (vec![], cap, "first"),
            (vec!["--json"], cap, "first"),
            (vec!["--format", "json"], cap, "first"),
            (vec!["--fields", "name"], cap, "first"),
            (vec!["--limit", "0"], 3, "first"),
            (vec!["--limit", "1"], 1, "first"),
            (vec!["--sort=-name"], cap, "third"),
            (vec!["--offset", "1"], 2, "second"),
            (vec!["--filter", "name=third"], 1, "third"),
            (vec!["--count"], 3, ""),
            (vec!["--count", "--offset", "1", "--limit", "1"], 1, ""),
        ] {
            for batch in [false, true] {
                let mut args = command.clone();
                args.extend(&flags);
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                if flags.contains(&"--count") {
                    assert_eq!(result, count);
                } else {
                    let no_query = flags.is_empty()
                        || flags.contains(&"--json")
                        || flags.contains(&"--format");
                    let rows = if batch && no_query {
                        assert_eq!(result["count"], count);
                        &result[key]
                    } else {
                        &result
                    };
                    assert_eq!(
                        rows.as_array().unwrap().len(),
                        count,
                        "{args:?}, default={configured}, batch={batch}"
                    );
                    assert_eq!(rows[0]["name"], first);
                }
            }
        }
        let requests = bridge.requests.lock().unwrap();
        assert!(requests
            .iter()
            .filter(|r| r["command"] == wire)
            .all(|r| r["args"]["limit"].is_null()));
    }
}

#[test]
fn memory_write_routes_hex_and_targets_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for batch in [false, true] {
        bridge.requests.lock().unwrap().clear();
        if batch {
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                "memory write main '90 c3' --program B\n",
            )
            .unwrap();
            let result = bridge.run(&["batch", "batch.txt"]);
            assert_eq!(result[0]["results"][0]["result"]["observed_program"], "B");
        } else {
            let result = bridge.run(&["memory", "write", "main", "90 c3", "--program", "B"]);
            assert_eq!(result[0]["observed_program"], "B");
        }
        let requests = bridge.requests.lock().unwrap();
        let write = requests
            .iter()
            .find(|r| r["command"] == "memory_write")
            .unwrap();
        assert_eq!(write["args"], json!({"address": "main", "hex": "90 c3"}));
    }
}

#[test]
fn standalone_targets_use_config_or_explicit_flags() {
    let configured = RecordedBridge::new();
    let explicit = RecordedBridge::new();
    let config = configured.root.path().join("config.yaml");
    std::fs::write(
        &config,
        serde_yaml::to_string(&json!({
            "default_project": configured.project,
            "default_program": "configured-startup-program",
        }))
        .unwrap(),
    )
    .unwrap();
    for with_flags in [false, true] {
        configured.requests.lock().unwrap().clear();
        explicit.requests.lock().unwrap().clear();
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        command
            .env("GHIDRA_CLI_CONFIG", &config)
            .env(
                "GHIDRA_INSTALL_DIR",
                configured.root.path().join("unused-install"),
            )
            .args(["symbol", "externals"]);
        if with_flags {
            command
                .arg("--project")
                .arg(&explicit.project)
                .args(["--program", "explicit-program"]);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let (selected, unused) = if with_flags {
            (&explicit, &configured)
        } else {
            (&configured, &explicit)
        };
        assert!(unused.requests.lock().unwrap().is_empty());
        let requests = selected.requests.lock().unwrap();
        assert!(requests.iter().any(|r| r["command"] == "symbol_externals"));
        let opened: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .collect();
        if with_flags {
            assert_eq!(opened.len(), 1);
            assert_eq!(opened[0]["args"]["program"], "explicit-program");
        } else {
            // A running bridge keeps its current selection, even with a configured default.
            assert!(opened.is_empty(), "{opened:?}");
        }
    }
}

#[test]
fn program_info_and_stats_support_projection_and_format_in_standalone_and_batch() {
    for (subcommand, wire_command) in [("info", "program_info"), ("stats", "stats")] {
        let bridge = RecordedBridge::new();
        let args = [
            "program",
            subcommand,
            "--program",
            "B",
            "--fields",
            "observed_program",
            "--format",
            "json-compact",
        ];
        assert_eq!(bridge.run(&args), json!([{"observed_program": "B"}]));
        std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
        assert_eq!(
            bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"],
            json!([{"observed_program": "B"}])
        );
        assert_eq!(
            bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["command"] == wire_command)
                .count(),
            2
        );
    }
}

#[test]
fn tag_get_preserves_details_and_projection_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 2147483648\n",
    )
    .unwrap();
    for fields in [None, Some("comment,use_count")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["tag", "get", "review", "--program", "B", "--json"];
            let mut expected = json!({"name": "review", "comment": "Review queue", "use_count": 2});
            if let Some(fields) = fields {
                args.extend(["--fields", fields, "--format", "json-compact"]);
                expected.as_object_mut().unwrap().remove("name");
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            if batch && fields.is_none() {
                assert_eq!(result, expected);
            } else {
                assert_eq!(result, json!([expected]));
            }
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], "tag_get");
            assert_eq!(domain[1]["args"], json!({"name": "review"}));
        }
    }
}

#[test]
fn memory_read_preserves_bytes_and_pointers_with_output_options() {
    let bridge = RecordedBridge::new();
    for fields in [None, Some("size,hex,pointers")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["memory", "read", "0x1000", "8", "--program", "B", "--json"];
            if let Some(fields) = fields {
                args.extend(["--fields", fields, "--format", "json-compact"]);
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            // A plain batch line retains the object; standalone and projected results are rows.
            let object = if batch && fields.is_none() {
                &result
            } else {
                &result[0]
            };
            assert_eq!(object["size"], 8);
            assert_eq!(object["hex"], "0000000001000000");
            assert_eq!(object["pointers"].as_array().unwrap().len(), 2);
            assert_eq!(object.get("address").is_some(), fields.is_none());
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], "read_memory");
            assert_eq!(domain[1]["args"], json!({"address": "0x1000", "size": 8}));
        }
    }
}
