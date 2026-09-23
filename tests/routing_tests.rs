//! CLI routing contracts, verified against recorded requests without Ghidra.

#[path = "support/json.rs"]
mod json_output;

use ghidra_cli::ghidra::bridge;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "routing/analysis.rs"]
mod analysis;
#[path = "routing/batch.rs"]
mod batch;
#[path = "routing/batch_execution.rs"]
mod batch_execution;
#[path = "routing/batch_syntax.rs"]
mod batch_syntax;
#[path = "routing/commands.rs"]
mod commands;
#[path = "routing/functions.rs"]
mod functions;
#[path = "routing/imports.rs"]
mod imports;
#[path = "support/installation.rs"]
mod installation_fixture;
#[path = "routing/listing.rs"]
mod listing;
#[path = "routing/management.rs"]
mod management;
#[path = "routing/memory.rs"]
mod memory;
#[path = "routing/output.rs"]
mod output;
#[path = "routing/program.rs"]
mod program;
#[path = "routing/program_analysis.rs"]
mod program_analysis;
#[path = "routing/queries.rs"]
mod queries;
#[path = "routing/references.rs"]
mod references;
#[path = "routing/rollout.rs"]
mod rollout;
#[path = "routing/scripts.rs"]
mod scripts;
#[path = "routing/search.rs"]
mod search;
#[path = "routing/symbols.rs"]
mod symbols;
#[path = "routing/types.rs"]
mod types;

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

fn api_list_fixture(command: &str) -> (&'static str, Vec<Value>) {
    match command {
        "bookmark_list" | "bookmark_get" => (
            "bookmarks",
            ["zeta", "alpha", "beta"]
                .into_iter()
                .map(|comment| json!({"address": "overlay:0x1000", "type": "Note", "category": "Review", "comment": comment}))
                .collect(),
        ),
        "program_list_relocations" => (
            "relocations",
            ["zeta", "alpha", "beta"]
                .into_iter()
                .enumerate()
                .map(|(i, symbol_name)| json!({"address": format!("0x{:x}", 0x1000 + i), "symbol_name": symbol_name, "status": "APPLIED"}))
                .collect(),
        ),
        "function_list_calling_conventions" => (
            "calling_conventions",
            ["zeta", "alpha", "beta"]
                .into_iter()
                .enumerate()
                .map(|(i, name)| json!({"name": name, "is_default": i == 0}))
                .collect(),
        ),
        _ => panic!("unexpected API list command: {command}"),
    }
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
        // Match the physical working directory seen by subprocesses on macOS,
        // where the temporary directory can be reached through /var or /private/var.
        let root = tempfile::Builder::new()
            .prefix("routing tests' ")
            .tempdir_in(dunce::canonicalize(std::env::temp_dir()).unwrap())
            .unwrap();
        installation_fixture::write(&root.path().join("unused-install"));
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
                if args["text"] == "test-save-failure"
                    || (request["command"] == "program_save"
                        && bridge_info["test_save_failure"] == true)
                {
                    writeln!(connection, "{}", json!({"status": "error", "message": "Save failed", "detail": {"save_failed": true}})).unwrap();
                    continue;
                }
                if args["text"] == "test-timeout" {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }
                if args["text"] == "test-lost-response" {
                    continue;
                }
                if args["text"] == "test-rollback" {
                    writeln!(connection, "{}", json!({"status": "error", "message": "Edit rejected", "detail": {"rolled_back": true, "program": program}})).unwrap();
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
                        "job": {"id": args["job_id"], "command": "analysis_run", "state": "complete"},
                    }),
                    "job_cancel" => json!({
                        "job_id": args["job_id"].as_u64().unwrap_or(7),
                        "state": "cancel_requested",
                    }),
                    "open_program" => {
                        program = args["program"].as_str().unwrap().to_owned();
                        json!({"program": program})
                    }
                    "list_programs" => json!({
                        "programs": [{"name": "A"}, {"name": "B"}],
                        "has_current_program": true,
                        "current_program_name": program,
                    }),
                    "import" => json!({"program": "imported"}),
                    "analysis_run" => {
                        let mode = if args["pending"] == true {
                            "pending"
                        } else if args["start"].is_string() {
                            "range"
                        } else {
                            "full"
                        };
                        let mut result = json!({
                            "status": "success", "program": program, "function_count": 3,
                            "mode": mode, "completed": true, "saved": true,
                        });
                        if mode == "range" {
                            result["start"] = args["start"].clone();
                            result["end"] = args["end"].clone();
                        }
                        result
                    }
                    "program_context_list" => json!({"count": 3, "registers": [
                        {"name": "ITState", "bit_length": 8},
                        {"name": "TMode", "bit_length": 1},
                        {"name": "contextreg", "bit_length": 32},
                    ]}),
                    "program_context_get" | "program_context_set" | "program_context_clear" => {
                        let command = request["command"].as_str().unwrap();
                        let end = args.get("end").unwrap_or(&args["start"]);
                        let cleared = command == "program_context_clear";
                        let stored = if cleared {
                            json!({"value": "0x0", "mask": "0x0"})
                        } else {
                            json!({"value": "0x1", "mask": "0x1"})
                        };
                        let default = json!({"value": "0x0", "mask": "0x1"});
                        let effective = if cleared { &default } else { &stored };
                        let ranges = if command == "program_context_get" && end != &args["start"] {
                            json!([
                                {"start": args["start"], "end": "overlay:0x1003", "stored": stored, "default": default, "effective": effective},
                                {"start": "overlay:0x1004", "end": "overlay:0x1007", "stored": {"value": "0x0", "mask": "0x0"}, "default": default, "effective": default},
                                {"start": "overlay:0x1008", "end": end, "stored": stored, "default": default, "effective": effective},
                            ])
                        } else {
                            json!([{"start": args["start"], "end": end, "stored": stored, "default": default, "effective": effective}])
                        };
                        let mut result = json!({
                            "register": args["register"], "bit_length": 1,
                            "start": args["start"], "end": end, "ranges": ranges,
                        });
                        if command != "program_context_get" {
                            result["status"] = json!(if cleared { "cleared" } else { "set" });
                        }
                        result
                    }
                    "program_rebase" => json!({
                        "old_base": "0x00001000", "new_base": "0x80000000",
                        "delta_bytes": "2147479552",
                        "moved_blocks": [{"name": "code", "old_start": "0x00001000", "old_end": "0x00001fff", "new_start": "0x80000000", "new_end": "0x80000fff"}],
                        "unchanged_blocks": [{"name": "overlay", "start": "overlay:0x00001000", "end": "overlay:0x000010ff", "reason": "overlay"}],
                    }),
                    "analysis_option_list" => json!({"count": 3, "options": [
                        {"name": "Analyzer", "type": "boolean", "value": true},
                        {"name": "Analyzer.Mode", "type": "enum", "value": "FAST", "choices": ["FAST", "FULL"]},
                        {"name": "Analyzer.Limit", "type": "int", "value": 10},
                    ]}),
                    "analysis_option_get" => json!({
                        "name": args["name"], "type": "enum", "value": "FAST", "choices": ["FAST", "FULL"],
                    }),
                    "analysis_option_set" => json!({
                        "name": args["name"], "type": "string", "value": args["value"], "status": "set",
                    }),
                    "bookmark_list"
                    | "bookmark_get"
                    | "program_list_relocations"
                    | "function_list_calling_conventions" => {
                        let (key, rows) = api_list_fixture(request["command"].as_str().unwrap());
                        json!({key: rows, "count": rows.len()})
                    }
                    "function_var_list" => json!({
                        "function": args["target"], "address": "0x1000", "program": program,
                        "modification": "42", "variables": [
                            {"name": "value", "kind": "param", "type": "int", "storage": "EDI:4", "ordinal": 0, "first_use": null},
                            {"name": "value", "kind": "local", "type": "int", "storage": "Stack[-0x8]:4", "ordinal": null, "first_use": "0x1010"},
                            {"name": "other", "kind": "local", "type": "int", "storage": "Stack[-0x4]:4", "ordinal": null, "first_use": "0x1014"},
                        ],
                    }),
                    "function_var_get" => json!({
                        "function": args["target"], "address": "0x1000",
                        "decompiler": args["selection"]["variable"], "database": null,
                    }),
                    "function_var_set" => json!({
                        "status": "updated", "function": args["target"], "address": "0x1000", "kind": "local",
                        "decompiler": args["selection"]["variable"], "before": null,
                        "after": {"name": args["new_name"], "type": args["type_name"]},
                    }),
                    "decompile" if args["address"] == "warned" => {
                        json!({
                            "name": "warned", "address": "0x1000",
                            "is_external": false, "entry_memory": {"name": "code", "permissions": "rx"},
                            "code": "/* WARNING: in C */\nint warned(void) { return 0; }\n",
                            "warnings": [
                                {"source": "decompiler", "message": "API-only diagnostic", "address": null},
                                {"source": "decompiler", "message": "WARNING: in C", "address": null},
                                {"source": "c_comment", "message": "WARNING: in C", "address": "0x1000"}
                            ]
                        })
                    }
                    "decompile" => {
                        let mut result = json!({"name": "main", "address": "0x1000", "code": "int main(void) {\n  return 0;\n}\n", "basic_block_count": 3});
                        if args["with_jump_tables"] == true {
                            result["jump_tables"] = json!([
                                {"switch_address": "0x1010", "cases": [{"label": 0, "address": "0x1020", "is_default": false}, {"label": 1, "address": "0x1030", "is_default": false}]},
                                {"switch_address": "0x1040", "cases": [{"label": 2, "address": "0x1050", "is_default": false}]},
                            ]);
                        }
                        result
                    }
                    "data_list" => {
                        let mut rows = vec![
                            json!({"name":"zeta", "address":"0x3000", "type":"Record", "size":16, "incoming_reference_count":0}),
                            json!({"name":"alpha", "address":"0x1000", "type":"Record", "size":8, "incoming_reference_count":9}),
                            json!({"name":"beta", "address":"0x2000", "type":"int", "size":4, "incoming_reference_count":3}),
                        ];
                        if let Some(limit) = args["limit"].as_u64().filter(|n| *n != 0) {
                            rows.truncate(limit as usize);
                        }
                        json!({"count":rows.len(), "items":rows})
                    }
                    "data_read" => json!({
                        "address":"0x1000", "name":"record", "type":"Record", "kind":"struct",
                        "state":"available", "target_address":"0x1000", "target_offset":0,
                        "components":[{"name":"flags", "value":"3"}, {"name":"count", "value":"7"}],
                    }),
                    "memory_info" => json!({
                        "address": "0x1000", "kind": "instruction",
                        "instruction": {"address": "0x1000", "end": "0x1001", "size": 2, "offset": 0, "mnemonic": "MOV"},
                        "data": null, "function": {"name": "main", "address": "0x1000"},
                        "memory": {"name": "code", "start": "0x1000", "end": "0x1fff", "permissions": "rx", "initialized": true},
                    }),
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
                    "graph_cfg" => functions::flow_fixture(false, &program),
                    "pcode_function" if args["high"] == true => {
                        functions::flow_fixture(true, &program)
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
                    "find_constant" => {
                        let mut rows: Vec<_> = [8, 16, 32, 64]
                            .into_iter()
                            .enumerate()
                            .map(|(i, bits)| {
                                json!({
                                    "address": format!("0x{:x}", 0x1000 + i),
                                    "disasm": "MOV reg,0x1", "operand_index": 1,
                                    "bits": bits, "value": "0x1", "signed_value": "1",
                                })
                            })
                            .collect();
                        if let Some(limit) = args["limit"].as_u64().filter(|&n| n > 0) {
                            rows.truncate(limit as usize);
                        }
                        json!({"results": rows, "count": rows.len()})
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
                            json!({"name":"first", "observed_program": program}),
                            json!({"name":"second", "observed_program": program}),
                            json!({"name":"third", "observed_program": program}),
                        ];
                        let key = "blocks";
                        json!({key: rows, "count": rows.len()})
                    }
                    "memory_file_mappings" => memory::file_mappings_fixture(args, &program),
                    "memory_block_create"
                    | "memory_block_rename"
                    | "memory_block_set_permissions"
                    | "memory_block_set_volatile"
                    | "memory_block_move"
                    | "memory_block_delete" => memory::block_receipt_fixture(
                        request["command"].as_str().unwrap(),
                        args,
                        &program,
                    ),
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
                    "equate_list" | "namespace_list" => {
                        let key = if request["command"] == "equate_list" {
                            "equates"
                        } else {
                            "namespaces"
                        };
                        let rows: Vec<_> = ["zeta", "alpha", "beta"].into_iter().map(|name| {
                            json!({"name": name, "path": name, "value": "0xffffffffffffffff", "signed_value": "-1", "kind": "ordinary"})
                        }).collect();
                        json!({key: rows, "count": 3})
                    }
                    "equate_get" => {
                        json!({"name": args["name"], "value": "0xffffffffffffffff", "signed_value": "-1",
                        "kind": "ordinary", "reference_count": 2, "references": [{"address": "0x1000", "operand_index": 1}, {"address": "0x2000", "operand_index": 1}]})
                    }
                    "namespace_get" => {
                        json!({"id": "9007199254740993", "name": "Widget", "path": args["path"], "parent": "app", "kind": "class"})
                    }
                    "type_category_list" => types::category_list_fixture(args),
                    "type_uses" => types::uses_fixture(args),
                    "type_clone"
                    | "type_resize"
                    | "type_move"
                    | "type_category_create"
                    | "type_category_delete"
                    | "type_field_create_bitfield" => json!({
                        "status": "updated", "changed": true,
                        "before": {"fields": [{"name": "flags", "bit_size": 3}]},
                        "after": {"fields": [{"name": "flags", "bit_size": 4}]},
                        "observed_program": program,
                    }),
                    "xref_create_memory"
                    | "xref_delete"
                    | "xref_set_primary"
                    | "equate_create"
                    | "equate_attach"
                    | "equate_detach"
                    | "equate_delete"
                    | "namespace_create"
                    | "symbol_set_namespace"
                    | "symbol_set_primary"
                    | "bookmark_set"
                    | "bookmark_delete" => json!({"changed": true, "count": 1,
                        "before": [{"address": "0x1000"}], "after": [{"address": "0x1000"}], "observed_program": program}),
                    "tag_attach" | "tag_detach" => {
                        json!({"status": if request["command"] == "tag_attach" {"attached"} else {"detached"}, "observed_program": program})
                    }
                    "define_code" => json!({"address": args["target"], "end": args["end"],
                        "ok": true, "landed": true, "already_defined": false,
                        "changed": true, "status": "defined"}),
                    "symbol_get" | "symbol_get_by_name" => {
                        json!({"symbols": if args["name"] == "missing" {
                            vec![]
                        } else if args["name"] == "scoped" {
                            [("9007199254740993", "app"), ("9007199254740994", "app::Widget")]
                                .into_iter().map(|(id, namespace)| {
                                    let mut symbol = symbol_fixture(id, "0x00ab", "label");
                                    symbol["name"] = json!("scoped");
                                    symbol["namespace"] = json!(namespace);
                                    symbol
                                }).collect()
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
                    "comment_get" => json!({
                        "address": args["address"],
                        "comments": [{"type": "EOL", "text": "first\nsecond"}, {"type": "PRE", "text": "review"}],
                    }),
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
        crate::json_output::from_slice(&output.stdout).unwrap()
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
