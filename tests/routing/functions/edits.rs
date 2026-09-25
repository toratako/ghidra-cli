use super::super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn signature_type_bindings_preserve_pairs_and_duplicates_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (base, wire, mut expected) in [
        (
            vec!["function", "set-signature", "entry"],
            "function_set_signature",
            json!({"target": "entry"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "entry",
                "--at",
                "0x1010",
            ],
            "function_call_signature_set",
            json!({"target": "entry", "at": "0x1010", "convention": null}),
        ),
    ] {
        expected["signature"] = json!("void entry(Profile *base, Cmp compare)");
        for bound in [false, true] {
            let mut args = base.clone();
            args.extend([
                "--signature",
                "void entry(Profile *base, Cmp compare)",
                "--program",
                "B",
            ]);
            if bound {
                args.extend([
                    "--bind-type",
                    "Profile",
                    "/Recovered Types/Profile",
                    "--bind-type",
                    "Cmp",
                    "/Recovered/Cmp",
                    "--bind-type",
                    "Cmp",
                    "/Other/Cmp",
                ]);
                expected["type_bindings"] = json!([
                    {"name": "Profile", "path": "/Recovered Types/Profile"},
                    {"name": "Cmp", "path": "/Recovered/Cmp"},
                    {"name": "Cmp", "path": "/Other/Cmp"},
                ]);
            }
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                if batch {
                    std::fs::write(
                        bridge.root.path().join("signatures.txt"),
                        batch_arguments(&args),
                    )
                    .unwrap();
                    bridge.run(&["batch", "signatures.txt"]);
                } else {
                    bridge.run(&args);
                }
                let requests = bridge.requests.lock().unwrap();
                let edits: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(edits.len(), 1);
                assert_eq!(edits[0]["args"], expected);
                assert_eq!(edits[0]["program"], "B");
            }
        }
    }
}

#[test]
fn function_body_and_call_signature_preserve_scope_and_options_in_batches() {
    let bridge = RecordedBridge::new();
    for (args, wire, expected) in [
        (
            vec![
                "function",
                "get",
                "caller",
                "--with-frame",
                "--with-signature",
            ],
            "get_function",
            json!({"address": "caller", "with_frame": true, "with_signature": true}),
        ),
        (
            vec![
                "function",
                "set-body",
                "caller",
                "--range",
                "overlay:0x1000",
                "overlay:0x101f",
                "--range",
                "overlay:0x2000",
                "overlay:0x200f",
            ],
            "function_set_body",
            json!({"target": "caller", "ranges": [{"start": "overlay:0x1000", "end": "overlay:0x101f"}, {"start": "overlay:0x2000", "end": "overlay:0x200f"}]}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "get",
                "caller",
                "--at",
                "ram:0x1234:0x10",
            ],
            "function_call_signature_get",
            json!({"target": "caller", "at": "ram:0x1234:0x10"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "caller",
                "--at",
                "0x1010",
                "--signature",
                "int callback(char *, ...)",
                "--convention",
                "__cdecl",
            ],
            "function_call_signature_set",
            json!({"target": "caller", "at": "0x1010", "signature": "int callback(char *, ...)", "convention": "__cdecl"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "caller",
                "--at",
                "0x1010",
                "--signature",
                "void callback(void)",
            ],
            "function_call_signature_set",
            json!({"target": "caller", "at": "0x1010", "signature": "void callback(void)", "convention": null}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "clear",
                "caller",
                "--at",
                "0x1010",
            ],
            "function_call_signature_clear",
            json!({"target": "caller", "at": "0x1010"}),
        ),
    ] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = args.clone();
            args.extend(["--program", "B", "--fields", "observed_program"]);
            let receipt = if batch {
                std::fs::write(
                    bridge.root.path().join("functions.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "functions.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(receipt, json!({"observed_program": "B"}));
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1, "{args:?}");
            assert_eq!(operations[0]["args"], expected, "{args:?}");
            assert!(requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .all(|r| r["program"] == "B"));
        }
    }
}

#[test]
fn variable_list_queries_preserve_context_and_filter_before_paging() {
    let bridge = RecordedBridge::new();
    let args = [
        "function",
        "var",
        "list",
        "main",
        "--filter",
        "kind=local",
        "--sort=-first_use",
        "--skip",
        "1",
        "--limit",
        "1",
        "--fields",
        "name,first_use",
    ];
    let output = bridge.command().args(args).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["data"],
        json!([{"name": "value", "first_use": "0x1010"}])
    );
    assert_eq!(result["meta"]["function"], "main");
    assert_eq!(result["meta"]["address"], "0x1000");
    assert_eq!(
        result["meta"]["project"],
        json!({"location":"/projects","name":"project"})
    );
    assert_eq!(result["meta"]["program"], "A");
    assert_eq!(result["meta"]["modification"], "42");
    assert_eq!(result["meta"]["returned"], 1);
    assert_eq!(result["meta"]["offset"], 1);
    assert_eq!(
        bridge.run(&["function", "var", "list", "main", "--count"]),
        3
    );
    std::fs::write(
        bridge.root.path().join("variables.txt"),
        batch_arguments(&args),
    )
    .unwrap();
    let batch = bridge.run(&["batch", "variables.txt"]);
    assert_eq!(batch["results"][0]["result"], result);
    let requests = bridge.requests.lock().unwrap();
    for request in requests
        .iter()
        .filter(|r| r["command"] == "function_var_list")
    {
        assert_eq!(
            request["args"],
            json!({"target": "main", "timeout_secs": 0})
        );
    }
}

#[test]
fn variable_selection_sends_full_snapshot_and_keeps_selector_out_of_result_queries() {
    let bridge = RecordedBridge::new();
    for operation in ["get", "set", "infer-struct"] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "function",
                "var",
                operation,
                "main",
                "--var",
                "value",
                "--where",
                "kind=local",
                "--program",
                "B",
            ];
            if operation == "set" {
                args.extend(["--name", "length", "--fields", "after"]);
            } else if operation == "infer-struct" {
                args.extend(["--with-accesses", "--max-accesses", "0x1"]);
            }
            let receipt = if batch {
                std::fs::write(
                    bridge.root.path().join("selection.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "selection.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            if operation == "set" {
                assert_eq!(receipt, json!({"after": {"name": "length", "type": null}}));
            } else if operation == "infer-struct" {
                assert_eq!(receipt["variable"]["name"], "value");
                assert_eq!(receipt["structure"]["components"][0]["offset"], 16);
                assert_eq!(receipt["accesses_status"]["truncated"], true);
                assert_eq!(receipt["accesses"].as_array().unwrap().len(), 1);
            } else {
                assert_eq!(receipt["decompiler"]["name"], "value");
                assert_eq!(receipt["decompiler"]["kind"], "local");
                assert!(receipt["database"].is_null());
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests
                .iter()
                .filter(|r| r["command"].as_str().unwrap().starts_with("function_var_"))
                .collect();
            assert_eq!(operations.len(), 2);
            assert!(operations.iter().all(|r| r["program"] == "B"));
            assert_eq!(operations[0]["command"], "function_var_list");
            assert_eq!(
                operations[1]["command"],
                format!("function_var_{}", operation.replace('-', "_"))
            );
            assert_eq!(operations[1]["args"]["var_name"], "value");
            assert_eq!(
                operations[1]["args"]["selection"],
                json!({
                    "project": {"location": "/projects", "name": "project"},
                    "program": "B", "function_address": "0x1000", "modification": "42",
                    "variable": {"name": "value", "kind": "local", "type": "int", "storage": "Stack[-0x8]:4", "ordinal": null, "first_use": "0x1010"},
                })
            );
            assert_eq!(operations[1]["args"]["timeout_secs"], 0);
            if operation == "infer-struct" {
                assert_eq!(operations[1]["args"]["with_accesses"], true);
                assert_eq!(operations[1]["args"]["max_accesses"], 1);
            }
        }
    }
}

#[test]
fn variable_selection_requires_exactly_one_same_name_candidate_before_mutation() {
    let bridge = RecordedBridge::new();
    for (filter, expected) in [
        ("kind=absent", "No variable named"),
        ("type=int", "matches 2 candidates"),
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args([
                "function", "var", "set", "main", "--var", "value", "--where", filter, "--name",
                "length",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{output:?}"
        );
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] == "function_var_list")
                .count(),
            1
        );
        assert!(requests.iter().all(|r| r["command"] != "function_var_set"));
    }
}

#[test]
fn function_edit_selectors_are_validated_before_program_selection_and_batch_execution() {
    let bridge = RecordedBridge::new();
    for args in [
        vec![
            "function",
            "set-body",
            "main",
            "--range",
            "0x1000",
            "overlay:1010",
        ],
        vec![
            "function",
            "call-signature",
            "clear",
            "main",
            "--at",
            "1010",
        ],
        vec![
            "function",
            "set-signature",
            "main",
            "--signature",
            "void main(void)",
            "--bind-type",
            "Bad-Name",
            "/Recovered/Profile",
        ],
        vec![
            "function",
            "call-signature",
            "set",
            "main",
            "--at",
            "0x1010",
            "--signature",
            "void callback(void)",
            "--bind-type",
            "Profile",
            "Recovered/Profile",
        ],
        vec![
            "function",
            "set-signature",
            "main",
            "--signature",
            "void main(void)",
            "--bind-type",
            "Profile",
            "/Recovered/",
        ],
        vec![
            "function", "var", "set", "main", "--var", "value", "--where", "invalid", "--name",
            "length",
        ],
        vec![
            "function",
            "var",
            "infer-struct",
            "main",
            "--var",
            "value",
            "--where",
            "invalid",
        ],
    ] {
        let mut args = args;
        args.extend(["--program", "must-not-open"]);
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        std::fs::write(
            bridge.root.path().join("invalid.txt"),
            batch_arguments(&args),
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "invalid.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["validation_failed"], true);
        assert_eq!(result["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
