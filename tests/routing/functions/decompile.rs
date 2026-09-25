use super::super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn decompiler_commands_share_native_timeout_configuration() {
    let bridge = RecordedBridge::new();
    for (args, wire) in [
        (vec!["decompile", "main"], "decompile"),
        (vec!["function", "var", "list", "main"], "function_var_list"),
        (
            vec!["function", "var", "get", "main", "--var", "value"],
            "function_var_get",
        ),
        (
            vec!["function", "var", "infer-struct", "main", "--var", "value"],
            "function_var_infer_struct",
        ),
        (
            vec!["function", "set-return-type", "main", "--type", "void"],
            "function_set_return_type",
        ),
        (
            vec!["pcode", "function", "main", "--high"],
            "pcode_function",
        ),
        (
            vec![
                "function", "var", "set", "main", "--var", "param_1", "--name", "input",
            ],
            "function_var_set",
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
fn decompile_forwards_jump_table_selection_without_truncating_nested_results() {
    let bridge = RecordedBridge::new();
    for with_jump_tables in [false, true] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["decompile", "main"];
            if with_jump_tables {
                args.push("--with-jump-tables");
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result["basic_block_count"], 3);
            assert_eq!(result.get("jump_tables").is_some(), with_jump_tables);
            assert!(result.get("line_addresses").is_none());
            if with_jump_tables {
                assert_eq!(result["jump_tables"].as_array().unwrap().len(), 2);
                assert_eq!(
                    result["jump_tables"][0]["cases"].as_array().unwrap().len(),
                    2
                );
            }
            let requests = bridge.requests.lock().unwrap();
            let decompile: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "decompile")
                .collect();
            assert_eq!(decompile.len(), 1);
            assert_eq!(
                decompile[0]["args"],
                json!({"address": "main", "with_vars": false, "with_params": false, "with_jump_tables": with_jump_tables, "with_addresses": false, "timeout_secs": 0})
            );
        }
    }
}

#[test]
fn decompile_line_addresses_preserve_raw_code_projection_and_batch_output() {
    let bridge = RecordedBridge::new();
    for fields in [None, Some("code,line_addresses"), Some("code")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["decompile", "main", "--with-addresses", "--program", "B"];
            if let Some(fields) = fields {
                args.extend(["--fields", fields]);
            }
            let result = if batch {
                std::fs::write(
                    bridge.root.path().join("addresses.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "addresses.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result["code"], "int main(void) {\n  return 0;\n}\n");
            if fields == Some("code") {
                assert!(result.get("line_addresses").is_none());
            } else {
                assert_eq!(
                    result["line_addresses"],
                    json!([{"line": 2, "addresses": ["0x1004", "0x1008"]}])
                );
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "decompile")
                .collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["program"], "B");
            assert_eq!(
                operations[0]["args"],
                json!({"address": "main", "with_vars": false, "with_params": false,
                    "with_jump_tables": false, "with_addresses": true, "timeout_secs": 0})
            );
        }
    }
}
