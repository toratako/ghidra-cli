use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

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
            assert_eq!(
                domain[1]["args"],
                json!({"address": "0x1000", "size": 8, "source": "memory"})
            );
        }
    }
}

#[test]
fn memory_info_preserves_nested_details_and_projection_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for target in ["main", "overlay:0x1000"] {
        for fields in [None, Some("kind,instruction,data,function,memory")] {
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let mut args = vec!["memory", "info", target, "--program", "B"];
                if let Some(fields) = fields {
                    args.extend(["--fields", fields]);
                }
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                let object = if batch && fields.is_none() {
                    &result
                } else {
                    &result[0]
                };
                assert_eq!(object["kind"], "instruction");
                assert_eq!(object["instruction"]["mnemonic"], "MOV");
                assert_eq!(object["data"], Value::Null);
                assert_eq!(object["function"]["name"], "main");
                assert_eq!(object["memory"]["permissions"], "rx");
                assert_eq!(object.get("address").is_some(), fields.is_none());
                let requests = bridge.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 2, "{domain:?}");
                assert_eq!(domain[0]["command"], "open_program");
                assert_eq!(domain[0]["args"], json!({"program": "B"}));
                assert_eq!(domain[1]["command"], "memory_info");
                assert_eq!(domain[1]["args"], json!({"address": target}));
            }
        }
    }
    let output = bridge
        .command()
        .args(["memory", "info", "main", "--format", "compact"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("instruction") && text.contains("MOV") && text.contains("main"),
        "{text}"
    );
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
fn api_reads_honor_project_overrides_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (command, wire) in [
        (vec!["bookmark", "list"], "bookmark_list"),
        (vec!["bookmark", "get", "0x1000"], "bookmark_get"),
        (vec!["memory", "info", "main"], "memory_info"),
        (
            vec!["program", "list-relocations"],
            "program_list_relocations",
        ),
        (
            vec!["function", "list-calling-conventions"],
            "function_list_calling_conventions",
        ),
    ] {
        for batch in [false, true] {
            first.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain([
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ])
                .collect();
            if batch {
                std::fs::write(first.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                first.run(&["batch", "batch.txt"]);
            } else {
                first.run(&args);
            }
            assert!(first
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"));
            let requests = selected.requests.lock().unwrap();
            assert_eq!(requests.iter().filter(|r| r["command"] == wire).count(), 1);
            assert!(requests
                .iter()
                .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        }
    }
}
