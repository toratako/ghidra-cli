use super::{batch_arguments, symbol_fixture, RecordedBridge};
use serde_json::{json, Value};

fn run(bridge: &RecordedBridge, args: &[&str], batched: bool) -> Value {
    let output = if batched {
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(args)).unwrap();
        bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap()
    } else {
        bridge.command().args(args).output().unwrap()
    };
    assert!(
        output.status.success(),
        "{args:?}, batch={batched}: {output:?}"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if batched {
        assert_eq!(result["data"]["failed"], 0);
        result["data"]["results"][0]["result"].clone()
    } else {
        result
    }
}

#[test]
fn annotation_commands_route_exact_arguments_and_targets_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (mut args, wire, expected) in [
        (
            vec![
                "xref",
                "create",
                "memory",
                "0x1000",
                "overlay:0x2000",
                "--operand=-1",
                "--type",
                "data",
            ],
            "xref_create_memory",
            json!({"from":"0x1000", "to":"overlay:0x2000", "operand_index":-1, "ref_type":"DATA"}),
        ),
        (
            vec!["xref", "delete", "0x1000", "0x2000", "--operand", "1"],
            "xref_delete",
            json!({"from":"0x1000", "to":"0x2000", "operand_index":1, "source":"USER_DEFINED"}),
        ),
        (
            vec![
                "xref",
                "set-primary",
                "0x1000",
                "0x2000",
                "--operand",
                "0",
                "--source",
                "analysis",
            ],
            "xref_set_primary",
            json!({"from":"0x1000", "to":"0x2000", "operand_index":0, "source":"ANALYSIS"}),
        ),
        (vec!["equate", "list"], "equate_list", Value::Null),
        (
            vec!["equate", "get", "FLAG"],
            "equate_get",
            json!({"name":"FLAG"}),
        ),
        (
            vec!["equate", "create", "FLAG", "0xffffffffffffffff"],
            "equate_create",
            json!({"name":"FLAG", "value":"0xffffffffffffffff"}),
        ),
        (
            vec!["equate", "create", "FLAG", "-9223372036854775808"],
            "equate_create",
            json!({"name":"FLAG", "value":"-9223372036854775808"}),
        ),
        (
            vec![
                "equate",
                "attach",
                "FLAG",
                "--at",
                "0x1000",
                "--operand",
                "1",
            ],
            "equate_attach",
            json!({"name":"FLAG", "address":"0x1000", "operand_index":1}),
        ),
        (
            vec![
                "equate",
                "detach",
                "FLAG",
                "--at",
                "0x1000",
                "--operand",
                "1",
            ],
            "equate_detach",
            json!({"name":"FLAG", "address":"0x1000", "operand_index":1}),
        ),
        (
            vec!["equate", "delete", "FLAG"],
            "equate_delete",
            json!({"name":"FLAG"}),
        ),
        (vec!["namespace", "list"], "namespace_list", Value::Null),
        (
            vec!["namespace", "get", "app::Widget"],
            "namespace_get",
            json!({"path":"app::Widget"}),
        ),
        (
            vec!["namespace", "create", "app"],
            "namespace_create",
            json!({"name":"app", "parent":null, "kind":"namespace"}),
        ),
        (
            vec![
                "namespace",
                "create",
                "Widget",
                "--parent",
                "app",
                "--kind",
                "class",
            ],
            "namespace_create",
            json!({"name":"Widget", "parent":"app", "kind":"class"}),
        ),
        (
            vec![
                "symbol",
                "set-namespace",
                "shared",
                "--namespace",
                "app::Widget",
                "--address",
                "0xab",
            ],
            "symbol_set_namespace",
            json!({"name":"shared", "targets":[symbol_fixture("9007199254740993", "0x00ab", "label")], "namespace":"app::Widget", "global":false}),
        ),
        (
            vec![
                "symbol",
                "set-namespace",
                "shared",
                "--global",
                "--filter",
                "id='9007199254740994'",
            ],
            "symbol_set_namespace",
            json!({"name":"shared", "targets":[symbol_fixture("9007199254740994", "0x00cd", "function")], "namespace":null, "global":true}),
        ),
        (
            vec!["symbol", "set-primary", "shared", "--filter", "kind=label"],
            "symbol_set_primary",
            json!({"name":"shared", "targets":[symbol_fixture("9007199254740993", "0x00ab", "label")]}),
        ),
        (
            vec![
                "bookmark",
                "set",
                "EXTERNAL:0x1000",
                "--text",
                "確認する",
                "--category",
                "Review",
            ],
            "bookmark_set",
            json!({"address":"EXTERNAL:0x1000", "text":"確認する", "type":"Note", "category":"Review"}),
        ),
        (
            vec![
                "bookmark",
                "delete",
                "overlay:0x1000",
                "--type",
                "note",
                "--category",
                "review",
            ],
            "bookmark_delete",
            json!({"address":"overlay:0x1000", "type":"note", "category":"review"}),
        ),
        (
            vec!["tag", "attach", "Reviewed", "Crypto", "--function", "main"],
            "tag_attach",
            json!({"function":"main", "tags":["Reviewed", "Crypto"]}),
        ),
        (
            vec!["tag", "detach", "Reviewed", "--function", "main"],
            "tag_detach",
            json!({"function":"main", "tags":["Reviewed"], "all":false}),
        ),
        (
            vec!["tag", "detach", "--all", "--function", "main"],
            "tag_detach",
            json!({"function":"main", "tags":[], "all":true}),
        ),
    ] {
        args.extend([
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
        ]);
        let mut standalone = Value::Null;
        for batched in [false, true] {
            first.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let result = run(&first, &args, batched);
            let is_list = matches!(wire, "equate_list" | "namespace_list");
            assert_eq!(result["data"].is_array(), is_list, "{args:?}: {result}");
            if !is_list {
                assert!(result.get("meta").is_none(), "{args:?}: {result}");
            }
            if batched {
                assert_eq!(result, standalone, "{args:?}");
            } else {
                standalone = result;
            }
            assert!(first
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"));
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"], json!({"program":"B"}));
            let edits: Vec<_> = domain.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(edits.len(), 1, "{args:?}: {domain:?}");
            assert_eq!(edits[0]["args"], expected, "{args:?}");
            if wire.starts_with("symbol_") {
                assert_eq!(domain.len(), 3);
                assert_eq!(domain[1]["command"], "symbol_get_by_name");
            } else {
                assert_eq!(domain.len(), 2);
            }
        }
    }
}

#[test]
fn definition_queries_and_nested_receipts_use_the_shared_result_contract() {
    let bridge = RecordedBridge::new();
    for batched in [false, true] {
        for family in ["equate", "namespace"] {
            let result = run(
                &bridge,
                &[
                    family,
                    "list",
                    "--filter",
                    "name!=zeta",
                    "--sort",
                    "name",
                    "--skip",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "name",
                ],
                batched,
            );
            assert_eq!(
                result,
                json!({"data":[{"name":"beta"}], "meta":{"offset":1,"limit":1,"returned":1}})
            );
            assert_eq!(
                run(&bridge, &[family, "list", "--count"], batched)["data"],
                3
            );
        }
        let definition = run(
            &bridge,
            &[
                "equate",
                "get",
                "FLAG",
                "--fields",
                "value,signed_value,references",
            ],
            batched,
        );
        assert_eq!(definition["data"]["value"], "0xffffffffffffffff");
        assert_eq!(definition["data"]["signed_value"], "-1");
        assert_eq!(
            definition["data"]["references"].as_array().unwrap().len(),
            2
        );
        assert!(definition.get("meta").is_none());
        for args in [
            vec!["xref", "set-primary", "0x1000", "0x2000", "--operand", "1"],
            vec!["bookmark", "delete", "0x1000", "--category", "Review"],
            vec![
                "equate",
                "attach",
                "FLAG",
                "--at",
                "0x1000",
                "--operand",
                "1",
            ],
            vec!["namespace", "create", "app"],
            vec!["symbol", "set-primary", "shared", "--address", "0xab"],
        ] {
            let args: Vec<_> = args
                .into_iter()
                .chain(["--fields", "changed,count,before,after"])
                .collect();
            assert_eq!(
                run(&bridge, &args, batched),
                json!({"data":{"changed":true,"count":1,"before":[{"address":"0x1000"}],"after":[{"address":"0x1000"}]}})
            );
        }
    }
}

#[test]
fn invalid_annotation_edits_fail_during_preflight_before_program_selection() {
    let bridge = RecordedBridge::new();
    for args in [
        vec![
            "xref",
            "create",
            "memory",
            "entry",
            "0x2000",
            "--operand",
            "0",
            "--type",
            "DATA",
        ],
        vec!["xref", "delete", "0x1000", "0x2000"],
        vec!["equate", "attach", "FLAG", "--at", "0x1000", "--operand=-1"],
        vec!["equate", "create", "FLAG", "9223372036854775808"],
        vec!["bookmark", "delete", "dead", "--category", "Review"],
        vec![
            "symbol",
            "set-namespace",
            "shared",
            "--namespace",
            "app",
            "--filter",
            "invalid",
        ],
        vec!["symbol", "set-primary", "shared", "--address", "dead"],
    ] {
        let args: Vec<_> = args
            .into_iter()
            .chain(["--program", "must-not-open"])
            .collect();
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            format!("program info\n{}", batch_arguments(&args)),
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["data"]["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty(), "{args:?}");
    }
}

#[test]
fn ambiguous_symbol_edits_report_stable_candidates_without_sending_a_mutation() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["symbol", "set-namespace", "shared", "--namespace", "app"],
        vec!["symbol", "set-primary", "shared"],
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let message = error["message"].as_str().unwrap();
        for candidate in [
            "9007199254740993",
            "9007199254740994",
            "namespace=Global",
            "address=0x00ab",
            "address=0x00cd",
        ] {
            assert!(message.contains(candidate), "{error}");
        }
        assert!(!message.contains("--all"), "{error}");
        assert!(bridge.requests.lock().unwrap().iter().all(|r| matches!(
            r["command"].as_str(),
            Some("bridge_info" | "symbol_get_by_name")
        )));
    }
}

#[test]
fn bookmark_text_inputs_preserve_unicode_whitespace_and_empty_text() {
    let bridge = RecordedBridge::new();
    for text in ["  確認\r\n`tick` $literal\n", ""] {
        std::fs::write(bridge.root.path().join("note.txt"), text).unwrap();
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            run(
                &bridge,
                &[
                    "bookmark",
                    "set",
                    "0x1000",
                    "--category",
                    "Review",
                    "--file",
                    "note.txt",
                ],
                batched,
            );
            let requests = bridge.requests.lock().unwrap();
            let request = requests
                .iter()
                .find(|r| r["command"] == "bookmark_set")
                .unwrap();
            assert_eq!(request["args"]["text"], text);
        }
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args([
                "bookmark",
                "set",
                "0x1000",
                "--category",
                "Review",
                "--stdin",
            ])
            .write_stdin(text)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let requests = bridge.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|r| r["command"] == "bookmark_set")
            .unwrap();
        assert_eq!(request["args"]["text"], text);
    }
}

#[test]
fn symbols_sharing_an_address_still_require_a_unique_namespace_or_id() {
    let bridge = RecordedBridge::new();
    for (command, destination) in [("set-primary", None), ("set-namespace", Some("other"))] {
        let mut args = vec!["symbol", command, "scoped"];
        if let Some(destination) = destination {
            args.extend(["--namespace", destination]);
        }
        args.extend(["--address", "0xab"]);
        bridge.requests.lock().unwrap().clear();
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("namespace=app::Widget"), "{error}");
        assert!(message.contains("namespace=app, address=0x00ab"), "{error}");
        assert!(bridge.requests.lock().unwrap().iter().all(|r| matches!(
            r["command"].as_str(),
            Some("bridge_info" | "symbol_get_by_name")
        )));
        args.extend(["--filter", "namespace='app::Widget'"]);
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            run(&bridge, &args, batched);
            let requests = bridge.requests.lock().unwrap();
            let edit = requests.last().unwrap();
            assert_eq!(edit["args"]["targets"].as_array().unwrap().len(), 1);
            assert_eq!(edit["args"]["targets"][0]["id"], "9007199254740994");
            assert_eq!(edit["args"]["targets"][0]["namespace"], "app::Widget");
        }
    }
}
