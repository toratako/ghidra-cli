use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

fn row(id: &str, path: &str, kind: &str) -> Value {
    let (parent, name) = path
        .rsplit_once("::")
        .map_or((None, path), |(parent, name)| (Some(parent), name));
    json!({"id":id, "name":name, "path":path, "parent":parent, "kind":kind})
}

fn bridge() -> RecordedBridge {
    RecordedBridge::with_info(json!({
        "protocol_version":4, "auto_save":true, "atomic_edits":true,
        "named_import":true, "explicit_addresses":true,
        "namespace_rows":[
            row("1", "other", "namespace"),
            json!({"id":"9007199254740993", "name":"app::Widget", "path":"app::Widget", "parent":null, "kind":"namespace"}),
            row("9007199254740994", "app::Widget", "namespace"),
            row("4", "app", "namespace"),
        ],
    }))
}

pub(super) fn receipt_fixture(command: &str, args: &Value) -> Value {
    let target = &args["target"];
    if command == "namespace_delete" {
        let recursive = args["recursive"] == true;
        let mut deleted = vec![
            json!({"id":target["id"],"name":target["name"],"path":target["path"],
            "parent":target["parent"],"type":"Namespace","address":null}),
        ];
        let mut counts = json!({"Namespace":1});
        if recursive {
            deleted.push(
                json!({"id":"10","name":"helper","path":"app::Widget::helper",
                "parent":"app::Widget","type":"Function","address":"0x1000"}),
            );
            counts["Function"] = json!(1);
        }
        json!({"status":"deleted","target":target,"recursive":recursive,
            "count":deleted.len(),"deleted":deleted,"counts":counts})
    } else {
        let mut after = target.clone();
        let status = if command == "namespace_rename" {
            after["name"] = args["new_name"].clone();
            "renamed"
        } else {
            after["parent"] = args["parent"]["path"].clone();
            "moved"
        };
        after["path"] = json!(match after["parent"].as_str() {
            Some(parent) => format!("{}::{}", parent, after["name"].as_str().unwrap()),
            None => after["name"].as_str().unwrap().to_owned(),
        });
        let status = if after == *target {
            "unchanged"
        } else {
            status
        };
        json!({"status":status,"before":target,"after":after,"function_changes":[]})
    }
}

fn invoke(bridge: &RecordedBridge, args: &[&str], batch: bool) -> std::process::Output {
    if batch {
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(args)).unwrap();
        bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap()
    } else {
        bridge.command().args(args).output().unwrap()
    }
}

#[test]
fn namespace_mutations_select_uncapped_snapshots_and_preserve_receipts() {
    let first = RecordedBridge::new();
    let selected = bridge();
    let target = row("9007199254740994", "app::Widget", "namespace");
    for (mut args, wire, expected, reads, fields) in [
        (
            vec!["namespace", "rename", "app::Widget", "Renamed"],
            "namespace_rename",
            json!({"target":target,"new_name":"Renamed"}),
            1,
            "status,before,after",
        ),
        (
            vec!["namespace", "move", "app::Widget", "--parent", "app"],
            "namespace_move",
            json!({"target":target,"parent":row("4", "app", "namespace")}),
            2,
            "status,before,after",
        ),
        (
            vec!["namespace", "move", "app::Widget", "--global"],
            "namespace_move",
            json!({"target":target,"parent":null}),
            1,
            "status,before,after",
        ),
        (
            vec!["namespace", "delete", "app::Widget"],
            "namespace_delete",
            json!({"target":target,"recursive":false}),
            1,
            "target,recursive,count,deleted,counts",
        ),
        (
            vec!["namespace", "delete", "app::Widget", "--recursive"],
            "namespace_delete",
            json!({"target":target,"recursive":true}),
            1,
            "target,recursive,count,deleted,counts",
        ),
    ] {
        args.extend([
            "--where",
            "id='9007199254740994'",
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
            "--fields",
            fields,
        ]);
        let mut standalone = Value::Null;
        for batch in [false, true] {
            first.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let output = invoke(&first, &args, batch);
            assert!(output.status.success(), "{args:?}: {output:?}");
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            let result = if batch {
                &response["data"]["results"][0]["result"]
            } else {
                &response
            };
            assert!(result["data"].is_object(), "{result}");
            assert!(result.get("meta").is_none(), "{result}");
            if wire == "namespace_delete" {
                assert_eq!(result["data"]["target"], target);
                let recursive = expected["recursive"] == true;
                assert_eq!(
                    result["data"]["deleted"].as_array().unwrap().len(),
                    if recursive { 2 } else { 1 }
                );
                assert_eq!(result["data"]["counts"]["Namespace"], 1);
                if recursive {
                    assert_eq!(result["data"]["counts"]["Function"], 1);
                }
                assert!(result["data"].get("status").is_none());
            } else {
                assert_eq!(result["data"]["before"], target);
                assert_eq!(result["data"]["after"]["id"], target["id"]);
            }
            if batch {
                assert_eq!(*result, standalone);
            } else {
                standalone = result.clone();
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
            assert_eq!(domain.len(), reads + 1, "{domain:?}");
            assert!(domain.iter().all(|r| r["program"] == "B"));
            for read in &domain[..reads] {
                assert_eq!(read["command"], "namespace_list");
                assert!(read["args"].is_null(), "{read}");
            }
            assert_eq!(domain[reads]["command"], wire);
            assert_eq!(domain[reads]["args"], expected);
        }
    }
}

#[test]
fn namespace_selection_never_broadens_paths_or_sends_ambiguous_edits() {
    let bridge = bridge();
    for (args, message) in [
        (
            vec!["namespace", "rename", "app::Widget", "Renamed"],
            "9007199254740993",
        ),
        (
            vec!["namespace", "delete", "app::Widget", "--recursive"],
            "9007199254740994",
        ),
        (
            vec![
                "namespace",
                "delete",
                "Widget",
                "--where",
                "id='9007199254740994'",
            ],
            "Namespace not found",
        ),
        (
            vec![
                "namespace",
                "delete",
                "app",
                "--where",
                "id='9007199254740994'",
            ],
            "No namespace",
        ),
        (
            vec!["namespace", "move", "app", "--parent", "app::Widget"],
            "matches 2 namespaces",
        ),
        (
            vec!["namespace", "move", "app", "--parent", "missing"],
            "Namespace not found",
        ),
    ] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let output = invoke(&bridge, &args, batch);
            assert!(!output.status.success(), "{args:?}: {output:?}");
            let diagnostic = if batch {
                &output.stdout
            } else {
                &output.stderr
            };
            assert!(
                String::from_utf8_lossy(diagnostic).contains(message),
                "{args:?}: {output:?}"
            );
            assert!(bridge.requests.lock().unwrap().iter().all(|r| matches!(
                r["command"].as_str(),
                Some("bridge_info" | "namespace_list")
            )));
        }
    }
}

#[test]
fn namespace_where_is_validated_before_any_standalone_or_batch_bridge_work() {
    let bridge = bridge();
    for args in [
        vec!["namespace", "rename", "app", "core"],
        vec!["namespace", "move", "app", "--global"],
        vec!["namespace", "delete", "app", "--recursive"],
    ] {
        let args: Vec<_> = args
            .into_iter()
            .chain(["--where", "invalid", "--program", "must-not-open"])
            .collect();
        let output = invoke(&bridge, &args, false);
        assert!(!output.status.success(), "{output:?}");
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
        assert!(!output.status.success(), "{output:?}");
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["data"]["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
