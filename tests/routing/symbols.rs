use super::{batch_arguments, symbol_fixture, RecordedBridge};
use serde_json::{json, Value};

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
