use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn new_inspection_and_abi_commands_keep_targets_and_wire_values_in_batches() {
    for (args, command, expected) in [
        (
            vec!["function", "get", "callee", "--with-signature"],
            "get_function",
            json!({"address":"callee", "with_signature":true}),
        ),
        (
            vec!["function", "get", "callee"],
            "get_function",
            json!({"address":"callee", "with_signature":false}),
        ),
        (
            vec!["function", "set-stack-purge", "callee", "--bytes", "-4"],
            "function_set_stack_purge",
            json!({"target":"callee", "bytes":-4, "unknown":false}),
        ),
        (
            vec!["function", "set-stack-purge", "callee", "--unknown"],
            "function_set_stack_purge",
            json!({"target":"callee", "bytes":null, "unknown":true}),
        ),
        (
            vec!["memory", "read", "blob", "16", "--source", "original"],
            "read_memory",
            json!({"address":"blob", "size":16, "source":"original"}),
        ),
        (
            vec!["memory", "read", "blob", "16"],
            "read_memory",
            json!({"address":"blob", "size":16, "source":"memory"}),
        ),
        (
            vec![
                "data",
                "read",
                "record",
                "--max-depth",
                "3",
                "--max-elements",
                "7",
            ],
            "data_read",
            json!({"target":"record", "max_depth":3, "max_elements":7}),
        ),
    ] {
        let bridge = RecordedBridge::new();
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut targeted = args.clone();
            targeted.extend(["--program", "B"]);
            if batched {
                std::fs::write(
                    bridge.root.path().join("new.txt"),
                    batch_arguments(&targeted),
                )
                .unwrap();
                bridge.run(&["batch", "new.txt", "--program", "A"]);
            } else {
                bridge.run(&targeted);
            }
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            let last = domain.last().unwrap();
            assert_eq!(last["command"], command);
            assert_eq!(last["args"], expected);
            assert_eq!(domain[domain.len() - 2]["command"], "open_program");
            assert_eq!(domain[domain.len() - 2]["args"]["program"], "B");
        }
    }
}

#[test]
fn typed_data_selection_precedes_paging_and_preserves_object_components() {
    let bridge = RecordedBridge::new();
    for batched in [false, true] {
        for (args, expected, expected_limit) in [
            (
                vec!["data", "list"],
                json!([{"name":"zeta","address":"0x3000","type":"Record","size":16}]),
                json!(1),
            ),
            (
                vec![
                    "data",
                    "list",
                    "--filter",
                    "type=Record",
                    "--sort",
                    "name",
                    "--offset",
                    "1",
                    "--fields",
                    "name",
                ],
                json!([{"name":"zeta"}]),
                Value::Null,
            ),
            (vec!["data", "list", "--count"], json!(3), Value::Null),
        ] {
            bridge.requests.lock().unwrap().clear();
            let value = if batched {
                std::fs::write(bridge.root.path().join("data.txt"), batch_arguments(&args))
                    .unwrap();
                let report = bridge.run(&["batch", "data.txt"]);
                report[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            let value = if batched && args.len() == 2 {
                value["items"].clone()
            } else {
                value
            };
            assert_eq!(value, expected, "{args:?}, batch={batched}");
            let requests = bridge.requests.lock().unwrap();
            let request = requests
                .iter()
                .find(|r| r["command"] == "data_list")
                .unwrap();
            assert_eq!(request["args"]["limit"], expected_limit);
        }
        let args = ["data", "read", "record", "--fields", "components"];
        let value = if batched {
            std::fs::write(bridge.root.path().join("data.txt"), batch_arguments(&args)).unwrap();
            bridge.run(&["batch", "data.txt"])[0]["results"][0]["result"].clone()
        } else {
            bridge.run(&args)
        };
        assert_eq!(
            value,
            json!([{"components":[{"name":"flags","value":"3"},{"name":"count","value":"7"}]}])
        );
    }
}
