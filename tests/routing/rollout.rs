use super::{batch_arguments, RecordedBridge};
use serde_json::json;

#[test]
fn new_inspection_and_abi_commands_keep_targets_and_wire_values_in_batches() {
    for (args, command, expected) in [
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
