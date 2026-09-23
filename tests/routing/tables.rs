use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn vtable_fixture(args: &Value, program: &str) -> Value {
    let entry_size = if args["encoding"] == "relative32" {
        4
    } else {
        8
    };
    let entries: Vec<_> = (0..args["entries"].as_u64().unwrap())
        .map(|index| {
            json!({
                "index": index,
                "offset": index * entry_size,
                "address": format!("bank1:0x{:x}", 0x4000 + index * entry_size),
                "target_address": format!("bank1:0x{:x}", 0x1000 + index * 16),
                "readable": true,
            })
        })
        .collect();
    json!({
        "address": "bank1:0x4000", "abi": args["abi"], "encoding": args["encoding"],
        "pointer_size": 8, "entry_size": entry_size, "endian": "little",
        "requested_entries": entries.len(), "read_entries": entries.len(),
        "complete": true, "entries": entries, "observed_program": program,
    })
}

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
fn vtable_reads_preserve_targets_and_nested_slots_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (target, abi, encoding) in [
        ("bank1:0x4000", "itanium", None),
        ("Widget::vftable", "msvc", Some("absolute")),
        ("relative_slots", "itanium", Some("relative32")),
    ] {
        let expected_args = json!({
            "target": target, "entries": 3, "abi": abi,
            "encoding": encoding.unwrap_or("absolute"),
        });
        for batched in [false, true] {
            for project_fields in [false, true] {
                outer.requests.lock().unwrap().clear();
                selected.requests.lock().unwrap().clear();
                let mut args = vec![
                    "vtable",
                    "read",
                    target,
                    "--entries",
                    "0x3",
                    "--abi",
                    abi,
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ];
                if let Some(encoding) = encoding {
                    args.extend(["--encoding", encoding]);
                }
                if project_fields {
                    args.extend(["--fields", "address,entries,observed_program"]);
                }
                let result = run(&outer, &args, batched);
                let expected = vtable_fixture(&expected_args, "B");
                if project_fields {
                    assert_eq!(
                        result,
                        json!({"data": {
                            "address": expected["address"], "entries": expected["entries"],
                            "observed_program": "B",
                        }})
                    );
                } else {
                    assert_eq!(result, json!({"data": expected}));
                }
                // The configured default limit is one; it must not truncate an object.
                assert_eq!(result["data"]["entries"].as_array().unwrap().len(), 3);
                assert!(outer
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request["command"] == "bridge_info"));
                let requests = selected.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|request| request["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 2, "{requests:?}");
                assert_eq!(domain[0]["command"], "open_program");
                assert_eq!(domain[0]["args"], json!({"program": "B"}));
                assert_eq!(domain[1]["command"], "vtable_read");
                assert_eq!(domain[1]["args"], expected_args);
            }
        }
    }
}

#[test]
fn incompatible_vtable_layout_fails_before_program_selection_and_batch_execution() {
    let bridge = RecordedBridge::new();
    let args = [
        "vtable",
        "read",
        "bank1:0x4000",
        "--entries",
        "4",
        "--abi",
        "msvc",
        "--encoding",
        "relative32",
        "--program",
        "must-not-open",
    ];
    let output = bridge.command().args(args).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--encoding relative32 requires --abi itanium"),
        "{output:?}"
    );
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
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["data"]["commands_executed"], 0);
    assert_eq!(result["data"]["validation_failed"], true);
    assert!(result["data"]["validation_errors"][0]["error"]
        .as_str()
        .unwrap()
        .contains("--encoding relative32 requires --abi itanium"));
    assert!(bridge.requests.lock().unwrap().is_empty());
}
