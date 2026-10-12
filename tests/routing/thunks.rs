use super::{batch_arguments, RecordedBridge};
use crate::responses::thunks::receipt_fixture;
use serde_json::{json, Value};

#[test]
fn thunk_edits_preserve_targets_and_receipts_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (base, wire, expected_args, set) in [
        (
            vec![
                "function",
                "set-thunk",
                "app::wrapper",
                "--target",
                "overlay:0x2000",
            ],
            "function_set_thunk",
            json!({"target": "app::wrapper", "thunk_target": "overlay:0x2000"}),
            true,
        ),
        (
            vec!["function", "clear-thunk", "overlay:0x1000"],
            "function_clear_thunk",
            json!({"target": "overlay:0x1000"}),
            false,
        ),
    ] {
        let receipt = receipt_fixture(set);
        let mut excluded = receipt.clone();
        excluded.as_object_mut().unwrap().remove("before");
        for (projection, expected) in [
            (vec![], receipt.clone()),
            (
                vec!["--fields", "status,after"],
                json!({"status": receipt["status"], "after": receipt["after"]}),
            ),
            (vec!["--exclude-fields", "before"], excluded),
        ] {
            let mut standalone = Value::Null;
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = base.clone();
                args.extend(projection.iter().copied());
                args.extend([
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ]);
                let result = if batch {
                    std::fs::write(outer.root.path().join("thunks.txt"), batch_arguments(&args))
                        .unwrap();
                    let report = outer.run(&["batch", "thunks.txt"]);
                    assert_eq!(report["failed"], 0, "{report}");
                    report["results"][0]["result"].clone()
                } else {
                    let output = outer.command().args(&args).output().unwrap();
                    assert!(output.status.success(), "{args:?}: {output:?}");
                    serde_json::from_slice(&output.stdout).unwrap()
                };
                assert_eq!(result, json!({"data": expected}), "{args:?}, batch={batch}");
                if batch {
                    assert_eq!(result, standalone);
                } else {
                    standalone = result;
                }
                let requests = selected.requests.lock().unwrap();
                let operations: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(operations.len(), 1, "{requests:?}");
                assert_eq!(operations[0]["program"], "B");
                assert_eq!(operations[0]["command"], wire);
                assert_eq!(operations[0]["args"], expected_args);
            }
        }
    }
    assert!(outer.requests.lock().unwrap().iter().all(|request| {
        request["command"] != "function_set_thunk"
            && request["command"] != "function_clear_thunk"
            && request["command"] != "open_program"
    }));
}

#[test]
fn missing_thunk_destination_prevents_program_selection_and_batch_mutations() {
    let bridge = RecordedBridge::new();
    let args = [
        "function",
        "set-thunk",
        "wrapper",
        "--program",
        "must-not-open",
    ];
    let output = bridge.command().args(args).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    std::fs::write(
        bridge.root.path().join("incomplete-thunk.txt"),
        format!("function clear-thunk wrapper\n{}\n", batch_arguments(&args)),
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "incomplete-thunk.txt"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["validation_failed"], true);
    assert_eq!(report["commands_executed"], 0);
    assert!(bridge.requests.lock().unwrap().is_empty());
}
