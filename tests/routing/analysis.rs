use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn analysis_options_route_targets_values_and_queries_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let cases = [
        (
            vec![
                "analysis",
                "option",
                "list",
                "--filter",
                "name~\"Analyzer.\"",
                "--sort",
                "name",
                "--offset",
                "1",
                "--limit",
                "1",
                "--fields",
                "name,value",
            ],
            "analysis_option_list",
            json!([{"name": "Analyzer.Mode", "value": "FAST"}]),
        ),
        (
            vec!["analysis", "option", "get", "Analyzer.Mode"],
            "analysis_option_get",
            json!({"name": "Analyzer.Mode", "type": "enum", "value": "FAST", "choices": ["FAST", "FULL"]}),
        ),
        (
            vec![
                "analysis",
                "option",
                "set",
                "Analyzer.Path",
                "path with spaces",
                "--fields",
                "name,value,status",
            ],
            "analysis_option_set",
            json!({"name": "Analyzer.Path", "value": "path with spaces", "status": "set"}),
        ),
    ];
    for (mut args, wire, expected) in cases {
        args.extend(["--program", "B"]);
        let batch = format!("{}\n", batch_arguments(&args));
        std::fs::write(bridge.root.path().join("batch.txt"), batch).unwrap();
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let output = if batched {
                bridge
                    .command()
                    .args(["batch", "batch.txt", "--program", "A"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(&args).output().unwrap()
            };
            assert!(output.status.success(), "{args:?}: {output:?}");
            let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
            if batched {
                assert_eq!(result["failed"], 0);
                let actual = &result["results"][0]["result"]["data"];
                assert_eq!(actual, &expected);
            } else {
                assert_eq!(result, expected);
            }
            let requests = bridge.requests.lock().unwrap();
            assert_eq!(requests.last().unwrap()["command"], wire);
            assert_eq!(requests[requests.len() - 2]["command"], "open_program");
            assert_eq!(requests[requests.len() - 2]["args"]["program"], "B");
            if wire == "analysis_option_set" {
                assert_eq!(
                    requests.last().unwrap()["args"],
                    json!({"name": "Analyzer.Path", "value": "path with spaces"})
                );
            }
            assert!(!requests
                .iter()
                .any(|request| request["command"] == "analysis_run"));
        }
    }
}

#[test]
fn analysis_run_preserves_target_selection_and_results_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let expected = json!({
        "command": "analysis run", "status": "success",
        "data": {"status": "success", "program": "B", "function_count": 3},
    });
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "analysis run --program B\nanalysis run\n",
    )
    .unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args(["analysis", "run", "--program", "B"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "JSON modes suppress progress");
        assert_eq!(
            crate::json_output::from_slice::<Value>(&output.stdout).unwrap(),
            expected
        );
        let requests = bridge.requests.lock().unwrap().clone();
        assert_eq!(requests[requests.len() - 2]["command"], "open_program");
        assert_eq!(requests.last().unwrap()["command"], "analysis_run");

        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args(["batch", "batch.txt", "--program", "A"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "batch must suppress progress");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["failed"], 0);
        let rows = report["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row["result"]["data"], expected);
        }
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] == "analysis_run")
                .count(),
            2
        );
        let selections: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .map(|r| r["args"]["program"].as_str().unwrap())
            .collect();
        assert_eq!(selections, ["A", "B"]);
    }
}
