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
                "--skip",
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
    for (mode, mode_args, expected_args) in [
        ("full", vec![], json!({})),
        (
            "range",
            vec!["--start", "overlay:0x1000", "--end", "overlay:0x1fff"],
            json!({"start": "overlay:0x1000", "end": "overlay:0x1fff"}),
        ),
        ("pending", vec!["--pending"], json!({"pending": true})),
    ] {
        let mut expected = json!({
            "command": "analysis run", "status": "success",
            "data": {
                "status": "success", "program": "B", "function_count": 3,
                "mode": mode, "completed": true, "saved": true,
            },
        });
        if mode == "range" {
            expected["data"]["start"] = expected_args["start"].clone();
            expected["data"]["end"] = expected_args["end"].clone();
        }
        let args: Vec<_> = ["analysis", "run"].into_iter().chain(mode_args).collect();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            format!(
                "{} --program B\n{}\n",
                batch_arguments(&args),
                batch_arguments(&args)
            ),
        )
        .unwrap();
        for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge
                .command()
                .args(&args)
                .args(["--program", "B"])
                .args(&flags)
                .output()
                .unwrap();
            assert!(output.status.success(), "{mode}: {output:?}");
            assert!(output.stderr.is_empty(), "JSON modes suppress progress");
            assert_eq!(
                crate::json_output::from_slice::<Value>(&output.stdout).unwrap(),
                expected
            );
            let requests = bridge.requests.lock().unwrap().clone();
            assert_eq!(requests[requests.len() - 2]["command"], "open_program");
            assert_eq!(
                requests[requests.len() - 2]["args"],
                json!({"program": "B"})
            );
            assert_eq!(requests.last().unwrap()["command"], "analysis_run");
            assert_eq!(requests.last().unwrap()["args"], expected_args);

            bridge.requests.lock().unwrap().clear();
            let output = bridge
                .command()
                .args(["batch", "batch.txt", "--program", "A"])
                .args(&flags)
                .output()
                .unwrap();
            assert!(output.status.success(), "{mode}: {output:?}");
            assert!(output.stderr.is_empty(), "batch must suppress progress");
            let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
            assert_eq!(report["failed"], 0);
            let rows = report["results"].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            for row in rows {
                assert_eq!(row["result"]["data"], expected);
            }
            let requests = bridge.requests.lock().unwrap();
            let runs: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "analysis_run")
                .collect();
            assert_eq!(runs.len(), 2);
            for run in runs {
                assert_eq!(run["args"], expected_args);
            }
            let selections: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "open_program")
                .map(|r| r["args"]["program"].as_str().unwrap())
                .collect();
            assert_eq!(selections, ["A", "B"]);
        }
    }
}

#[test]
fn analysis_run_honors_project_overrides_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    let args = [
        "analysis",
        "run",
        "--pending",
        "--project",
        selected.project.to_str().unwrap(),
        "--program",
        "B",
    ];
    for batched in [false, true] {
        first.requests.lock().unwrap().clear();
        selected.requests.lock().unwrap().clear();
        if batched {
            std::fs::write(first.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
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
        let domain: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] != "bridge_info")
            .collect();
        assert_eq!(domain.len(), 2, "{domain:?}");
        assert_eq!(domain[0]["command"], "open_program");
        assert_eq!(domain[0]["args"], json!({"program": "B"}));
        assert_eq!(domain[1]["command"], "analysis_run");
        assert_eq!(domain[1]["args"], json!({"pending": true}));
    }
}

#[test]
fn incompatible_analysis_modes_do_not_reach_the_bridge() {
    let bridge = RecordedBridge::new();
    let args = [
        "analysis",
        "run",
        "--pending",
        "--start",
        "0x1000",
        "--end",
        "0x1fff",
    ];
    for batched in [false, true] {
        let output = if batched {
            std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
            bridge
                .command()
                .args(["batch", "batch.txt"])
                .output()
                .unwrap()
        } else {
            bridge.command().args(args).output().unwrap()
        };
        assert!(!output.status.success(), "{output:?}");
        assert!(bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r["command"] == "bridge_info"));
    }
}
