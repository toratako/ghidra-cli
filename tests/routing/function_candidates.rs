use super::{batch_arguments, RecordedBridge};
use crate::responses::function_candidates::fixture;
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
fn queries_fetch_all_candidates_before_residual_selection_and_keep_scan_context() {
    let bridge = RecordedBridge::new();
    let fixture = fixture(&json!({}));
    let all = &fixture["results"];
    for (flags, expected, fetch_limit, offset, page_limit) in [
        (vec![], json!([all[0]]), json!(1), 0, json!(1)),
        (
            vec!["--limit", "0"],
            all.clone(),
            Value::Null,
            0,
            Value::Null,
        ),
        (
            vec!["--limit", "2"],
            json!([all[0], all[1]]),
            json!(2),
            0,
            json!(2),
        ),
        (
            vec!["--fields", "address,evidence"],
            json!([{"address": all[0]["address"], "evidence": all[0]["evidence"]}]),
            json!(1),
            0,
            json!(1),
        ),
        (
            vec!["--filter", "block!='.plt'"],
            json!([all[1]]),
            Value::Null,
            0,
            json!(1),
        ),
        (
            vec!["--sort=-call_count,address"],
            json!([all[3]]),
            Value::Null,
            0,
            json!(1),
        ),
        (
            vec!["--skip", "2"],
            json!([all[2]]),
            Value::Null,
            2,
            json!(1),
        ),
        (
            vec![
                "--filter",
                "call_count>=3",
                "--sort=-call_count,-address",
                "--skip",
                "1",
                "--limit",
                "1",
                "--fields",
                "address,evidence_omitted",
            ],
            json!([{"address": "bank1:0x3000", "evidence_omitted": 0}]),
            Value::Null,
            1,
            json!(1),
        ),
        (vec!["--count"], json!(4), Value::Null, 0, Value::Null),
        (
            vec![
                "--filter",
                "call_count>=3",
                "--skip",
                "1",
                "--limit",
                "1",
                "--count",
            ],
            json!(1),
            Value::Null,
            1,
            json!(1),
        ),
        (
            vec!["--filter", "call_count>8"],
            json!([]),
            Value::Null,
            0,
            json!(1),
        ),
        (
            vec!["--filter", "call_count>8", "--count"],
            json!(0),
            Value::Null,
            0,
            Value::Null,
        ),
    ] {
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args: Vec<_> = [
                "find",
                "function-candidates",
                "--start",
                "bank1:0x1000",
                "--end",
                "upper_bound",
                "--program",
                "B",
            ]
            .into_iter()
            .chain(flags.iter().copied())
            .collect();
            let result = run(&bridge, &args, batched);
            assert_eq!(result["data"], expected, "{args:?}, batch={batched}");
            for key in ["scope", "ranges"] {
                assert_eq!(result["meta"][key], fixture[key], "{key}: {result}");
            }
            assert_eq!(result["meta"]["offset"], offset);
            assert_eq!(result["meta"]["limit"], page_limit);
            assert_eq!(
                result["meta"]["scan"],
                if fetch_limit.is_null() {
                    json!({"complete": true})
                } else {
                    json!({"complete": false, "stop_reason": "limit"})
                }
            );
            if let Some(rows) = expected.as_array() {
                assert_eq!(result["meta"]["returned"], rows.len());
            } else {
                assert!(result["meta"].get("returned").is_none());
            }
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|request| request["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{requests:?}");
            assert_eq!(domain[0]["command"], "find_function_candidates");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(
                domain[0]["args"],
                json!({"start": "bank1:0x1000", "end": "upper_bound", "limit": fetch_limit})
            );
        }
    }
}

#[test]
fn candidate_search_uses_explicit_project_and_preserves_optional_bounds() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (bounds, start, end) in [
        (vec![], Value::Null, Value::Null),
        (
            vec!["--start", "lower_bound"],
            json!("lower_bound"),
            Value::Null,
        ),
        (
            vec!["--end", "bank1:0x7000"],
            Value::Null,
            json!("bank1:0x7000"),
        ),
    ] {
        for batched in [false, true] {
            outer.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let args: Vec<_> = [
                "find",
                "function-candidates",
                "--project",
                selected.project.to_str().unwrap(),
                "--program",
                "B",
                "--limit",
                "0",
            ]
            .into_iter()
            .chain(bounds.iter().copied())
            .collect();
            let result = run(&outer, &args, batched);
            assert_eq!(result["data"].as_array().unwrap().len(), 4);
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
            assert_eq!(domain.len(), 1, "{requests:?}");
            assert_eq!(domain[0]["command"], "find_function_candidates");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(
                domain[0]["args"],
                json!({"start": start, "end": end, "limit": null})
            );
        }
    }
}

#[test]
fn malformed_candidate_filter_fails_before_standalone_or_batch_bridge_work() {
    let bridge = RecordedBridge::new();
    let args = ["find", "function-candidates", "--filter", "call_count>="];
    for batched in [false, true] {
        let output = if batched {
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                format!("program info\n{}", batch_arguments(&args)),
            )
            .unwrap();
            bridge
                .command()
                .args(["batch", "batch.txt"])
                .output()
                .unwrap()
        } else {
            bridge.command().args(args).output().unwrap()
        };
        assert!(!output.status.success(), "batch={batched}: {output:?}");
        if batched {
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["data"]["validation_failed"], true);
            assert_eq!(result["data"]["commands_executed"], 0);
        }
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
