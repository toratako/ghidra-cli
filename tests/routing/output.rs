use super::RecordedBridge;
use serde_json::{json, Value};

fn document(bridge: &RecordedBridge, args: &[&str]) -> Value {
    let output = bridge.command().args(args).output().unwrap();
    assert!(output.status.success(), "{args:?}: {output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn human_file_mappings_show_excluded_ranges_even_without_direct_rows() {
    let bridge = RecordedBridge::new();
    for format in ["compact", "full"] {
        for offset in ["512", "999"] {
            for flags in [vec![], vec!["--quiet", "--fields", "address"]] {
                let output = bridge
                    .command()
                    .args([
                        "memory",
                        "file-mappings",
                        "--file-offset",
                        offset,
                        "--format",
                        format,
                    ])
                    .args(&flags)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{output:?}");
                assert!(output.stderr.is_empty(), "{output:?}");
                let text = String::from_utf8(output.stdout).unwrap();
                let (direct, excluded) = text
                    .split_once("Unsupported file mappings (excluded):\n")
                    .unwrap_or_else(|| panic!("missing exclusions: {text}"));
                for value in [
                    "ram:0x3000",
                    "ram:0x30ff",
                    "Indirect bit/byte memory mapping",
                ] {
                    assert!(excluded.contains(value), "{text}");
                }
                if offset == "999" {
                    assert!(direct.contains("No direct file mappings"), "{text}");
                } else {
                    assert!(direct.contains("ram:0x1000"), "{text}");
                    assert_eq!(direct.contains("file_offset"), flags.is_empty(), "{text}");
                }
                assert!(!text.contains("returned"), "{text}");
            }
        }
    }
}

#[test]
fn file_mapping_exclusions_preserve_count_and_ndjson_contracts() {
    let bridge = RecordedBridge::new();
    for (offset, count) in [("512", "3\n"), ("999", "0\n")] {
        for format in ["compact", "full", "ndjson"] {
            let output = bridge
                .command()
                .args([
                    "memory",
                    "file-mappings",
                    "--file-offset",
                    offset,
                    "--count",
                    "--format",
                    format,
                ])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(String::from_utf8(output.stdout).unwrap(), count);
        }
        let output = bridge
            .command()
            .args([
                "memory",
                "file-mappings",
                "--file-offset",
                offset,
                "--fields",
                "address",
                "--format",
                "ndjson",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            if offset == "512" {
                "{\"address\":\"ram:0x1000\"}\n"
            } else {
                ""
            },
        );
    }
}

#[test]
fn compact_fallback_displays_receipt_fields_once() {
    let bridge = RecordedBridge::new();
    for fields in [vec![], vec!["--fields", "changed"]] {
        let output = bridge
            .command()
            .args([
                "memory",
                "block",
                "rename",
                "bank1:0x1000",
                ".renamed",
                "--format",
                "compact",
            ])
            .args(&fields)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(text.matches("changed=true").count(), 1, "{text}");
        if fields.is_empty() {
            assert_eq!(text.matches("before=").count(), 1, "{text}");
            assert_eq!(text.matches("after=").count(), 1, "{text}");
            assert_eq!(text.matches("observed_program=A").count(), 1, "{text}");
        } else {
            assert_eq!(text, "changed=true\n");
        }
    }
}

#[test]
fn json_results_match_batch_entries_and_retain_context_after_queries() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["tag", "get", "review"],
        vec!["tag", "get", "review", "--fields", "name"],
        vec!["memory", "read", "0x1000", "8"],
        vec!["decompile", "warned", "--fields", "code,warnings"],
        vec!["function", "list"],
        vec![
            "function", "list", "--filter", "name~l", "--offset", "1", "--limit", "1", "--fields",
            "name",
        ],
        vec!["function", "list", "--count"],
        vec![
            "function", "list", "--offset", "1", "--limit", "2", "--count",
        ],
        vec![
            "graph",
            "calls",
            "--filter",
            "name=alpha",
            "--fields",
            "name",
        ],
        vec!["graph", "calls", "--filter", "name=absent"],
        vec!["graph", "callees", "entry", "--fields", "callee"],
        vec!["string", "refs", "absent"],
        vec![
            "comment", "get", "0x1000", "--limit", "0", "--fields", "text",
        ],
        vec!["comment", "get", "0x1000", "--count"],
        vec!["symbol", "delete", "shared", "--filter", "kind=label"],
    ] {
        let standalone = document(&bridge, &args);
        assert!(standalone.get("data").is_some(), "{standalone}");
        std::fs::write(
            bridge.root.path().join("contract.txt"),
            super::batch_arguments(&args),
        )
        .unwrap();
        let report = document(&bridge, &["batch", "contract.txt"]);
        assert_eq!(
            report["data"]["results"][0]["result"], standalone,
            "{args:?}"
        );
        assert!(report.get("meta").is_none());
    }
    let page = document(
        &bridge,
        &[
            "function", "list", "--offset", "2", "--limit", "1", "--fields", "name",
        ],
    );
    assert_eq!(
        page,
        json!({"data": [{"name": "large"}], "meta": {"returned": 1, "offset": 2, "limit": 1}})
    );
    let comments = document(&bridge, &["comment", "get", "0x1000", "--count"]);
    assert_eq!(
        comments,
        json!({"data": 2, "meta": {"address": "0x1000", "offset": 0, "limit": null}})
    );
    assert_eq!(
        document(&bridge, &["string", "refs", "absent"]),
        json!({"data": [], "meta": {"pattern": "absent", "returned": 0, "offset": 0, "limit": 1}})
    );
    let tag = document(&bridge, &["tag", "get", "review", "--fields", "name"]);
    assert_eq!(tag, json!({"data": {"name": "review"}}));
}

#[test]
fn ndjson_preserves_values_and_escaping_without_result_metadata() {
    let bridge = RecordedBridge::new();
    for (args, expected) in [
        (
            vec![
                "comment", "get", "0x1000", "--limit", "0", "--fields", "text",
            ],
            vec![json!({"text": "first\nsecond"}), json!({"text": "review"})],
        ),
        (vec!["string", "refs", "absent"], vec![]),
        (vec!["comment", "get", "0x1000", "--count"], vec![json!(2)]),
        (
            vec!["tag", "get", "review", "--fields", "name"],
            vec![json!({"name": "review"})],
        ),
        (
            vec!["graph", "calls", "--filter", "name=absent"],
            vec![json!({"nodes": [], "edges": [], "node_count": 0, "edge_count": 0})],
        ),
    ] {
        let output = bridge
            .command()
            .args(args)
            .args(["--format", "ndjson"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines, expected);
    }
    std::fs::write(
        bridge.root.path().join("ndjson.txt"),
        "comment get 0x1000 --count\n",
    )
    .unwrap();
    let expected = document(&bridge, &["batch", "ndjson.txt"]);
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 1\ndefault_output_format: ndjson\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "ndjson.txt"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        expected["data"]
    );
}

#[test]
fn explicit_code_formats_override_json_without_changing_output_defaults() {
    let bridge = RecordedBridge::new();
    let command = vec!["decompile", "main"];
    let rows = bridge.run(&command);
    assert_eq!(rows["name"], "main", "non-TTY default stays JSON");
    for flag in ["--json", "--pretty"] {
        let output = bridge
            .command()
            .args(&command)
            .args([flag, "--format", "c"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "int main(void) {\n  return 0;\n}\n"
        );
    }
    for command in [
        vec!["disassemble", "0x1000"],
        vec!["disassemble", "0x1000", "--end", "0x1002"],
        vec!["function", "disassemble", "main"],
    ] {
        assert!(bridge.run(&command).is_array());
        let output = bridge
            .command()
            .args(&command)
            .args(["--pretty", "--format", "asm"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("0x1000  90           NOP\n"));
    }
}

#[test]
fn decompile_warnings_follow_output_formats_and_projection() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .args(["decompile", "warned"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let rows: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(rows["warnings"].as_array().unwrap().len(), 3);
    assert_eq!(rows["entry_memory"]["permissions"], "rx");
    let code = rows["code"].as_str().unwrap();
    for fields in [vec![], vec!["--fields", "code"]] {
        let output = bridge
            .command()
            .args(["decompile", "warned", "--format", "c"])
            .args(&fields)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(String::from_utf8_lossy(&output.stdout), code);
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "Warning: [decompiler] API-only diagnostic\n"
        );
    }
    for format in ["compact", "full"] {
        let output = bridge
            .command()
            .args(["decompile", "warned", "--format", format])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(code), "{text}");
        assert!(text.contains("Warnings:\n"), "{text}");
        assert!(text.contains("[decompiler] API-only diagnostic"), "{text}");
        assert!(
            text.contains("[c_comment at 0x1000] WARNING: in C"),
            "{text}"
        );
        assert!(
            text.contains("External: false\nEntry memory: code (rx)"),
            "{text}"
        );
    }
    for flags in [vec!["--fields", "warnings"], vec!["--quiet"]] {
        let output = bridge
            .command()
            .args(["decompile", "warned", "--format", "c"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flags:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{flags:?}: {output:?}");
    }
    std::fs::write(bridge.root.path().join("batch.txt"), "decompile warned\n").unwrap();
    let batch = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(
        batch["results"][0]["result"]["data"]["warnings"],
        rows["warnings"]
    );
}

#[test]
fn configured_format_applies_to_query_rows_and_explicit_flags_override_it() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 1\ndefault_output_format: csv\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["symbol", "externals"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "name\nfirst\n");
    for flags in [vec!["--json"], vec!["--pretty"], vec!["-o", "json-compact"]] {
        let output = bridge
            .command()
            .args(["symbol", "externals"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flags:?}: {output:?}");
        assert_eq!(
            crate::json_output::from_slice::<Value>(&output.stdout).unwrap(),
            json!([{"name": "first"}])
        );
    }
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_output_format: auto\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["symbol", "externals"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<Value>(&output.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn ndjson_contains_exactly_one_document_per_line() {
    let bridge = RecordedBridge::new();
    bridge
        .command()
        .args(["config", "set", "default_output_format", "ndjson"])
        .assert()
        .success();
    let config = bridge.run(&["config", "list", "--json"]);
    assert_eq!(config["default_output_format"], "ndjson");
    for flags in [vec![], vec!["--format", "ndjson"]] {
        let output = bridge
            .command()
            .args(["symbol", "externals", "--limit", "0"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flags:?}: {output:?}");
        let output = String::from_utf8(output.stdout).unwrap();
        let rows = output
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![json!({"name": "first"}), json!({"name": "second"})]
        );
    }
}
