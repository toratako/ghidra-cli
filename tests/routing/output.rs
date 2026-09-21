use super::RecordedBridge;
use serde_json::{json, Value};

#[test]
fn explicit_code_formats_override_json_without_changing_output_defaults() {
    let bridge = RecordedBridge::new();
    let command = vec!["decompile", "main"];
    let rows = bridge.run(&command);
    assert_eq!(rows[0]["name"], "main", "non-TTY default stays JSON");
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
fn decompile_warnings_follow_output_formats_and_selected_rows() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .args(["decompile", "warned"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let rows: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows[0]["warnings"].as_array().unwrap().len(), 3);
    assert_eq!(rows[0]["entry_memory"]["permissions"], "rx");
    let code = rows[0]["code"].as_str().unwrap();
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
    for flags in [
        vec!["--count"],
        vec!["--filter", "name=absent"],
        vec!["--fields", "warnings"],
        vec!["--quiet"],
    ] {
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
        batch[0]["results"][0]["result"]["warnings"],
        rows[0]["warnings"]
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
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
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
        serde_json::from_slice::<Value>(&output.stdout)
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
