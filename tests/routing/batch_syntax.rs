use super::RecordedBridge;
use serde_json::{json, Value};

#[test]
fn batch_preserves_quoted_signatures_types_and_comments() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        r#"function set-signature parse_header --signature "int parse_header(char *buf, int len)"
function set-return-type parse_header --type 'unsigned long'
comment set 0x1000 --text 'Header length includes the prefix'
"#,
    )
    .unwrap();
    let result = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(result["commands_executed"], 3);
    let requests = bridge.requests.lock().unwrap();
    let edits: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .map(|r| (r["command"].clone(), r["args"].clone()))
        .collect();
    assert_eq!(
        edits,
        vec![
            (
                json!("function_set_signature"),
                json!({"target": "parse_header", "signature": "int parse_header(char *buf, int len)"}),
            ),
            (
                json!("function_set_return_type"),
                json!({"target": "parse_header", "return_type": "unsigned long", "timeout_secs": 0}),
            ),
            (
                json!("comment_set"),
                json!({"address": "0x1000", "text": "Header length includes the prefix", "comment_type": null}),
            ),
        ]
    );
}

#[test]
fn batch_unescapes_arguments_without_expanding_shell_syntax() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        concat!(
            r#"comment set 0x1000 --text "say \"hello\"; path C:\temp; slash \\; \$value"
comment set 0x1001 --text escaped\ spaces\ and\ \'quotes\'
comment set 0x1002 --text '$HOME $(echo expanded) `echo expanded` *.bin > out | cat # literal'
comment set 0x1003 --text ""
"#,
            "comment set 0x1004 --text trailing\\ \n",
        ),
    )
    .unwrap();
    bridge.run(&["batch", "batch.txt"]);
    let requests = bridge.requests.lock().unwrap();
    let comments: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "comment_set")
        .map(|r| r["args"]["text"].as_str().unwrap())
        .collect();
    assert_eq!(
        comments,
        vec![
            r#"say "hello"; path C:\temp; slash \; $value"#,
            "escaped spaces and 'quotes'",
            "$HOME $(echo expanded) `echo expanded` *.bin > out | cat # literal",
            "",
            "trailing ",
        ]
    );
}

#[test]
fn batch_reports_all_malformed_quoting_before_executing_any_lines() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "# commands\ncomment set 0x1000 --text 'unfinished\ncomment set 0x1001 --text \"unfinished\ncomment set 0x1002 --text trailing\\\ncomment set 0x1003 --text 'valid after errors'\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["detail"].get("results").is_none());
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    let detail = &report;
    assert_eq!(detail["commands_parsed"], 4);
    assert_eq!(detail["commands_executed"], 0);
    assert_eq!(detail["failed"], 3);
    assert_eq!(detail["not_executed"], 4);
    assert_eq!(detail["validation_failed"], true);
    assert_eq!(detail["results"], json!([]));
    for (index, diagnostic) in [
        "unterminated single quote",
        "unterminated double quote",
        "trailing escape",
    ]
    .iter()
    .enumerate()
    {
        let row = &detail["validation_errors"][index];
        assert_eq!(row["file"], "batch.txt");
        assert_eq!(row["line"], index + 2);
        assert!(row["error"].as_str().unwrap().contains(diagnostic), "{row}");
    }
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_rejects_invalid_regex_before_a_preceding_edit() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "comment set 0x1000 --text before\nfunction list --filter 'name=~\"[\"'\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["commands_executed"], 0);
    assert_eq!(report["validation_errors"][0]["line"], 2);
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_checks_configured_limit_before_a_preceding_edit() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 2147483648\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "comment set 0x1000 --text before\ngraph calls\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["commands_executed"], 0);
    assert_eq!(report["validation_errors"][0]["line"], 2);
    assert!(report["validation_errors"][0]["error"]
        .as_str()
        .unwrap()
        .contains("--limit must be between 0 and 2147483647"));
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_preflight_collects_nested_syntax_queries_read_errors_and_cycles() {
    for policy in ["continue", "stop"] {
        let bridge = RecordedBridge::new();
        std::fs::create_dir(bridge.root.path().join("scripts")).unwrap();
        std::fs::write(
            bridge.root.path().join("scripts/batch.txt"),
            "comment set 0x1000 --text before\nbatch nested.txt\nbatch missing.txt\nfunction delete\n",
        )
        .unwrap();
        // Nested files use the invocation's cwd, including names containing an apostrophe.
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            "function list --filter invalid\nsymbol delete existing --where invalid\nsymbol rename existing renamed --where invalid\nsymbol delete existing --address invalid\ngraph callers main --depth 2147483648\nlisting undefine 0x1000 --end invalid\nbatch \"scripts/./batch.txt\"\nbatch \"nested valid's.txt\"\nprogram import generated.bin --loader-option malformed\nprogram import generated.bin --base-address invalid\nscript run generated.java --expect-rows results.jsonl 9223372036854775808\n",
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("nested valid's.txt"),
            "comment set 0x1001 --text child\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .args([
                "batch",
                "scripts/batch.txt",
                "--program",
                "must-not-open",
                "--on-error",
                policy,
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        let report = &report;
        assert_eq!(report["commands_parsed"], 4);
        assert_eq!(report["commands_executed"], 0);
        assert_eq!(report["not_executed"], 4);
        assert_eq!(report["results"], json!([]));
        let errors = report["validation_errors"].as_array().unwrap();
        assert_eq!(errors.len(), 12, "{errors:?}");
        for (error, (file, line, message)) in errors.iter().zip([
            ("nested.txt", 1, "invalid --filter expression"),
            ("nested.txt", 2, "invalid --where expression"),
            ("nested.txt", 3, "invalid --where expression"),
            ("nested.txt", 4, "Invalid --address"),
            ("nested.txt", 5, "--depth must be between"),
            ("nested.txt", 6, "Invalid --end address"),
            ("nested.txt", 7, "Batch include cycle"),
            ("nested.txt", 9, "--loader-option"),
            ("nested.txt", 10, "Invalid base address"),
            ("nested.txt", 11, "Invalid --expect-rows MIN_ROWS"),
            (
                "scripts/batch.txt",
                3,
                "Failed to read batch file missing.txt",
            ),
            ("scripts/batch.txt", 4, "required arguments"),
        ]) {
            assert_eq!(error["file"], file);
            assert_eq!(error["line"], line);
            assert!(
                error["error"].as_str().unwrap().contains(message),
                "{error}"
            );
        }
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn batch_can_reuse_a_nested_file_after_its_previous_invocation_finishes() {
    let bridge = RecordedBridge::new();
    std::fs::create_dir(bridge.root.path().join("scripts")).unwrap();
    std::fs::write(
        bridge.root.path().join("scripts/batch.txt"),
        "batch \"nested valid's.txt\"\nbatch \"./nested valid's.txt\"\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("nested valid's.txt"),
        "comment set 0x1000 --text nested\n",
    )
    .unwrap();
    let report = bridge.run(&["batch", "scripts/batch.txt"]);
    assert_eq!(report["commands_executed"], 2);
    assert_eq!(report["failed"], 0);
    assert_eq!(
        bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["command"] == "comment_set")
            .count(),
        2
    );
}
