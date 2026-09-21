use super::*;

fn execute_test_batch(
    content: &str,
    policy: BatchErrorPolicy,
    mut execute: impl FnMut(&str) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let lines: Vec<_> = command_lines(content)
        .map(|(number, text)| PreparedLine {
            number,
            text: text.to_owned(),
            cli: Cli::try_parse_from(["ghidra-cli", "program", "info"]).unwrap(),
            nested: None,
        })
        .collect();
    let batch = PreparedBatch {
        file: PathBuf::from("test.ghidra"),
        from_line: 1,
        commands_parsed: lines.len(),
        lines,
    };
    execute_batch(&batch, policy, |line| execute(&line.text))
}

#[test]
fn batch_arguments_preserve_quoted_and_escaped_values() {
    for (line, expected) in [
        ("  first\tsecond  ", vec!["first", "second"]),
        (
            r#"'' "" before"two words"after"#,
            vec!["", "", "beforetwo wordsafter"],
        ),
        (r#"'literal \ " $value'"#, vec![r#"literal \ " $value"#]),
        (
            r#"escaped\ space \'quote\' back\\slash"#,
            vec!["escaped space", "'quote'", r"back\slash"],
        ),
        (
            r#""say \"yes\" \$value \`name\` C:\temp \\""#,
            vec![r#"say "yes" $value `name` C:\temp \"#],
        ),
        (r#""日本語 のコメント""#, vec!["日本語 のコメント"]),
        (
            "$value $(command) `command` *.bin ; | >",
            vec!["$value", "$(command)", "`command`", "*.bin", ";", "|", ">"],
        ),
    ] {
        assert_eq!(split_arguments(line).unwrap(), expected, "{line}");
    }
}

#[test]
fn prepared_batches_execute_the_validated_content_after_files_change() {
    let directory = tempfile::tempdir().unwrap();
    let outer = directory.path().join("outer.txt");
    let child = directory.path().join("child.txt");
    let child_argument = serde_json::to_string(&child).unwrap();
    std::fs::write(&outer, format!("batch {child_argument}\nprogram stats\n")).unwrap();
    std::fs::write(&child, "program info\n").unwrap();
    let prepared = prepare(&outer, None, |_| Ok(())).unwrap();

    // Replacing either source after preflight must not change what executes.
    std::fs::write(&outer, "comment set 0x1000 changed\n").unwrap();
    std::fs::remove_file(&child).unwrap();
    let mut executed = Vec::new();
    let report = execute_batch(&prepared, BatchErrorPolicy::Continue, |line| {
        if let Some(nested) = &line.nested {
            execute_batch(nested, BatchErrorPolicy::Continue, |line| {
                executed.push(line.text.clone());
                assert!(matches!(
                    line.cli.command,
                    Commands::Program(crate::cli::ProgramCommands::Info(_))
                ));
                Ok(json!({"name": "original"}))
            })
        } else {
            executed.push(line.text.clone());
            assert!(matches!(
                line.cli.command,
                Commands::Program(crate::cli::ProgramCommands::Stats(_))
            ));
            Ok(json!({"functions": 1}))
        }
    })
    .unwrap();
    assert_eq!(executed, ["program info", "program stats"]);
    assert_eq!(report["results"][0]["result"]["commands_executed"], 1);
    assert_eq!(report["results"][1]["result"]["functions"], 1);
}

#[test]
fn batch_keeps_successes_and_error_detail_and_returns_failure() {
    for (policy, executed) in [(BatchErrorPolicy::Continue, 3), (BatchErrorPolicy::Stop, 2)] {
        let mut calls = Vec::new();
        let error = execute_test_batch("# commands\nfirst\n\nconflict\nlast", policy, |command| {
            calls.push(command.to_owned());
            if command == "conflict" {
                Err(BridgeCommandError {
                    message: "Already exists".to_owned(),
                    detail: serde_json::json!({"address": "0x1000", "partial_changes_saved": true}),
                }
                .into())
            } else {
                Ok(serde_json::json!({"executed": command}))
            }
        })
        .unwrap_err();
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(calls.len(), executed);
        assert_eq!(detail["commands_parsed"], 3);
        assert_eq!(detail["commands_executed"], executed);
        assert_eq!(detail["failed"], 1);
        assert_eq!(detail["not_executed"], 3 - executed);
        assert_eq!(detail["results"][0]["result"]["executed"], "first");
        assert_eq!(detail["results"][1]["line"], 4);
        assert_eq!(detail["results"][1]["detail"]["address"], "0x1000");
        assert_eq!(
            detail["results"][1]["detail"]["partial_changes_saved"],
            true
        );
        if policy == BatchErrorPolicy::Continue {
            assert_eq!(detail["results"][2]["result"]["executed"], "last");
        }
    }
}

#[test]
fn batch_stops_on_transaction_or_save_failure_including_at_end_of_nested_batch() {
    for flag in ["save_failed", "transaction_failed"] {
        for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
            let mut calls = 0;
            let error = execute_test_batch("nested\nmust-not-run", policy, |_| {
                calls += 1;
                execute_test_batch("edit", policy, |_| {
                    Err(BridgeCommandError {
                        message: "Request finalization failed".to_owned(),
                        detail: serde_json::json!({
                            flag: true,
                            "command_response": {"status": "success", "data": {"created": true}},
                        }),
                    }
                    .into())
                })
            })
            .unwrap_err();
            let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
            assert_eq!(calls, 1);
            assert_eq!(detail["not_executed"], 1);
            assert_eq!(detail[flag], true);
            assert_eq!(detail["results"][0]["detail"][flag], true);
            assert_eq!(
                detail["results"][0]["detail"]["results"][0]["detail"]["command_response"]["data"]
                    ["created"],
                true
            );
        }
    }
}

#[test]
fn batch_can_continue_after_completed_request_rollback() {
    let mut calls = 0;
    let error = execute_test_batch("failed-edit\nnext-edit", BatchErrorPolicy::Continue, |_| {
        calls += 1;
        if calls == 1 {
            Err(BridgeCommandError {
                message: "Edit failed".to_owned(),
                detail: serde_json::json!({"rolled_back": true}),
            }
            .into())
        } else {
            Ok(serde_json::json!({"created": true}))
        }
    })
    .unwrap_err();
    let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
    assert_eq!(calls, 2);
    assert_eq!(detail["not_executed"], 0);
    assert_eq!(detail["results"][0]["detail"]["rolled_back"], true);
    assert_eq!(detail["results"][1]["result"]["created"], true);
    assert!(detail.get("save_failed").is_none());
    assert!(detail.get("transaction_failed").is_none());
}

#[test]
fn batch_timeout_retains_exit_classification_and_stops() {
    for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
        let mut calls = 0;
        let error = execute_test_batch("nested\nmust-not-run", policy, |_| {
            calls += 1;
            execute_test_batch("slow\nmust-not-run", policy, |command| {
                assert_eq!(command, "slow");
                Err(BridgeTimeoutError {
                    command: "slow".to_owned(),
                    timeout_secs: 1,
                }
                .into())
            })
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(error.downcast_ref::<BridgeTimeoutError>().is_some());
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(detail["results"][0]["exit_code"], 75);
        assert_eq!(
            detail["results"][0]["detail"]["results"][0]["exit_code"],
            75
        );
        assert_eq!(detail["results"][0]["detail"]["not_executed"], 1);
        assert_eq!(detail["not_executed"], 1);
    }
}

#[test]
fn successful_batch_returns_all_results() {
    for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
        let result = execute_test_batch("first\nsecond", policy, |command| {
            Ok(serde_json::json!(command))
        })
        .unwrap();
        assert_eq!(result["failed"], 0);
        assert_eq!(result["commands_executed"], 2);
        assert_eq!(result["results"][1]["result"], "second");
    }
}
