use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn test_int_query_limits_reject_overflow_without_truncating_results() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("int-query-limits-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/scripts/CreateQueryFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        client
            .script_run_source(
                include_str!("../fixtures/readonly/CompleteIntQueryLimitFixture.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        for (wire, args, key) in [
            ("symbol_externals", json!({}), "externals"),
            ("symbol_entry_points", json!({}), "entry_points"),
            ("tag_list", json!({}), "tags"),
            ("graph_calls", json!({}), "nodes"),
            ("find_instruction", json!({"pattern":"RET"}), "results"),
        ] {
            let baseline = client.send_command(wire, Some(args.clone())).unwrap();
            let rows = baseline[key].as_array().unwrap();
            assert!(rows.len() >= 2, "{wire}: {baseline}");
            for limit in [Value::Null, json!(0), json!(i32::MAX)] {
                let mut bounded = args.clone();
                bounded["limit"] = limit;
                assert_eq!(
                    client.send_command(wire, Some(bounded.clone())).unwrap(),
                    baseline,
                    "{wire}: {bounded}"
                );
            }
            let mut bounded = args.clone();
            bounded["limit"] = json!(1);
            assert_eq!(
                client.send_command(wire, Some(bounded)).unwrap()[key],
                json!(rows[..1]),
                "{wire}"
            );
            for limit in [
                json!(-1),
                json!(1.5),
                json!("1"),
                json!(2147483648u64),
                json!(4294967296u64),
                json!(4294967297u64),
                json!(u64::MAX),
            ] {
                let mut invalid = args.clone();
                invalid["limit"] = limit;
                let error = client
                    .send_command(wire, Some(invalid.clone()))
                    .expect_err(&format!("{wire} accepted {invalid}"));
                assert!(
                    error
                        .to_string()
                        .contains("limit must be an integer from 0 to 2147483647"),
                    "{wire}: {invalid}: {error}"
                );
            }
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn test_search_limits_and_client_defaults_on_complete_results() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("search-limits-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateSearchLimitFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config = ghidra_cli::config::Config::load().unwrap();
        config.default_limit = Some(2);
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let run = |args: &[&str]| -> Value {
            let output = ghidra(harness)
                .args(args.iter().copied())
                .with_project(test_project(), &name)
                .env(
                    "GHIDRA_CLI_CONFIG",
                    config_path.to_string_lossy().into_owned(),
                )
                .run();
            output.assert_success();
            output.data()
        };
        let bytes = "4341505f4e4545444c455f"; // CAP_NEEDLE_
        for command in [
            vec!["find", "bytes", bytes],
            vec!["find", "bytes", "--regex", "CAP_NEEDLE_[0-9]{3}"],
            vec!["find", "text", "CAP_NEEDLE_"],
            vec!["find", "string", "DEFINED_NEEDLE_"],
        ] {
            let with = |flags: &[&str]| {
                let mut args = command.clone();
                args.extend(flags);
                run(&args)
            };
            let all = with(&["--limit", "0"]);
            let rows = all.as_array().unwrap();
            assert_eq!(rows.len(), 160, "{command:?}: {all}");
            assert_eq!(with(&["--count"]), 160);
            assert_eq!(with(&["--limit", "120"]), json!(rows[..120]));
            assert_eq!(with(&[]), json!(rows[..2]));
            assert_eq!(with(&["--fields", "address"]).as_array().unwrap().len(), 2);
            assert_eq!(with(&["--skip", "100"]), json!(rows[100..102]));
            assert_eq!(with(&["--skip", "100", "--limit", "0"]), json!(rows[100..]));
            assert_eq!(with(&["--count", "--skip", "100", "--limit", "2"]), 2);
            let filter = format!("address='{}'", rows[159]["address"].as_str().unwrap());
            assert_eq!(with(&["--filter", &filter]), json!([rows[159]]));
            let mut descending = rows.clone();
            descending.reverse();
            assert_eq!(with(&["--sort=-address"]), json!(descending[..2]));
        }
        // Library calls stay unlimited unless their caller supplies a cap.
        for data in [
            client.find_string("DEFINED_NEEDLE_").unwrap(),
            client.find_text("CAP_NEEDLE_", "utf-8").unwrap(),
            client.find_bytes(bytes).unwrap(),
            client
                .find_bytes_regex_with_limit("CAP_NEEDLE_[0-9]{3}", None)
                .unwrap(),
        ] {
            assert_eq!(data["count"], 160);
            assert_eq!(data["results"].as_array().unwrap().len(), 160);
        }
        for data in [
            client
                .find_string_with_limit("DEFINED_NEEDLE_", Some(120))
                .unwrap(),
            client.find_bytes_with_limit(bytes, Some(120)).unwrap(),
            client
                .find_bytes_regex_with_limit("CAP_NEEDLE_[0-9]{3}", Some(120))
                .unwrap(),
            client
                .find_text_with_limit("CAP_NEEDLE_", "utf-8", Some(120))
                .unwrap(),
        ] {
            assert_eq!(data["count"], 120);
            assert_eq!(data["results"].as_array().unwrap().len(), 120);
        }
        for (wire, mut args) in [
            ("find_string", json!({"pattern":"DEFINED_NEEDLE_"})),
            ("find_text", json!({"text":"CAP_NEEDLE_"})),
            ("find_bytes", json!({"hex": bytes})),
            (
                "find_bytes_regex",
                json!({"pattern": "CAP_NEEDLE_[0-9]{3}"}),
            ),
        ] {
            for limit in [json!(0), json!(4294967296u64)] {
                args["limit"] = limit;
                assert_eq!(
                    client.send_command(wire, Some(args.clone())).unwrap()["count"],
                    160
                );
            }
            for limit in [json!(-1), json!(1.5), json!(u64::MAX)] {
                args["limit"] = limit;
                assert!(
                    client.send_command(wire, Some(args.clone())).is_err(),
                    "{wire}: {args}"
                );
            }
        }
        for (command, total) in [
            (
                vec!["function", "list", "--filter", "name~password_case_"],
                160,
            ),
            (vec!["string", "refs", "DEFINED_NEEDLE_000"], 160),
            (vec!["xref", "to", "0x8000"], 160),
            (vec!["memory", "block", "list"], 3),
        ] {
            assert_eq!(run(&command).as_array().unwrap().len(), 2, "{command:?}");
            let mut count = command.clone();
            count.push("--count");
            assert_eq!(run(&count), total);
            let mut unlimited = command.clone();
            unlimited.extend(["--limit", "0"]);
            let all = run(&unlimited);
            assert_eq!(all.as_array().unwrap().len(), total);
            let field = all[0].as_object().unwrap().keys().next().unwrap();
            let mut projected = command.clone();
            projected.extend(["--fields", field]);
            assert_eq!(run(&projected).as_array().unwrap().len(), 2);
        }
        let batch_path = temp.path().join("limits.txt");
        std::fs::write(&batch_path, "function list --filter name~password_case_\nfunction list --filter name~password_case_ --fields name\nfind bytes 4341505f4e4545444c455f --count\nfunction list --skip 100 --limit 0\n").unwrap();
        let batch = run(&["batch", batch_path.to_str().unwrap()]);
        let results = &batch["results"];
        assert_eq!(results[0]["result"]["data"].as_array().unwrap().len(), 2);
        assert_eq!(results[1]["result"]["data"].as_array().unwrap().len(), 2);
        assert_eq!(results[2]["result"]["data"], 160);
        assert_eq!(results[3]["result"]["data"].as_array().unwrap().len(), 60);

        // A dense uncapped search cannot finish before cancellation is observed.
        // Its next request must get a fresh, non-cancelled monitor.
        client
            .script_run_source(
                include_str!("../fixtures/readonly/AddDenseSearchBlock.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        for (wire, args) in [
            ("find_bytes", json!({"hex": "0000"})),
            ("find_bytes_regex", json!({"pattern": r"\x00\x00"})),
            ("find_text", json!({"text": "\0\0"})),
        ] {
            let worker = harness.client().unwrap();
            let search = std::thread::spawn(move || worker.send_command(wire, Some(args)));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut cancelled_id = None;
            while !search.is_finished() && std::time::Instant::now() < deadline {
                let status = client.status().unwrap();
                if status["active_job"]["command"] == wire {
                    let id = status["active_job"]["id"].as_str().unwrap().to_owned();
                    client.cancel_job(Some(&id)).unwrap();
                    cancelled_id = Some(id);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let result = search.join().unwrap();
            let id = cancelled_id.expect("uncapped search must remain active until cancellation");
            assert!(
                result.is_err(),
                "cancelled search returned a successful partial result"
            );
            assert_eq!(
                client.job_status(Some(&id)).unwrap()["job"]["state"],
                "cancelled"
            );
            assert_eq!(
                client.find_bytes_with_limit("0000", Some(2)).unwrap()["count"],
                2
            );
            assert_eq!(
                client
                    .find_bytes_regex_with_limit(r"\x00\x00", Some(2))
                    .unwrap()["count"],
                2
            );
            assert_eq!(
                client
                    .find_text_with_limit("\0\0", "utf-8", Some(2))
                    .unwrap()["count"],
                2
            );
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}
