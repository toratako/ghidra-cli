//! Native CALL evidence, conservative entry boundaries, query scope and unchanged databases.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};

#[macro_use]
mod common;

fn fixture(language: &str, check: impl FnOnce(&common::DaemonTestHarness, &str)) {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-function-candidates-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("candidates.bin");
    std::fs::write(&binary, [0xcc_u8; 4]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_installation()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some(language.to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import isolated raw function-candidate fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("fixtures/function_candidates/CreateFunctionCandidates.java"),
            &[],
            &[],
            false,
        )
        .expect("create and validate native candidate listing/reference facts");
    check(&harness, &program);
}

fn search(client: &BridgeClient, mut args: Value) -> Value {
    if args.get("limit").is_none() {
        args["limit"] = json!(0);
    }
    client
        .send_command("find_function_candidates", Some(args))
        .expect("find native function candidates")
}

fn address(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

fn row_at(result: &Value, target: u64) -> &Value {
    result["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            let target_address = row["address"].as_str().unwrap();
            target_address.starts_with("0x") && address(&row["address"]) == target
        })
        .unwrap_or_else(|| panic!("Missing candidate {target:#x}: {result}"))
}

fn check_x86(language: &str, thorough: bool) {
    fixture(language, |harness, program| {
        let client = harness.client().unwrap();
        let all = search(&client, json!({}));
        let rows = all["results"].as_array().unwrap();
        let normal_addresses: Vec<_> = rows
            .iter()
            .filter(|row| row["address"].as_str().unwrap().starts_with("0x"))
            .map(|row| address(&row["address"]))
            .collect();
        assert_eq!(
            normal_addresses,
            [
                0x3000, 0x3020, 0x3040, 0x3048, 0x3060, 0x3080, 0x30a0, 0x30c0, 0x3180, 0x3360,
                0x33c0, 0x4000
            ],
            "Each deliberately invalid target must be absent: {all}"
        );
        assert_eq!(rows.len(), 13, "{all}");
        assert_eq!(all["count"], rows.len());
        assert_eq!(all["scope"], "candidate-starts");
        assert_eq!(all["scan"], json!({"complete":true}));
        assert_eq!(search(&client, json!({})), all, "Stable evidence order");

        let single = row_at(&all, 0x3000);
        assert_eq!(single["name"], "single_candidate");
        assert_eq!(single["block"], "candidates");
        assert_eq!(single["call_count"], 1);
        assert!(!single["instruction"].as_str().unwrap().is_empty());
        let evidence = &single["evidence"][0];
        assert_eq!(address(&evidence["from"]), 0x1100);
        assert_eq!(evidence["caller"], "single_caller");
        assert_eq!(address(&evidence["caller_address"]), 0x1100);
        assert_eq!(evidence["type"], "UNCONDITIONAL_CALL");
        assert_eq!(evidence["operand"], 0);
        assert!(evidence["source"].is_string());
        assert_eq!(single["evidence_omitted"], 0);

        let popular = row_at(&all, 0x3020);
        assert_eq!(
            popular["call_count"], 7,
            "Duplicate operand refs count once"
        );
        assert_eq!(popular["evidence"].as_array().unwrap().len(), 5);
        assert_eq!(popular["evidence_omitted"], 2);
        let sites: Vec<_> = popular["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|evidence| address(&evidence["from"]))
            .collect();
        assert_eq!(sites, [0x1120, 0x1130, 0x1140, 0x1150, 0x1160]);
        for evidence in popular["evidence"].as_array().unwrap() {
            assert!(evidence["caller"].is_null());
            assert!(evidence["caller_address"].is_null());
        }
        for target in [0x3040, 0x3048] {
            let computed = row_at(&all, target);
            assert_eq!(computed["call_count"], 1);
            assert_eq!(computed["evidence"][0]["type"], "COMPUTED_CALL");
            assert_eq!(computed["evidence"][0]["source"], "USER_DEFINED");
        }
        assert_eq!(
            row_at(&all, 0x3060)["evidence"][0]["type"],
            "CONDITIONAL_CALL"
        );
        assert_eq!(
            row_at(&all, 0x3360)["evidence"][0]["type"],
            "CALL_OVERRIDE_UNCONDITIONAL"
        );
        assert_eq!(row_at(&all, 0x4000)["block"], ".plt");
        assert_eq!(
            row_at(&all, 0x33c0)["evidence"][0]["type"],
            "CALLOTHER_OVERRIDE_CALL"
        );

        // Bounds select destinations, and callers outside those bounds remain evidence.
        let exact = search(
            &client,
            json!({"start":"single_candidate","end":"single_candidate"}),
        );
        assert_eq!(exact["results"], json!([single]));
        assert_eq!(address(&exact["ranges"][0]["start"]), 0x3000);
        assert_eq!(address(&exact["ranges"][0]["end"]), 0x3000);
        let exact_limited = search(
            &client,
            json!({"start":"single_candidate","end":"single_candidate","limit":1}),
        );
        assert_eq!(
            exact_limited, exact,
            "A fully exhausted singleton scope is complete despite limit=1"
        );
        let overlay = search(
            &client,
            json!({"start":"candidate_overlay:0x3000", "end":"candidate_overlay:0x3000"}),
        );
        assert_eq!(
            overlay["count"], 1,
            "Same offsets in distinct spaces: {overlay}"
        );
        assert!(overlay["results"][0]["address"]
            .as_str()
            .unwrap()
            .starts_with("candidate_overlay:0x"));
        assert_eq!(overlay["results"][0]["block"], "candidate_overlay");
        assert_eq!(
            overlay["results"][0]["call_count"], 2,
            "Native overlay direct CALL is retained"
        );
        assert_eq!(
            address(&overlay["results"][0]["evidence"][0]["from"]),
            0x1380
        );
        assert!(rows.contains(&overlay["results"][0]));
        let empty = search(&client, json!({"start":"0x3100", "end":"0x3170"}));
        assert_eq!(empty["results"], json!([]));
        assert_eq!(empty["scan"], json!({"complete":true}));

        for invalid in [
            json!({"start":"0x3060","end":"0x3000"}),
            json!({"start":"0x3000","end":"candidate_overlay:0x3000"}),
            json!({"start":"missing_candidate_symbol"}),
        ] {
            client
                .send_command("find_function_candidates", Some(invalid.clone()))
                .expect_err(&format!("Invalid search range accepted: {invalid}"));
        }
        if thorough {
            check_cli(harness, &all);
            client.script_run_source(
                include_str!("fixtures/function_candidates/CheckFunctionCandidatesReadOnly.java"),
                &[], &[], false,
            ).expect("read-only saved database, deterministic cancellation and fresh-monitor recovery");
        }
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(
            search(&client, json!({})),
            all,
            "Saved fixture remains unchanged"
        );

        let created = common::ghidra(harness)
            .args(["--json", "function", "create", "single_candidate"])
            .run();
        created.assert_success();
        let after = search(&client, json!({}));
        let expected: Vec<_> = rows.iter().filter(|row| *row != single).cloned().collect();
        assert_eq!(
            after["results"],
            json!(expected),
            "Creating one candidate only removes that candidate"
        );
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(
            search(&client, json!({})),
            after,
            "Created function ownership persists"
        );
    });
}

fn check_cli(harness: &common::DaemonTestHarness, all: &Value) {
    let output = common::ghidra(harness)
        .args([
            "find",
            "function-candidates",
            "--start",
            "0x3000",
            "--end",
            "0x4000",
            "--filter",
            "call_count>1",
            "--sort=-call_count,address",
            "--limit",
            "1",
        ])
        .json_format()
        .run();
    output.assert_success();
    let envelope: Value = output.json();
    assert_eq!(envelope["data"], json!([row_at(all, 0x3020)]));
    assert_eq!(envelope["meta"]["scope"], "candidate-starts");
    assert_eq!(
        envelope["meta"]["scan"]["complete"], true,
        "Sorted/filtered query must finish the scan before selecting a page: {envelope}"
    );

    let projected = common::ghidra(harness)
        .args([
            "find",
            "function-candidates",
            "--start",
            "0x3000",
            "--end",
            "0x4000",
            "--sort=-call_count,address",
            "--skip",
            "1",
            "--limit",
            "1",
            "--fields",
            "address,name",
        ])
        .json_format()
        .run();
    projected.assert_success();
    assert_eq!(
        projected.data::<Value>(),
        json!([{
            "address":row_at(all, 0x3000)["address"], "name":"single_candidate"
        }])
    );

    let capped = common::ghidra(harness)
        .args(["find", "function-candidates", "--limit", "1"])
        .json_format()
        .run();
    capped.assert_success();
    let capped: Value = capped.json();
    assert_eq!(capped["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        capped["meta"]["scan"],
        json!({"complete":false,"stop_reason":"limit"})
    );
}

#[test]
fn candidates_x86_32_accept_supported_calls_and_reject_false_entries() {
    check_x86("x86:LE:32:default", false);
}

#[test]
fn candidates_x86_64_queries_cancellation_read_only_and_function_creation() {
    check_x86("x86:LE:64:default", true);
}

#[test]
fn candidates_thumb_respect_instruction_boundaries_and_context() {
    fixture("ARM:LE:32:v8", |harness, program| {
        let client = harness.client().unwrap();
        let found = search(&client, json!({}));
        assert_eq!(found["count"], 1, "{found}");
        let row = row_at(&found, 0x3000);
        assert_eq!(row["name"], "thumb_candidate");
        assert_eq!(row["call_count"], 1);
        assert_eq!(row["evidence"][0]["type"], "COMPUTED_CALL");
        assert_eq!(found["scan"], json!({"complete":true}));
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(search(&client, json!({})), found);
    });
}

#[test]
fn candidates_mips_exclude_delay_slots_and_post_delay_fallthrough() {
    fixture("MIPS:BE:32:default", |harness, program| {
        let client = harness.client().unwrap();
        let found = search(&client, json!({}));
        assert_eq!(found["count"], 1, "{found}");
        let row = row_at(&found, 0x3000);
        assert_eq!(row["name"], "mips_candidate");
        assert_eq!(row["call_count"], 1);
        assert_eq!(row["evidence"][0]["type"], "UNCONDITIONAL_CALL");
        assert_eq!(found["scan"], json!({"complete":true}));
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(search(&client, json!({})), found);
    });
}
