use super::{ghidra, harness, test_project, DaemonTestHarness, TEST_PROGRAM};
use serial_test::serial;

/// Disassembly failures retain diagnostics, stop dependent edits, and roll back clearing.
#[test]
#[serial]
fn test_define_code_ranges_receipts_failures_and_persistence() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("disasm-failure-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/patch/CreateDisasmFailureFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        check_define_code_ranges(harness, &client, &name);
        let instruction = client.define_code("0x1000", None).unwrap();
        assert_eq!(instruction["landed"], true);
        assert_eq!(instruction["already_defined"], false);
        assert_eq!(instruction["changed"], true);
        assert_eq!(instruction["status"], "defined");
        assert!(instruction.get("instructions").is_none());
        let repeated = client.define_code("0x1000", None).unwrap();
        assert_eq!(repeated["already_defined"], true);
        assert_eq!(repeated["changed"], false);
        assert_eq!(repeated["status"], "unchanged");

        // An unmapped address is syntactically valid but cannot produce an instruction.
        let failed = ghidra(harness)
            .args(["--json", "listing", "define-code", "0x8000"])
            .run();
        assert_eq!(failed.exit_code, 1, "{failed:?}");
        assert!(failed.stdout.is_empty(), "{failed:?}");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        let detail = &error["detail"];
        let failed_address = detail["address"].as_str().unwrap();
        assert_eq!(
            u64::from_str_radix(failed_address.strip_prefix("0x").unwrap(), 16).unwrap(),
            0x8000
        );
        assert_eq!(detail["already_defined"], false);
        // Ghidra can report true even when no instruction lands at the target.
        assert!(detail["ok"].is_boolean());
        assert_eq!(detail["landed"], false);
        assert_eq!(detail["status"], "failed");
        assert_eq!(detail["rolled_back"], true);
        assert!(detail.get("partial_changes_saved").is_none());

        let batch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            batch.path(),
            "listing define-code 0x8000\ncomment set 0x1000 --text must-not-run\n",
        )
        .unwrap();
        let failed_batch = ghidra(harness)
            .args(["--json", "batch"])
            .arg(batch.path().to_str().unwrap())
            .args(["--on-error", "stop"])
            .run();
        assert_eq!(failed_batch.exit_code, 1, "{failed_batch:?}");
        let report: serde_json::Value = failed_batch.data();
        assert_eq!(report["commands_executed"], 1);
        assert_eq!(report["failed"], 1);
        assert_eq!(report["not_executed"], 1);
        assert_eq!(report["results"][0]["detail"]["landed"], false);
        assert!(client.comment_get("0x1000").unwrap()["comments"]
            .as_array()
            .unwrap()
            .is_empty());

        let cleared = ghidra(harness)
            .args([
                "--json",
                "listing",
                "undefine",
                "0x1000",
                "--end",
                "0x1000",
                "--disassemble-at",
                "0x8000",
            ])
            .run();
        assert_eq!(cleared.exit_code, 1, "{cleared:?}");
        assert!(cleared.stdout.is_empty(), "{cleared:?}");
        let clear_error: serde_json::Value = serde_json::from_str(&cleared.stderr).unwrap();
        let clear_detail = &clear_error["detail"];
        assert_eq!(clear_detail["start"], instruction["address"]);
        assert_eq!(clear_detail["end"], instruction["address"]);
        assert_eq!(clear_detail["disasm_at"], failed_address);
        assert!(clear_detail["ok"].is_boolean());
        assert_eq!(clear_detail["landed"], false);
        assert_eq!(clear_detail["status"], "failed");
        assert_eq!(clear_detail["rolled_back"], true);
        assert!(clear_detail.get("partial_changes_saved").is_none());
        assert!(clear_detail["hint"].is_string());

        // Both the current listing and the saved program keep the earlier instruction.
        let restored = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000"})),
            )
            .unwrap();
        assert_eq!(restored["count"], 1);
        assert_eq!(restored["instructions"][0]["bytes"], "c3");
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        let listing = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000"})),
            )
            .unwrap();
        assert_eq!(listing, restored);
        let recovered = client
            .send_command(
                "clear_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000","disasm_at":"0x1000"})),
            )
            .unwrap();
        assert_eq!(recovered["status"], "cleared_and_disassembled");
        assert_eq!(recovered["ok"], true);
        assert_eq!(recovered["landed"], true);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn check_define_code_ranges(
    harness: &DaemonTestHarness,
    client: &ghidra_cli::ipc::client::BridgeClient,
    program: &str,
) {
    use serde_json::{json, Value};
    for args in [
        json!({"target": "0x2000", "limit": 1}),
        json!({"target": "0x2000", "count": 1}),
        json!({"target": "0x2000", "end": "0x1fff"}),
        json!({"target": "0x2000", "end": "register:0x0"}),
        json!({"target": "0x2000", "end": "0xnot-hex"}),
        json!({"target": "0x2000", "end": "missing_end"}),
    ] {
        assert!(
            client
                .send_command("define_code", Some(args.clone()))
                .is_err(),
            "{args}"
        );
    }
    assert_eq!(
        client.disasm_range("0x2000", "0x2014", None).unwrap()["count"],
        0,
        "invalid arguments must fail before creating any instructions"
    );

    let result = ghidra(harness)
        .args([
            "--json",
            "listing",
            "define-code",
            "code_start",
            "--end",
            "code_end",
        ])
        .with_project(test_project(), program)
        .run();
    result.assert_success();
    let receipt = &result.data::<Value>();
    assert_eq!(receipt["already_defined"], false);
    assert_eq!(receipt["landed"], true);
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["end"], "0x0000200b");
    let all = client.disasm_range("0x2000", "0x2014", None).unwrap();
    assert_eq!(
        all["count"], 12,
        "end must bound instruction creation, not just output"
    );
    let repeated = client.define_code("0x2000", Some("0x200b")).unwrap();
    assert_eq!(repeated["changed"], false);
    assert_eq!(repeated["status"], "unchanged");

    ghidra(harness)
        .args(["listing", "undefine", "0x2000", "--end", "0x2014"])
        .with_project(test_project(), program)
        .run()
        .assert_success();
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    test_config.default_limit = Some(12);
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    let result = ghidra(harness)
        .args(["--json", "listing", "define-code", "0x2000"])
        .with_project(test_project(), program)
        .env("GHIDRA_CLI_CONFIG", config.to_string_lossy())
        .run();
    result.assert_success();
    assert_eq!(
        client.disasm_range("0x2000", "0x2014", None).unwrap()["count"],
        21
    );

    client.define_code("0x3000", Some("0x3015")).unwrap();
    let flow = client.disasm_range("0x3000", "0x3030", None).unwrap();
    let addresses: Vec<_> = flow["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            u64::from_str_radix(
                row["address"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        addresses,
        [0x3000, 0x3010, 0x3011],
        "follow branches, not every byte; terminate loops"
    );
    client.define_code("0x3020", Some("0x3024")).unwrap();
    assert_eq!(
        client.disasm_range("0x3030", "0x3030", None).unwrap()["count"],
        0
    );
    client.clear_range("0x3020", "0x3024", None).unwrap();
    client.define_code("0x3020", None).unwrap();
    assert_eq!(
        client.disasm_range("0x3030", "0x3030", None).unwrap()["count"],
        1
    );

    client.define_code("0x4002", None).unwrap();
    client
        .comment_set("0x4002", "preserve outside preview", None)
        .unwrap();
    let outside = client.comment_get("0x4002").unwrap();
    assert!(client.define_code("0x4000", Some("0x4000")).is_err());
    assert_eq!(
        client.disasm_range("0x4000", "0x4002", None).unwrap()["count"],
        1,
        "preview rollback must preserve existing adjacent instructions"
    );
    client.define_code("0x4000", Some("0x4001")).unwrap();
    assert_eq!(
        client.disasm_range("0x4000", "0x4002", None).unwrap()["count"],
        2
    );
    client.define_code("0x4100", Some("0x4103")).unwrap();
    assert_eq!(
        client.disasm_range("0x4100", "0x4106", None).unwrap()["count"],
        1
    );
    client.define_code("0x5000", Some("0x5010")).unwrap();
    assert_eq!(
        client.disasm_range("0x5000", "0x5010", None).unwrap()["count"],
        2
    );
    assert_eq!(
        client.disasm_range("0x5005", "0x500f", None).unwrap()["count"],
        0,
        "native no-return handling must suppress fallthrough"
    );
    // Code definitions are saved, while underlying bytes remain untouched.
    client.open_program(TEST_PROGRAM).unwrap();
    client.open_program(program).unwrap();
    assert_eq!(
        client.disasm_range("0x4100", "0x4106", None).unwrap()["count"],
        1
    );
    let bytes = client
        .send_command("read_memory", Some(json!({"address": "0x4000", "size": 3})))
        .unwrap();
    assert_eq!(bytes["hex"], "6690c3");
    assert_eq!(client.comment_get("0x4002").unwrap(), outside);
}

#[test]
#[serial]
fn define_code_preserves_thumb_it_context() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-code-thumb-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/patch/CreateBoundedThumbFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        client.define_code("0x1000", None).unwrap();
        let native = client.disasm_range("0x1000", "0x1005", None).unwrap();
        assert_eq!(native["count"], 3, "{native}");
        assert!(
            native["instructions"][1]["mnemonic"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("eq"),
            "{native}"
        );
        client.clear_range("0x1000", "0x1005", None).unwrap();
        client.define_code("0x1000", Some("0x1005")).unwrap();
        assert_eq!(
            client.disasm_range("0x1000", "0x1005", None).unwrap(),
            native
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn define_code_keeps_mips_delay_slot_groups_within_end() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-code-mips-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/patch/CreateBoundedMipsFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let references_before = client.xrefs_from("0x1000".into(), false).unwrap();
        for end in ["0x1003", "0x1005"] {
            assert!(client.define_code("0x1000", Some(end)).is_err());
            assert_eq!(
                client.disasm_range("0x1000", "0x1017", None).unwrap()["count"],
                0
            );
            assert_eq!(
                client.xrefs_from("0x1000".into(), false).unwrap(),
                references_before,
                "rejected previews must not leave branch references"
            );
        }
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(
            client.disasm_range("0x1000", "0x1017", None).unwrap()["count"],
            0
        );
        assert_eq!(
            client.xrefs_from("0x1000".into(), false).unwrap(),
            references_before
        );
        let receipt = client.define_code("0x1000", Some("0x1007")).unwrap();
        assert_eq!(receipt["changed"], true);
        let bounded = client.disasm_range("0x1000", "0x1017", None).unwrap();
        assert_eq!(
            bounded["count"], 2,
            "branch and complete delay slot only: {bounded}"
        );
        client.clear_range("0x1000", "0x1017", None).unwrap();
        client.define_code("0x1000", Some("0x1017")).unwrap();
        let full = client.disasm_range("0x1000", "0x1017", None).unwrap();
        assert_eq!(
            full["count"], 4,
            "both branch groups, not unreachable bytes: {full}"
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(client.disasm_range("0x1000", "0x1017", None).unwrap(), full);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
