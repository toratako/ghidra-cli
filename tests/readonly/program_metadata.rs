use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn relocations_preserve_native_evidence_and_support_cli_queries() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("program-metadata-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreateProgramMetadataFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let info = client.program_info().unwrap();
        assert_eq!(info["language_id"], "x86:LE:64:default");
        assert_eq!(info["compiler_spec_id"], "gcc");
        assert_eq!(info.get("executable_md5"), Some(&Value::Null));
        assert_eq!(info.get("executable_sha256"), Some(&Value::Null));

        let expected = json!([
            {
                "address": "0x00001000", "type": 17, "status": "APPLIED",
                "symbol_name": "relocation_alpha",
                "values": [-1, 9007199254740993i64, i64::MIN, i64::MAX],
                "original_bytes": "0080ff"
            },
            {
                "address": "0x00001000", "type": 3, "status": "SKIPPED",
                "symbol_name": null, "values": [], "original_bytes": ""
            },
            {
                "address": "0x00001010", "type": 7, "status": "FAILURE",
                "symbol_name": "relocation_beta", "values": null, "original_bytes": null
            },
            {
                "address": "relocation_overlay:0x00001000", "type": 23,
                "status": "UNSUPPORTED", "symbol_name": "relocation_overlay",
                "values": [8], "original_bytes": null
            }
        ]);
        let all = client
            .send_command("program_list_relocations", None)
            .unwrap();
        assert_eq!(all["count"], 4);
        assert_eq!(all["relocations"], expected);

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config = ghidra_cli::config::Config::load().unwrap();
        config.default_limit = Some(2);
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let run = |flags: &[&str]| -> Value {
            let result = ghidra(harness)
                .args(["program", "list-relocations"])
                .args(flags.iter().copied())
                .with_project(test_project(), &name)
                .env("GHIDRA_CLI_CONFIG", config_path.to_string_lossy())
                .arg("--json")
                .run();
            result.assert_success();
            result.data()
        };
        let rows = expected.as_array().unwrap();
        assert_eq!(run(&[]), json!(rows[..2]));
        assert_eq!(run(&["--limit", "0"]), expected);
        assert_eq!(run(&["--count"]), 4);
        assert_eq!(run(&["--offset", "2"]), json!(rows[2..]));
        assert_eq!(run(&["--offset", "10"]), json!([]));
        assert_eq!(
            run(&["--filter", "status='FAILURE'", "--fields", "address,status"]),
            json!([{"address":"0x00001010", "status":"FAILURE"}])
        );
        assert_eq!(
            run(&["--filter", "address='relocation_overlay:0x1000'"]),
            json!([rows[3]])
        );
        assert_eq!(
            run(&["--sort", "type", "--offset", "1", "--limit", "2", "--fields", "type"]),
            json!([{"type":7}, {"type":17}])
        );
        assert_eq!(run(&["--filter", "status='APPLIED'", "--count"]), 1);
        assert_eq!(run(&["--count", "--offset", "1", "--limit", "2"]), 2);

        client
            .script_run_source(
                include_str!("CheckRelocationCancellation.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        client.program_close().unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(
            client
                .send_command("program_list_relocations", None)
                .unwrap(),
            all
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
fn executable_hashes_describe_imported_file_after_memory_edits_and_reopen() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("original.bin");
    std::fs::write(&binary, b"abc").unwrap();
    let name = format!("executable-hashes-{}", uuid::Uuid::new_v4());
    client
        .send_command(
            "import",
            Some(json!({
                "binary_path": binary.to_str().unwrap(), "program": name,
                "loader": "BinaryLoader", "language": "x86:LE:64:default"
            })),
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let before = client.program_info().unwrap();
        assert_eq!(before["executable_md5"], "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            before["executable_sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let empty = client
            .send_command("program_list_relocations", None)
            .unwrap();
        assert_eq!(empty["relocations"], json!([]));
        assert_eq!(empty["count"], 0);
        for flags in [vec![], vec!["--count"]] {
            let result = ghidra(harness)
                .args(["program", "list-relocations"])
                .args(flags.iter().copied())
                .with_project(test_project(), &name)
                .arg("--json")
                .run();
            result.assert_success();
            assert_eq!(
                result.data::<Value>(),
                if flags.is_empty() {
                    json!([])
                } else {
                    json!(0)
                }
            );
        }

        client
            .memory_write(before["min_address"].as_str().unwrap(), "646566")
            .unwrap();
        // Saved metadata also survives removal of the original input file.
        std::fs::remove_file(&binary).unwrap();
        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&name).unwrap();
            }
            let after = client.program_info().unwrap();
            assert_eq!(after["executable_md5"], before["executable_md5"]);
            assert_eq!(after["executable_sha256"], before["executable_sha256"]);
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
