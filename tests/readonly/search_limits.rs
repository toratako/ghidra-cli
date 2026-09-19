use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn test_search_limits_and_client_defaults_on_complete_results() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("search-limits-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.DefaultLanguageService;
public class CreateSearchLimitFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("search limits fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                for (long base : new long[]{0x1000, 0x8000, 0x10000}) {
                    program.getMemory().createInitializedBlock("block_" + base, space.getAddress(base),
                        160 * 32, (byte) 0, monitor, false);
                }
                for (int i = 0; i < 160; i++) {
                    for (boolean defined : new boolean[]{false, true}) {
                        var address = space.getAddress((defined ? 0x8000 : 0x1000) + i * 32);
                        byte[] value = String.format(java.util.Locale.ROOT,
                            (defined ? "DEFINED_NEEDLE_" : "CAP_NEEDLE_") + "%03d", i)
                            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                        program.getMemory().setBytes(address, value);
                        if (defined) program.getListing().createData(address, StringDataType.dataType, value.length + 1);
                    }
                    var entry = space.getAddress(0x10000 + i * 16);
                    program.getFunctionManager().createFunction(String.format(java.util.Locale.ROOT, "password_case_%03d", i),
                        entry, new AddressSet(entry), SourceType.USER_DEFINED);
                    program.getReferenceManager().addMemoryReference(entry, space.getAddress(0x8000),
                        RefType.DATA, SourceType.USER_DEFINED, 0);
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
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
            output.json()
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
            assert_eq!(with(&["--offset", "100"]), json!(rows[100..102]));
            assert_eq!(
                with(&["--offset", "100", "--limit", "0"]),
                json!(rows[100..])
            );
            assert_eq!(with(&["--count", "--offset", "100", "--limit", "2"]), 2);
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
            (vec!["memory", "map"], 3),
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
        std::fs::write(&batch_path, "function list --filter name~password_case_\nfunction list --filter name~password_case_ --fields name\nfind bytes 4341505f4e4545444c455f --count\nfunction list --offset 100 --limit 0\n").unwrap();
        let batch = run(&["batch", batch_path.to_str().unwrap()]);
        let results = &batch[0]["results"];
        assert_eq!(results[0]["result"].as_array().unwrap().len(), 2);
        assert_eq!(results[1]["result"].as_array().unwrap().len(), 2);
        assert_eq!(results[2]["result"], 160);
        assert_eq!(results[3]["result"].as_array().unwrap().len(), 60);

        // A dense uncapped search cannot finish before cancellation is observed.
        // Its next request must get a fresh, non-cancelled monitor.
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class AddDenseSearchBlock extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getMemory().createInitializedBlock("dense",
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x100000),
            16 * 1024 * 1024, (byte) 0, monitor, false);
    }
}
"#,
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
                    let id = status["active_job"]["id"].as_u64().unwrap();
                    client.cancel_job(Some(id)).unwrap();
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
                client.job_status(Some(id)).unwrap()["job"]["state"],
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
