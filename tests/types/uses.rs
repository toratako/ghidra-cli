use super::{harness, type_command, unique_suffix, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn uses(program: &str, name: &str, extra: &[&str]) -> Value {
    let mut args = vec!["uses", name];
    args.extend(extra);
    let result = type_command(program, &args);
    result.assert_success();
    serde_json::from_str(&result.stdout).unwrap()
}

fn wrapper_kinds(row: &Value) -> Vec<&str> {
    row["wrappers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|wrapper| wrapper["kind"].as_str().unwrap())
        .collect()
}

#[test]
#[serial]
fn uses_preserve_type_identity_wrappers_and_database_signature_provenance() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for compiler in ["gcc", "windows"] {
        let program = format!("type-uses-{compiler}-{}", unique_suffix());
        client
            .script_run_source(
                include_str!("CreateTypeUsesFixture.java"),
                &[program.clone(), compiler.to_owned()],
                &[],
                false,
            )
            .unwrap();
        client.open_program(&program).unwrap();
        let checked = std::panic::catch_unwind(|| {
            let all = uses(&program, "/Recovered/Widget", &["--limit", "0"]);
            assert_eq!(all["meta"]["target_type_path"], "/Recovered/Widget");
            assert_eq!(all["meta"]["kinds"], json!(["data", "signature"]));
            assert_eq!(
                all["meta"]["scan"],
                json!({"complete":true, "stop_reason":null})
            );
            let rows = all["data"].as_array().unwrap();
            let data: Vec<_> = rows.iter().filter(|r| r["kind"] == "data").collect();
            assert_eq!(
                data.iter()
                    .map(|r| r["name"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                [
                    "direct",
                    "pointer",
                    "array",
                    "alias",
                    "pointer_alias",
                    "nested_array"
                ]
            );
            for (row, expected) in data.iter().zip([
                vec![],
                vec!["pointer"],
                vec!["array"],
                vec!["typedef"],
                vec!["pointer", "typedef"],
                vec!["array", "array", "typedef", "pointer"],
            ]) {
                assert_eq!(wrapper_kinds(row), expected, "{row}");
            }
            assert_eq!(data[2]["wrappers"][0]["count"], 3);
            assert_eq!(data[5]["wrappers"][0]["count"], 2);
            assert_eq!(data[5]["wrappers"][1]["count"], 3);
            let only_data = uses(
                &program,
                "/Recovered/Widget",
                &["--kind", "data", "--limit", "0"],
            );
            assert_eq!(only_data["data"], json!(data));
            let signature = uses(
                &program,
                "/Recovered/Widget",
                &["--kind", "signature", "--limit", "0"],
            );
            let signatures = signature["data"].as_array().unwrap();
            assert_eq!(signatures.len(), 12, "{signature}");
            for (address, name) in [
                ("0x00001000", "process"),
                ("0x00001100", "process_thunk"),
                ("0x00001200", "chained_thunk"),
            ] {
                let params: Vec<_> = signatures
                    .iter()
                    .filter(|r| r["address"] == address)
                    .collect();
                assert_eq!(params.len(), 2, "{name}: {signature}");
                assert_eq!(params[0]["role"], "return");
                assert_eq!(params[1]["role"], "parameter");
                assert_eq!(params[1]["ordinal"], 0);
                assert_eq!(params[1]["name"], "ctx");
                assert_eq!(params[1]["signature_source"], "USER_DEFINED");
                assert_eq!(wrapper_kinds(params[1]), ["pointer", "typedef"]);
                if name != "process" {
                    assert_eq!(params[1]["is_thunk"], true);
                    assert_eq!(params[1]["effective_address"], "0x00001000");
                }
            }
            let indirect: Vec<_> = signatures
                .iter()
                .filter(|r| r["function"] == "indirect")
                .collect();
            assert_eq!(indirect.len(), 2, "{signature}");
            assert_eq!(indirect[0]["role"], "return");
            assert_eq!(indirect[0]["type_path"], "/Recovered/Widget");
            assert_eq!(indirect[0]["forced_indirect"], true);
            assert_eq!(indirect[0]["effective_type_path"], "/Recovered/Widget *");
            assert!(wrapper_kinds(indirect[0]).is_empty());
            assert_eq!(indirect[1]["auto_parameter"], "RETURN_STORAGE_PTR");
            assert_eq!(indirect[1]["ordinal"], 0);
            assert_eq!(
                signatures
                    .iter()
                    .filter(|r| r["is_external"] == true)
                    .count(),
                4
            );

            let wrapper = uses(
                &program,
                "/Wrapper",
                &["--kind", "signature", "--limit", "0"],
            );
            assert_eq!(wrapper["data"].as_array().unwrap().len(), 1, "{wrapper}");
            assert_eq!(wrapper["data"][0]["address"], "0x00001600");
            assert_eq!(wrapper["data"][0]["auto_parameter"], "THIS");
            assert_eq!(wrapper["data"][0]["effective_address"], "0x00001500");

            let alias = uses(
                &program,
                "/Recovered/WidgetAlias",
                &["--kind", "data", "--limit", "0"],
            );
            assert_eq!(alias["data"].as_array().unwrap().len(), 2, "{alias}");
            assert_eq!(alias["data"][0]["name"], "alias");
            assert!(wrapper_kinds(&alias["data"][0]).is_empty());
            let pointer = uses(
                &program,
                "/Recovered/Widget *",
                &["--kind", "data", "--limit", "0"],
            );
            assert_eq!(pointer["data"].as_array().unwrap().len(), 2, "{pointer}");
            assert_eq!(pointer["data"][0]["name"], "pointer");
            let array_path = data[2]["type_path"].as_str().unwrap();
            let array = uses(&program, array_path, &["--kind", "data", "--limit", "0"]);
            assert_eq!(array["data"].as_array().unwrap().len(), 1);
            assert!(wrapper_kinds(&array["data"][0]).is_empty());
            for (name, expected) in [
                ("/int", "builtin"),
                ("/Recovered/int", "named_int"),
                ("/Other/Widget", "other"),
            ] {
                let found = uses(&program, name, &["--kind", "data", "--limit", "0"]);
                assert_eq!(found["data"].as_array().unwrap().len(), 1, "{found}");
                assert_eq!(found["data"][0]["name"], expected);
            }
            let empty = uses(&program, "/Recovered/Unused", &["--limit", "0"]);
            assert_eq!(empty["data"], json!([]));
            assert_eq!(empty["meta"]["scan"]["complete"], true);
            type_command(&program, &["uses", "Widget"])
                .assert_failure()
                .assert_stderr_contains("Ambiguous type name");
            type_command(&program, &["uses", "/Missing/Widget"])
                .assert_failure()
                .assert_stderr_contains("Registered type not found");

            let limited = uses(&program, "/Recovered/Widget", &["--limit", "1"]);
            assert_eq!(limited["data"], json!([data[0]]));
            assert_eq!(
                limited["meta"]["scan"],
                json!({"complete":false, "stop_reason":"limit"})
            );
            let filtered = uses(
                &program,
                "/Recovered/Widget",
                &[
                    "--filter",
                    "kind=signature AND function=process",
                    "--sort",
                    "role",
                    "--skip",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "role,address",
                ],
            );
            assert_eq!(
                filtered["data"],
                json!([{"role":"return", "address":"0x00001000"}])
            );
            assert_eq!(filtered["meta"]["scan"]["complete"], true);
            assert_eq!(
                uses(
                    &program,
                    "/Recovered/Widget",
                    &["--kind", "data", "--count"]
                )["data"],
                6
            );
            // Read-only DB probe also verifies cancellation after scanning has begun.
            client
                .script_run_source(include_str!("CheckTypeUsesReadOnly.java"), &[], &[], false)
                .unwrap();
            client.program_close().unwrap();
            assert_eq!(uses(&program, "/Recovered/Widget", &["--limit", "0"]), all);
        });
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
        if let Err(panic) = checked {
            std::panic::resume_unwind(panic);
        }
    }
}
