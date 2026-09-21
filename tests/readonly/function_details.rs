use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

fn fixture(compiler: &str) -> String {
    let program = format!("function-details-{compiler}-{}", uuid::Uuid::new_v4());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("CreateFunctionDetailsFixture.java"),
            &[program.clone(), compiler.to_owned()],
            &[],
            false,
        )
        .unwrap();
    program
}

fn command(program: &str, args: &[&str]) -> Value {
    let result = ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run();
    result.assert_success();
    result.json()
}

#[test]
#[serial]
fn function_get_preserves_disjoint_body_ranges_without_expanding_list_rows() {
    require_ghidra!();
    let program = fixture("gcc");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let detail = command(&program, &["function", "get", "disjoint"])[0].clone();
        assert_eq!(detail["entry_point"], "0x00001000");
        assert_eq!(detail["size"], 10);
        assert_eq!(
            detail["body_ranges"],
            json!([
                {"start":"0x00000ff0", "end":"0x00000ff1"},
                {"start":"0x00001000", "end":"0x00001004"},
                {"start":"0x00001100", "end":"0x00001102"},
            ])
        );
        // Selectors in any body range resolve the same function, even before its entry.
        for address in ["0xff1", "0x1000", "0x1102"] {
            assert_eq!(command(&program, &["function", "get", address])[0], detail);
        }
        assert!(client
            .send_command("get_function", Some(json!({"address":"0x1080"})))
            .is_err());

        let overlay = command(&program, &["function", "get", "body_overlay:0x1010"]);
        assert_eq!(overlay[0]["name"], "overlay_body");
        assert_eq!(overlay[0]["size"], 3);
        assert_eq!(
            overlay[0]["body_ranges"],
            json!([
                {"start":"body_overlay:0x00001000", "end":"body_overlay:0x00001001"},
                {"start":"body_overlay:0x00001010", "end":"body_overlay:0x00001010"},
            ])
        );

        let listed = command(&program, &["function", "list", "--limit", "0"]);
        let rows = listed.as_array().unwrap();
        assert_eq!(rows.len(), 2, "{listed}");
        assert!(rows.iter().all(|row| row.get("body_ranges").is_none()));
        let mut summary = detail.clone();
        summary.as_object_mut().unwrap().remove("body_ranges");
        assert!(rows.contains(&summary));
        assert!(rows.iter().any(|row| row["name"] == "overlay_body"));
        assert_eq!(
            command(&program, &["function", "get", "unmapped_body"])[0]["body_ranges"],
            json!([{"start":"0x00009000", "end":"0x00009000"}])
        );
        let external = command(&program, &["function", "get", "outside_body"]);
        assert_eq!(external[0]["is_external"], true);
        assert_eq!(external[0]["body_ranges"], json!([]));
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn calling_convention_discovery_follows_selected_compiler_and_accepts_listed_names() {
    require_ghidra!();
    let gcc = fixture("gcc");
    let windows = fixture("windows");
    let client = harness().client().unwrap();
    let checked = std::panic::catch_unwind(|| {
        for (program, default, distinct) in [
            (&gcc, "__cdecl", "__regparm3"),
            (&windows, "__stdcall", "__fastcall"),
        ] {
            client.open_program(program).unwrap();
            let native = client
                .send_command("function_list_calling_conventions", None)
                .unwrap();
            let rows = native["calling_conventions"].as_array().unwrap();
            assert_eq!(native["count"], rows.len());
            assert!(rows.iter().any(|row| row["name"] == distinct));
            let defaults: Vec<_> = rows
                .iter()
                .filter(|row| row["is_default"] == true)
                .map(|row| row["name"].as_str().unwrap())
                .collect();
            assert_eq!(defaults, [default]);
            assert_eq!(
                command(program, &["function", "list-calling-conventions"]),
                json!(rows)
            );
            for row in rows {
                let name = row["name"].as_str().unwrap();
                assert_eq!(row.as_object().unwrap().len(), 2);
                client
                    .send_command(
                        "function_set_calling_convention",
                        Some(json!({"target":"disjoint", "convention":name})),
                    )
                    .unwrap_or_else(|error| panic!("discovered {name} is unusable: {error}"));
                let function = client
                    .send_command("get_function", Some(json!({"address":"disjoint"})))
                    .unwrap();
                assert_eq!(function["calling_convention"], name);
            }
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&gcc).unwrap();
    client.program_delete(&windows).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
