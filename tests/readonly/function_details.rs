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
    result.data()
}

#[test]
#[serial]
fn function_get_preserves_disjoint_body_ranges_without_expanding_list_rows() {
    require_ghidra!();
    let program = fixture("gcc");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let detail = command(&program, &["function", "get", "disjoint"]);
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
            assert_eq!(command(&program, &["function", "get", address]), detail);
        }
        assert!(client
            .send_command("get_function", Some(json!({"address":"0x1080"})))
            .is_err());

        let overlay = command(&program, &["function", "get", "body_overlay:0x1010"]);
        assert_eq!(overlay["name"], "overlay_body");
        assert_eq!(overlay["size"], 3);
        assert_eq!(
            overlay["body_ranges"],
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
            command(&program, &["function", "get", "unmapped_body"])["body_ranges"],
            json!([{"start":"0x00009000", "end":"0x00009000"}])
        );
        let external = command(&program, &["function", "get", "outside_body"]);
        assert_eq!(external["is_external"], true);
        assert_eq!(external["body_ranges"], json!([]));
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
                .send_command("program_list_calling_conventions", None)
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
                command(program, &["program", "list-calling-conventions"]),
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

fn signature_details(program: &str, target: &str) -> Value {
    command(program, &["function", "get", target, "--with-signature"])
}

fn frame_details(program: &str, target: &str) -> Value {
    command(program, &["function", "get", target, "--with-frame"])
}

fn signature_program_state() -> String {
    let result = harness().client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class ReadSignatureProgramState extends GhidraScript {
    public void run() {
        println("program-state=" + currentProgram.getModificationNumber() + ":" + currentProgram.isChanged());
    }
}
"#, &[], &[], false).unwrap();
    result["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.starts_with("program-state="))
        .unwrap()
        .to_owned()
}

#[test]
#[serial]
fn signature_details_read_program_types_storage_and_thunk_provenance_without_edits() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for compiler in ["gcc", "windows"] {
        let program = format!("signature-details-{compiler}-{}", uuid::Uuid::new_v4());
        client
            .script_run_source(
                include_str!("CreateSignatureDetailsFixture.java"),
                &[program.clone(), compiler.to_owned()],
                &[],
                false,
            )
            .unwrap();
        client.open_program(&program).unwrap();
        let checked = std::panic::catch_unwind(|| {
            let before = signature_program_state();
            let plain = signature_details(&program, "plain");
            let details = &plain["signature_details"];
            assert_eq!(details["storage_mode"], "dynamic");
            assert_eq!(details["source"], "USER_DEFINED");
            assert_eq!(details["variadic"], true);
            assert_eq!(
                details["return"],
                json!({
                    "type":"int", "type_path":"/int", "size":4,
                    "storage":"EAX:4", "forced_indirect":false
                })
            );
            assert_eq!(details["params"].as_array().unwrap().len(), 2);
            for (ordinal, name) in ["first", "second"].into_iter().enumerate() {
                let param = &details["params"][ordinal];
                assert_eq!(param["ordinal"], ordinal);
                assert_eq!(param["name"], name);
                assert_eq!(param["auto_parameter"], Value::Null);
                assert_eq!(
                    param["storage"],
                    format!("Stack[0x{:x}]:4", 4 + ordinal * 4)
                );
            }
            let mut summary = plain.clone();
            summary.as_object_mut().unwrap().remove("signature_details");
            assert_eq!(command(&program, &["function", "get", "plain"]), summary);
            assert_eq!(plain["stack_purge"]["bytes"], 4);

            let indirect = signature_details(&program, "indirect");
            let details = &indirect["signature_details"];
            assert_eq!(details["source"], "IMPORTED");
            assert_eq!(details["return"]["forced_indirect"], true);
            assert_eq!(details["return"]["formal_type"], "Result");
            assert_eq!(details["return"]["formal_type_path"], "/Recovered/Result");
            assert_eq!(details["return"]["type"], "Result *");
            assert_eq!(details["return"]["size"], 4);
            assert_eq!(details["params"][0]["auto_parameter"], "RETURN_STORAGE_PTR");
            assert_eq!(details["params"][1]["name"], "value");
            assert_eq!(details["params"][1]["ordinal"], 1);

            let method = signature_details(&program, "method");
            assert_eq!(method["signature_details"]["return"]["storage"], "<VOID>");
            assert_eq!(
                method["signature_details"]["params"][0]["auto_parameter"],
                "THIS"
            );
            let thunk = signature_details(&program, "method_thunk");
            let details = &thunk["signature_details"];
            assert_eq!(details["thunk_function"], "method");
            assert_eq!(details["thunk_address"], method["address"]);
            assert_eq!(details["effective_function"], "method");
            assert_eq!(details["effective_address"], method["address"]);
            assert_eq!(details["params"][0]["type"], "Wrapper *");

            let thunk = signature_details(&program, "plain_thunk");
            let mut details = thunk["signature_details"].clone();
            let obj = details.as_object_mut().unwrap();
            assert_eq!(obj.remove("thunk_function").unwrap(), "plain");
            assert_eq!(obj.remove("thunk_address").unwrap(), plain["address"]);
            assert_eq!(obj.remove("effective_function").unwrap(), "plain");
            assert_eq!(obj.remove("effective_address").unwrap(), plain["address"]);
            assert_eq!(details, plain["signature_details"]);

            let chained = signature_details(&program, "chained_thunk");
            let details = &chained["signature_details"];
            assert_eq!(details["thunk_function"], "plain_thunk");
            assert_eq!(details["thunk_address"], thunk["address"]);
            assert_eq!(details["effective_function"], "plain");
            assert_eq!(details["effective_address"], plain["address"]);

            let custom = signature_details(&program, "custom");
            let details = &custom["signature_details"];
            assert_eq!(details["storage_mode"], "custom");
            assert_eq!(details["return"]["storage"], "EDX:4,EAX:4");
            assert_eq!(details["return"]["size"], 8);
            assert_eq!(details["params"][0]["storage"], "EAX:4");
            assert_eq!(details["params"][1]["storage"], "Stack[0x4]:4");
            assert_eq!(
                signature_details(&program, "unassigned")["signature_details"]["return"]["storage"],
                "<UNASSIGNED>"
            );

            let unknown = signature_details(&program, "unknown");
            assert_eq!(unknown["signature_details"]["source"], "DEFAULT");
            assert_eq!(unknown["signature_details"]["params"], json!([]));
            let external = signature_details(&program, "outside");
            assert_eq!(external["is_external"], true);
            assert_eq!(external["signature_details"]["return"]["type"], "void");

            let framed = frame_details(&program, "plain");
            assert!(framed.get("signature_details").is_none());
            assert_eq!(
                framed["frame_details"],
                json!({
                    "effective_function":"plain", "effective_address":plain["address"],
                    "frame_size":28, "local_size":20, "parameter_size":8,
                    "parameter_offset":4, "return_address_offset":8, "grows_negative":true,
                    "stack_variables":[
                        {"name":"buffer", "kind":"local", "type":"int", "type_path":"/int",
                         "size":4, "storage":"Stack[-0x10]:4", "stack_offset":-16,
                         "stack_size":4, "source":"USER_DEFINED", "first_use_offset":0},
                        {"name":"flag", "kind":"local", "type":"short", "type_path":"/short",
                         "size":2, "storage":"Stack[-0x4]:2", "stack_offset":-4,
                         "stack_size":2, "source":"ANALYSIS", "first_use_offset":0},
                        {"name":"first", "kind":"parameter", "type":"int", "type_path":"/int",
                         "size":4, "storage":"Stack[0x4]:4", "stack_offset":4,
                         "stack_size":4, "source":"USER_DEFINED", "ordinal":0, "auto_parameter":null},
                        {"name":"second", "kind":"parameter", "type":"int", "type_path":"/int",
                         "size":4, "storage":"Stack[0x8]:4", "stack_offset":8,
                         "stack_size":4, "source":"USER_DEFINED", "ordinal":1, "auto_parameter":null}
                    ]
                })
            );
            for target in ["plain_thunk", "chained_thunk"] {
                let forwarded = frame_details(&program, target);
                assert_eq!(forwarded["name"], target);
                assert!(forwarded.get("signature_details").is_none());
                assert_eq!(forwarded["frame_details"], framed["frame_details"]);
            }
            let framed_custom = frame_details(&program, "custom");
            let frame = &framed_custom["frame_details"];
            assert_eq!(frame["frame_size"], 20);
            assert_eq!(frame["local_size"], 16);
            assert_eq!(frame["parameter_size"], 4);
            let variables = frame["stack_variables"].as_array().unwrap();
            assert_eq!(variables.len(), 2);
            assert_eq!(variables[0]["name"], "custom_local");
            assert_eq!(variables[1]["name"], "on_stack");
            assert_eq!(
                frame_details(&program, "unassigned")["frame_details"]["stack_variables"],
                json!([])
            );
            assert_eq!(
                frame_details(&program, "outside")["frame_details"]["stack_variables"],
                json!([])
            );
            for target in ["indirect", "method", "method_thunk"] {
                let saved = signature_details(&program, target);
                let frame = frame_details(&program, target);
                let params = saved["signature_details"]["params"].as_array().unwrap();
                for variable in frame["frame_details"]["stack_variables"]
                    .as_array()
                    .unwrap()
                {
                    let ordinal = variable["ordinal"].as_u64().unwrap() as usize;
                    assert_eq!(variable["storage"], params[ordinal]["storage"]);
                    assert_eq!(
                        variable["auto_parameter"],
                        params[ordinal]["auto_parameter"]
                    );
                }
            }
            let both = command(
                &program,
                &[
                    "function",
                    "get",
                    "chained_thunk",
                    "--with-signature",
                    "--with-frame",
                ],
            );
            assert_eq!(both["signature_details"], chained["signature_details"]);
            assert_eq!(both["frame_details"], framed["frame_details"]);

            let listed = command(&program, &["function", "list", "--limit", "0"]);
            assert!(listed
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row.get("signature_details").is_none()
                    && row.get("frame_details").is_none()));
            assert_eq!(
                command(
                    &program,
                    &[
                        "function",
                        "get",
                        "custom",
                        "--with-signature",
                        "--fields",
                        "name,signature_details"
                    ]
                ),
                json!({"name":"custom", "signature_details":custom["signature_details"]})
            );
            for format in ["compact", "full"] {
                let result = ghidra(harness())
                    .args([
                        "function",
                        "get",
                        "indirect",
                        "--with-signature",
                        "--format",
                        format,
                    ])
                    .with_project(test_project(), &program)
                    .run();
                result
                    .assert_success()
                    .assert_stdout_contains("Program signature:")
                    .assert_stdout_contains("indirect from /Recovered/Result")
                    .assert_stdout_contains("auto=RETURN_STORAGE_PTR");
            }
            assert_eq!(
                signature_program_state(),
                before,
                "Inspection changed the Program"
            );
            client.open_program(TEST_PROGRAM).unwrap();
            client.open_program(&program).unwrap();
            assert_eq!(signature_details(&program, "plain"), plain);
            assert_eq!(signature_details(&program, "custom"), custom);
            assert_eq!(frame_details(&program, "plain"), framed);
            assert_eq!(frame_details(&program, "custom"), framed_custom);

            let receipt = command(
                &program,
                &[
                    "function",
                    "set-signature",
                    "chained_thunk",
                    "--signature",
                    "short plain(int replacement)",
                ],
            );
            assert_eq!(receipt["effective_function"], "plain");
            assert_eq!(receipt["effective_address"], plain["address"]);
            let updated = signature_details(&program, "plain");
            assert_eq!(updated["signature_details"]["return"]["type"], "short");
            assert_eq!(
                updated["signature_details"]["params"][0]["name"],
                "replacement"
            );
        });
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
        if let Err(panic) = checked {
            std::panic::resume_unwind(panic);
        }
    }
}

#[test]
#[serial]
fn frame_details_preserve_positive_growth_and_signed_stack_offsets() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("positive-frame-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreatePositiveFrameFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let before = signature_program_state();
        let detail = frame_details(&program, "positive_frame");
        let frame = &detail["frame_details"];
        assert_eq!(frame["effective_function"], "positive_frame");
        assert_eq!(frame["effective_address"], detail["address"]);
        assert_eq!(frame["grows_negative"], false);
        assert_eq!(frame["frame_size"], 13);
        assert_eq!(frame["local_size"], 7);
        assert_eq!(frame["parameter_size"], 6);
        assert_eq!(frame["parameter_offset"], -2);
        assert_eq!(frame["return_address_offset"], -2);
        let variables = frame["stack_variables"].as_array().unwrap();
        assert_eq!(variables.len(), 4);
        for (row, (name, offset)) in
            variables
                .iter()
                .zip([("split", -8), ("second", -6), ("first", -4), ("local", 4)])
        {
            assert_eq!(row["name"], name);
            assert_eq!(row["stack_offset"], offset);
            assert_eq!(row["stack_size"], 1);
        }
        assert_eq!(variables[0]["size"], 2);
        assert_eq!(variables[0]["storage"], "ACC:1,Stack[-0x8]:1");
        assert_eq!(variables[0]["ordinal"], 2);
        assert_eq!(
            signature_program_state(),
            before,
            "Frame inspection changed the Program"
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
