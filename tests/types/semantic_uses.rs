use super::{harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("semantic-type-uses-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("CreateSemanticTypeUsesFixture.java"),
                std::slice::from_ref(&name),
                &[],
                false,
            )
            .unwrap();
        name
    })
}

fn restored(check: impl FnOnce()) {
    let client = harness().client().unwrap();
    client.open_program(fixture()).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check));
    client.open_program(TEST_PROGRAM).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

fn query(args: &[&str]) -> Value {
    let result = type_command(fixture(), args);
    result.assert_success();
    serde_json::from_str(&result.stdout).unwrap()
}

fn variables(name: &str, extra: &[&str]) -> Value {
    let mut args = vec!["uses", name, "--kind", "variable", "--limit", "0"];
    args.extend_from_slice(extra);
    query(&args)
}

fn fields(name: &str, selector: &[&str], extra: &[&str]) -> Value {
    let mut args = vec!["field", "uses", name, "--limit", "0"];
    args.extend_from_slice(selector);
    args.extend_from_slice(extra);
    query(&args)
}

fn packet_field(field: &str, function: &str) -> Value {
    fields(
        "/Semantic/Packet",
        &["--field", field],
        &["--function", function],
    )
}

fn rows(result: &Value) -> &[Value] {
    result["data"].as_array().unwrap()
}

fn wrappers(row: &Value) -> Vec<&str> {
    row["wrappers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|wrapper| wrapper["kind"].as_str().unwrap())
        .collect()
}

fn assert_complete(result: &Value) {
    let scan = &result["meta"]["scan"];
    assert_eq!(scan["complete"], true, "{result}");
    assert!(scan["stop_reason"].is_null(), "{result}");
    assert_eq!(scan["failed_functions"], json!([]), "{result}");
    assert_eq!(scan["unvisited_functions"], 0, "{result}");
}

#[test]
#[serial]
fn semantic_variable_uses_match_registered_identity_and_fresh_decompiler_variables() {
    require_ghidra!();
    restored(|| {
        let client = harness().client().unwrap();
        for (function, expected) in [
            ("read_count", vec!["pointer"]),
            ("alias_read", vec!["pointer", "typedef"]),
            ("array_read", vec!["pointer", "array", "typedef"]),
            ("by_value", vec![]),
        ] {
            let found = variables("/Semantic/Packet", &["--function", function]);
            assert_complete(&found);
            assert_eq!(found["meta"]["target_type_path"], "/Semantic/Packet");
            assert_eq!(found["meta"]["scope"]["function"], function);
            assert_eq!(rows(&found).len(), 1, "{found}");
            let row = &rows(&found)[0];
            assert_eq!(row["kind"], "variable");
            assert_eq!(row["role"], "parameter");
            assert_eq!(row["function"], function);
            assert_eq!(row["name"], "ctx");
            assert_eq!(row["ordinal"], 0);
            assert_eq!(row["evidence"], "decompiler");
            assert!(row["address"].is_string());
            assert!(row["storage"].is_string());
            assert!(row["type_path"].is_string());
            assert_eq!(wrappers(row), expected, "{row}");
            if function == "array_read" {
                assert_eq!(row["wrappers"][1]["count"], 2);
            }
        }
        for function in ["other_read", "twin_read", "nested_read"] {
            let excluded = variables("/Semantic/Packet", &["--function", function]);
            assert_complete(&excluded);
            assert_eq!(excluded["data"], json!([]), "{excluded}");
        }
        for (target, function) in [
            ("/Other/Packet", "other_read"),
            ("/Twin/Packet", "twin_read"),
        ] {
            let found = variables(target, &["--function", function]);
            assert_complete(&found);
            assert_eq!(rows(&found).len(), 1, "{found}");
        }
        let pointer = variables("/Semantic/Packet *32", &["--function", "read_count"]);
        assert_complete(&pointer);
        assert_eq!(rows(&pointer).len(), 1, "{pointer}");
        assert!(wrappers(&rows(&pointer)[0]).is_empty());
        let local_before = client.function_var_list("inferred_local").unwrap();
        let local = variables("/Semantic/Packet", &["--function", "inferred_local"]);
        assert_complete(&local);
        let local_row = rows(&local)
            .iter()
            .find(|row| row["role"] == "local")
            .unwrap_or_else(|| panic!("Expected inferred Packet local: {local}"));
        assert!(
            local_row["first_use"].is_string() || local_row["first_use"].is_null(),
            "{local_row}"
        );
        assert_eq!(local_row["type_path"], "/Semantic/Packet");
        let detail = client
            .send_command(
                "function_var_get",
                Some(json!({"target":"inferred_local", "var_name":local_row["name"]})),
            )
            .unwrap();
        assert!(detail["database"].is_null(), "{detail}");
        assert_eq!(detail["decompiler"]["type_path"], local_row["type_path"]);
        assert_eq!(
            client.function_var_list("inferred_local").unwrap(),
            local_before
        );

        let inferred = variables("/Semantic/Packet", &["--function", "inferred_parameter"]);
        assert_complete(&inferred);
        assert_eq!(rows(&inferred).len(), 1, "{inferred}");
        assert_eq!(rows(&inferred)[0]["role"], "parameter");
        let signature = client
            .send_command(
                "get_function",
                Some(json!({"address":"inferred_parameter", "with_signature":true})),
            )
            .unwrap();
        assert_eq!(signature["signature_details"]["params"], json!([]));
        assert_eq!(signature["signature_details"]["source"], "DEFAULT");
        let database = query(&["uses", "/Semantic/Packet", "--limit", "0"]);
        assert_eq!(database["meta"]["kinds"], json!(["data", "signature"]));
        assert!(rows(&database).iter().all(|row| row["kind"] != "variable"));
        assert!(rows(&database)
            .iter()
            .all(|row| row["function"] != "inferred_parameter"));
    });
}

#[test]
#[serial]
fn semantic_field_uses_report_native_read_write_address_and_identity() {
    require_ghidra!();
    restored(|| {
        for (function, instruction, expected) in [
            ("read_count", "0x00001004", vec!["read"]),
            ("write_count", "0x00001044", vec!["write"]),
            ("address_count", "0x00001084", vec!["address"]),
            ("update_count", "0x000010c4", vec!["read", "write"]),
            ("alias_read", "0x00001184", vec!["read"]),
            ("address_to_call", "0x00001484", vec!["address"]),
        ] {
            let found = packet_field("count", function);
            assert_complete(&found);
            assert_eq!(found["meta"]["target_type_path"], "/Semantic/Packet");
            assert_eq!(found["meta"]["target_field"]["name"], "count");
            let mut accesses: Vec<_> = rows(&found)
                .iter()
                .map(|row| row["access"].as_str().unwrap())
                .collect();
            accesses.sort_unstable();
            assert_eq!(accesses, expected, "{found}");
            for row in rows(&found) {
                assert_eq!(row["function"], function);
                assert_eq!(row["instruction_address"], instruction, "{row}");
                assert!(row["function_address"].is_string());
                assert!(row["sequence"].is_number());
                assert!(row["evidence"].is_object(), "{row}");
            }
        }
        let named = packet_field("zero", "read_zero");
        assert_complete(&named);
        assert_eq!(rows(&named).len(), 1, "{named}");
        assert_eq!(rows(&named)[0]["access"], "read");
        assert_eq!(rows(&named)[0]["instruction_address"], "0x00001104");
        for selector in [["--offset", "0x0"], ["--ordinal", "0"]] {
            assert_eq!(
                fields("/Semantic/Packet", &selector, &["--function", "read_zero"]),
                named
            );
        }
        for function in ["other_read", "twin_read", "no_access"] {
            let excluded = packet_field("count", function);
            assert_complete(&excluded);
            assert_eq!(excluded["data"], json!([]), "{excluded}");
        }
    });
}

#[test]
#[serial]
fn semantic_field_uses_follow_nested_arrays_and_by_value_components() {
    require_ghidra!();
    restored(|| {
        for (function, field, instruction) in [
            ("array_read", "count", "0x000011c4"),
            ("by_value", "count", "0x00001204"),
            ("nested_read", "count", "0x00001244"),
            ("read_values", "values", "0x00001284"),
        ] {
            let found = packet_field(field, function);
            assert_complete(&found);
            assert_eq!(rows(&found).len(), 1, "{found}");
            assert_eq!(rows(&found)[0]["access"], "read", "{found}");
            assert_eq!(
                rows(&found)[0]["instruction_address"],
                instruction,
                "{found}"
            );
        }
        let local = packet_field("count", "inferred_local");
        assert_complete(&local);
        let mut accesses: Vec<_> = rows(&local)
            .iter()
            .map(|row| row["access"].as_str().unwrap())
            .collect();
        accesses.sort_unstable();
        assert_eq!(accesses, ["address", "write"], "{local}");
        assert!(rows(&local)
            .iter()
            .any(|row| row["access"] == "write" && row["instruction_address"] == "0x0000134d"));
        let returned = packet_field("count", "by_value_return");
        assert_complete(&returned);
        assert_eq!(rows(&returned).len(), 1, "{returned}");
        assert_eq!(rows(&returned)[0]["access"], "read");
    });
}

#[test]
#[serial]
fn semantic_scans_distinguish_empty_failed_and_limited_work_and_apply_queries() {
    require_ghidra!();
    restored(|| {
        let empty = variables("/Semantic/Unused", &["--function", "read_count"]);
        assert_complete(&empty);
        assert_eq!(empty["data"], json!([]));
        assert_eq!(empty["meta"]["scan"]["successful_functions"], 1);
        let failed = variables("/Semantic/Packet", &["--function", "unmapped"]);
        assert_eq!(failed["data"], json!([]));
        let scan = &failed["meta"]["scan"];
        assert_eq!(scan["complete"], false, "{failed}");
        assert_eq!(scan["stop_reason"], "decompile_failed");
        assert_eq!(scan["visited_functions"], 1);
        assert_eq!(scan["successful_functions"], 0);
        assert_eq!(scan["failed_functions"][0]["function"], "unmapped");
        assert_eq!(scan["failed_functions"][0]["address"], "0x00003000");
        assert!(scan["failed_functions"][0]["reason"].is_string());
        assert!(scan["failed_functions"][0]["message"].is_string());

        let all = variables("/Semantic/Packet", &[]);
        assert!(all["meta"]["scope"].is_null());
        assert_eq!(all["meta"]["scan"]["complete"], false);
        assert_eq!(all["meta"]["scan"]["stop_reason"], "decompile_failed");
        assert_eq!(
            all["meta"]["scan"]["failed_functions"],
            scan["failed_functions"]
        );
        let limited = query(&[
            "uses",
            "/Semantic/Packet",
            "--kind",
            "variable",
            "--limit",
            "1",
        ]);
        assert_eq!(rows(&limited).len(), 1);
        assert_eq!(limited["meta"]["scan"]["complete"], false);
        assert_eq!(limited["meta"]["scan"]["stop_reason"], "limit");
        assert!(
            limited["meta"]["scan"]["unvisited_functions"]
                .as_u64()
                .unwrap()
                > 0
        );
        let filtered = variables(
            "/Semantic/Packet",
            &[
                "--filter",
                "function=alias_read",
                "--fields",
                "function,role,name",
                "--sort",
                "function",
            ],
        );
        assert_eq!(
            filtered["data"],
            json!([{"function":"alias_read","role":"parameter","name":"ctx"}])
        );
        let count = fields(
            "/Semantic/Packet",
            &["--field", "count"],
            &[
                "--function",
                "update_count",
                "--filter",
                "access=write",
                "--count",
            ],
        );
        assert_eq!(count["data"], 1);
        assert_complete(&count);
        let field_limit = query(&[
            "field",
            "uses",
            "/Semantic/Packet",
            "--field",
            "count",
            "--function",
            "update_count",
            "--limit",
            "1",
        ]);
        assert_eq!(rows(&field_limit).len(), 1);
        assert_eq!(field_limit["meta"]["scan"]["complete"], false);
        assert_eq!(field_limit["meta"]["scan"]["stop_reason"], "limit");
        assert_eq!(field_limit["meta"]["scan"]["unvisited_functions"], 0);
        assert_eq!(field_limit["meta"]["scan"]["omitted_uses"], 1);
        let projected = fields(
            "/Semantic/Packet",
            &["--offset", "4"],
            &[
                "--function",
                "0x10c0",
                "--sort",
                "access",
                "--skip",
                "1",
                "--fields",
                "access",
            ],
        );
        assert_eq!(projected["data"], json!([{"access":"write"}]));
        assert_complete(&projected);
    });
}

#[test]
#[serial]
fn semantic_field_uses_distinguish_union_members_and_neighboring_bitfields() {
    require_ghidra!();
    restored(|| {
        let capability = harness()
            .client()
            .unwrap()
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class SemanticTypeUsesCapabilities extends GhidraScript {
    public void run() {
        try {
            Class.forName("ghidra.app.decompiler.ClangBitFieldToken");
            println("true");
        } catch (ClassNotFoundException unsupported) { println("false"); }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let native_bitfields = capability["stdout"]
            .as_str()
            .unwrap()
            .trim()
            .parse::<bool>()
            .unwrap();
        let left = fields(
            "/Semantic/Choice",
            &["--field", "left"],
            &["--function", "union_read"],
        );
        assert_complete(&left);
        assert_eq!(rows(&left).len(), 1, "{left}");
        assert_eq!(rows(&left)[0]["access"], "read");
        assert_eq!(rows(&left)[0]["instruction_address"], "0x00001404");
        let right = fields(
            "/Semantic/Choice",
            &["--ordinal", "1"],
            &["--function", "union_read"],
        );
        assert_complete(&right);
        assert_eq!(right["data"], json!([]), "{right}");
        for (function, access, instruction) in [
            ("bit_read", "read", "0x00001447"),
            ("bit_write", "write", "0x00001584"),
        ] {
            let low = fields(
                "/Semantic/Bits",
                &["--field", "low"],
                &["--function", function],
            );
            let high = fields(
                "/Semantic/Bits",
                &["--field", "high"],
                &["--function", function],
            );
            // Ghidra releases without native bit-field identities must expose an
            // unresolved scan; the shared storage byte cannot prove both fields.
            if !native_bitfields {
                assert_eq!(low["data"], json!([]), "{low}");
                assert_eq!(low["meta"]["scan"]["complete"], false, "{low}");
                assert!(
                    !low["meta"]["scan"]["unresolved"]
                        .as_array()
                        .unwrap()
                        .is_empty(),
                    "{low}"
                );
            } else {
                assert_complete(&low);
                assert_complete(&high);
                assert_eq!(rows(&low).len(), 1, "{low}");
                assert_eq!(rows(&low)[0]["access"], access);
                assert_eq!(rows(&low)[0]["instruction_address"], instruction);
            }
            assert_eq!(high["data"], json!([]), "{high}");
        }
    });
}

#[test]
#[serial]
fn semantic_searches_preserve_saved_program_and_recover_native_cancel_and_timeout() {
    require_ghidra!();
    restored(|| {
        let client = harness().client().unwrap();
        let before = client.function_var_list("inferred_local").unwrap();
        client
            .script_run_source(
                include_str!("CheckSemanticTypeUsesReadOnly.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        assert_eq!(client.function_var_list("inferred_local").unwrap(), before);
        client.program_close().unwrap();
        assert_complete(&variables(
            "/Semantic/Packet",
            &["--function", "inferred_local"],
        ));
        assert_complete(&packet_field("count", "read_count"));
    });
}
