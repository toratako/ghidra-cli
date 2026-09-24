use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("structure-inference-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("CreateStructureInferenceFixture.java"),
                std::slice::from_ref(&name),
                &[],
                false,
            )
            .unwrap();
        name
    })
}

fn infer(target: &str, variable: &str, extra: &[&str]) -> Value {
    let result = ghidra(harness())
        .args([
            "function",
            "var",
            "infer-struct",
            target,
            "--var",
            variable,
            "--json",
        ])
        .args(extra.iter().copied())
        .with_project(test_project(), fixture())
        .run();
    result.assert_success();
    result.data()
}

fn restored(check: impl FnOnce()) {
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check));
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[serial]
fn structure_inference_returns_native_layout_and_bounded_accesses_without_edits() {
    require_ghidra!();
    let client = harness().client().unwrap();
    client.open_program(fixture()).unwrap();
    restored(|| {
        let variables = || client.function_var_list("recover").unwrap();
        let before = variables();
        let result = infer(
            "recover",
            "ctx",
            &["--where", "kind=parameter AND ordinal=0", "--with-accesses"],
        );
        assert_eq!(result["function"], "recover");
        let selected = before["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "ctx")
            .unwrap();
        assert_eq!(result["variable"], *selected);
        assert_eq!(result["structure"]["kind"], "struct");
        assert_eq!(result["structure"]["size"], 0x1c);
        assert!(result["structure"].get("path").is_none());
        let components = result["structure"]["components"].as_array().unwrap();
        assert_eq!(components.len(), 2, "{result}");
        assert_eq!(components[0]["offset"], 0x10);
        assert_eq!(components[0]["size"], 4);
        assert_eq!(components[0]["type_path"], "/int");
        assert_eq!(components[1]["offset"], 0x18);
        assert_eq!(components[1]["size"], 4);
        assert!(
            components[1]["type"].as_str().unwrap().contains("char"),
            "{result}"
        );
        assert!(components.iter().all(|field| field["name"].is_null()));
        let accesses = result["accesses"].as_array().unwrap();
        assert_eq!(accesses.len(), 2, "{result}");
        assert_eq!(accesses[0]["mnemonic"], "LOAD");
        assert_eq!(accesses[0]["offset"], 0x10);
        assert_eq!(accesses[1]["mnemonic"], "STORE");
        assert_eq!(accesses[1]["offset"], 0x18);
        assert!(accesses
            .iter()
            .all(|row| row["instruction_address"].is_string() && row["sequence"].is_number()));
        assert_eq!(
            result["accesses_status"],
            json!({"returned":2, "total":2, "max_accesses":1000, "truncated":false})
        );
        let limited = infer(
            "recover",
            "ctx",
            &["--with-accesses", "--max-accesses", "0x1"],
        );
        assert_eq!(limited["structure"], result["structure"]);
        assert_eq!(limited["accesses"], json!([accesses[0]]));
        assert_eq!(
            limited["accesses_status"],
            json!({"returned":1, "total":2, "max_accesses":1, "truncated":true})
        );
        let plain = infer("recover", "ctx", &[]);
        assert_eq!(plain["structure"], result["structure"]);
        assert!(plain.get("accesses").is_none());
        assert!(plain.get("accesses_status").is_none());
        assert!(plain["warnings"].is_array());
        assert_eq!(
            infer("recover", "ctx", &["--fields", "structure"]),
            json!({"structure":result["structure"]})
        );
        assert_eq!(
            variables(),
            before,
            "inference must preserve the program modification number and variable definitions"
        );
        assert_eq!(infer("integer_root", "ctx", &[])["structure"]["size"], 0x1c);
        assert!(infer("no_access", "ctx", &[])["structure"].is_null());
        assert!(infer("indexed", "ctx", &[])["structure"].is_null());
        let overlap = infer("overlap", "ctx", &["--with-accesses"]);
        let evidence = overlap["accesses"].as_array().unwrap();
        assert!(
            evidence
                .iter()
                .any(|row| row["mnemonic"] == "LOAD" && row["size"] == 4),
            "{overlap}"
        );
        assert!(
            evidence
                .iter()
                .any(|row| row["mnemonic"] == "STORE" && row["size"] == 1),
            "{overlap}"
        );
        assert_eq!(variables(), before);
    });
}

#[test]
#[serial]
fn structure_inference_preserves_existing_types_and_this_namespaces_and_rejects_partial_roots() {
    require_ghidra!();
    let client = harness().client().unwrap();
    client.open_program(fixture()).unwrap();
    restored(|| {
        let existing = || {
            client
                .send_command("type_get", Some(json!({"name":"Existing"})))
                .unwrap()
        };
        let signature = |target: &str| {
            client
                .send_command(
                    "get_function",
                    Some(json!({"address":target,"with_signature":true})),
                )
                .unwrap()
        };
        let before_type = existing();
        let before_signature = signature("typed_root");
        let method_signature = signature("0x11c0");
        let before = client.function_var_list("typed_root").unwrap();
        let typed = infer("typed_root", "ctx", &[]);
        assert!(!typed["structure"].is_null(), "{typed}");
        let method = infer("0x11c0", "this", &[]);
        assert!(!method["structure"].is_null(), "{method}");
        assert_eq!(client.function_var_list("typed_root").unwrap(), before);
        for (target, variable, message) in [
            ("partial", "ctx", "one whole HighVariable"),
            ("recover", "absent", "Variable not found"),
            ("outside", "ctx", "Decompilation failed"),
        ] {
            ghidra(harness())
                .args([
                    "function",
                    "var",
                    "infer-struct",
                    target,
                    "--var",
                    variable,
                    "--json",
                ])
                .with_project(test_project(), fixture())
                .run()
                .assert_failure()
                .assert_stderr_contains(message);
        }
        let row = before["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "ctx")
            .unwrap();
        let stale = json!({"project":before["project"],"program":before["program"],"function_address":before["address"],"modification":"stale","variable":row});
        let error = client
            .function_var_infer_struct("typed_root", "ctx", Some(&stale), false, None)
            .unwrap_err();
        assert!(error.to_string().contains("stale"), "{error:#}");
        for mut args in [
            json!({"with_accesses":true,"max_accesses":0}),
            json!({"max_accesses":1}),
        ] {
            args["target"] = json!("typed_root");
            args["var_name"] = json!("ctx");
            let error = client
                .send_command("function_var_infer_struct", Some(args))
                .unwrap_err();
            assert!(error.to_string().contains("max_accesses"), "{error:#}");
        }
        assert_eq!(existing(), before_type);
        assert_eq!(signature("typed_root"), before_signature);
        assert_eq!(signature("0x11c0"), method_signature);
        // Reopen to check the saved database as well as the live values.
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(fixture()).unwrap();
        assert_eq!(existing(), before_type);
        assert_eq!(signature("typed_root"), before_signature);
        assert_eq!(signature("0x11c0"), method_signature);
    });
}

#[test]
#[serial]
fn structure_inference_cancellation_discards_candidates_and_recovers() {
    require_ghidra!();
    let client = harness().client().unwrap();
    client.open_program(fixture()).unwrap();
    restored(|| {
        client
            .script_run_source(
                include_str!("CheckStructureInferenceCancellation.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        assert!(!infer("recover", "ctx", &[])["structure"].is_null());
    });
}
