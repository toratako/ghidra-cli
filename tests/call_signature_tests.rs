//! Saved call-site prototypes, effective calls, ownership, and native cleanup.

#[macro_use]
mod common;

use common::{ensure_test_project, test_project, DaemonTestHarness, FIXTURE_PROGRAM};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), FIXTURE_PROGRAM);
        DaemonTestHarness::new(test_project(), FIXTURE_PROGRAM).expect("Failed to start bridge")
    })
}

fn fixture(test: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    let name = format!("call-signatures-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("call_signatures/CreateCallSignatureFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&client, &name)));
    client.open_program(FIXTURE_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn run(client: &BridgeClient, command: &str, args: Value) -> Value {
    client.send_command(command, Some(args)).unwrap()
}

fn get(client: &BridgeClient, target: &str, at: &str) -> Value {
    run(
        client,
        "function_call_signature_get",
        json!({"target":target,"at":at}),
    )
}

fn set(client: &BridgeClient, target: &str, at: &str, signature: &str) -> Value {
    run(
        client,
        "function_call_signature_set",
        json!({"target":target,"at":at,"signature":signature}),
    )
}

fn clear(client: &BridgeClient, target: &str, at: &str) -> Value {
    run(
        client,
        "function_call_signature_clear",
        json!({"target":target,"at":at}),
    )
}

fn function(client: &BridgeClient, target: &str) -> Value {
    run(
        client,
        "get_function",
        json!({"address":target,"with_signature":true}),
    )
}

fn rejected(client: &BridgeClient, args: Value, diagnostic: &str) {
    let error = client
        .send_command("function_call_signature_set", Some(args))
        .unwrap_err();
    let error = error.downcast_ref::<BridgeCommandError>().unwrap();
    assert_eq!(error.detail["rolled_back"], true, "{error:?}");
    assert!(error.to_string().contains(diagnostic), "{error:?}");
}

fn check(client: &BridgeClient, arguments: &[&str]) {
    client
        .script_run_source(
            include_str!("call_signatures/CheckCallSignatureFixture.java"),
            &arguments
                .iter()
                .map(|arg| arg.to_string())
                .collect::<Vec<_>>(),
            &[],
            false,
        )
        .unwrap();
}

fn check_calls(client: &BridgeClient, expected: &[usize]) {
    // Use the bridge's retained native decompiler so edits must invalidate its cache.
    let pcode = client.pcode_function("caller", true, None, None).unwrap();
    let arities: Vec<_> = pcode["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|operation| operation["mnemonic"] == "CALL")
        .map(|operation| operation["inputs"].as_array().unwrap().len() - 1)
        .collect();
    assert_eq!(arities, expected, "{pcode}");
}

#[test]
#[serial]
fn direct_overrides_affect_only_selected_calls_and_preserve_shared_saved_types() {
    require_ghidra!();
    fixture(|client, program| {
        let original_callee = function(client, "callee");
        let original_caller = function(client, "caller");
        let initial = get(client, "caller", "0x1005");
        assert!(initial["override"].is_null(), "{initial}");
        assert_eq!(initial["in_body"], true);
        assert_eq!(initial["call_kind"], "direct");
        check_calls(client, &[1, 1]);

        let output = common::ghidra(harness())
            .args([
                "function",
                "call-signature",
                "set",
                "caller",
                "--at",
                "0x1005",
                "--signature",
                "int unrelated_name(int value, int extra)",
                "--convention",
                "__cdecl",
                "--json",
            ])
            .with_project(test_project(), program)
            .run();
        output.assert_success();
        let receipt: Value = output.data();
        assert_eq!(receipt["status"], "call_signature_set");
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["after"]["params"].as_array().unwrap().len(), 2);
        assert_eq!(receipt["after"]["calling_convention"], "__cdecl");
        assert_eq!(
            get(client, "caller", "0x1005")["override"],
            receipt["after"]
        );
        assert!(get(client, "caller", "0x1012")["override"].is_null());
        assert_eq!(function(client, "callee"), original_callee);
        assert_eq!(function(client, "caller"), original_caller);
        check_calls(client, &[2, 1]);

        // Names in declarations are not identities; these share one native type.
        let second = set(
            client,
            "caller",
            "0x1012",
            "int other_name(int value, int extra)",
        );
        assert_eq!(second["after"], receipt["after"]);
        check(client, &["shared"]);
        assert_eq!(
            set(
                client,
                "caller",
                "0x1005",
                "int another(int value, int extra)"
            )["changed"],
            false
        );
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(
            get(client, "caller", "0x1005")["override"],
            receipt["after"]
        );
        check(client, &["shared"]);
        check_calls(client, &[2, 2]);

        assert_eq!(clear(client, "caller", "0x1005")["changed"], true);
        assert_eq!(get(client, "caller", "0x1012")["override"], second["after"]);
        check_calls(client, &[1, 2]);
        set(
            client,
            "caller",
            "0x1005",
            "int restored(int value, int extra)",
        );
        check(client, &["shared"]);
        let replacement = set(client, "caller", "0x1005", "char *replacement(int value)");
        assert_eq!(replacement["after"]["return"]["type"], "char *");
        assert_eq!(replacement["after"]["return"]["size"], 4);
        assert_eq!(get(client, "caller", "0x1012")["override"], second["after"]);
        clear(client, "caller", "0x1005");
        assert_eq!(get(client, "caller", "0x1012")["override"], second["after"]);
        clear(client, "caller", "0x1012");
        assert_eq!(clear(client, "caller", "0x1012")["changed"], false);
        check(client, &["clean"]);
        assert_eq!(function(client, "callee"), original_callee);
    });
}

#[test]
#[serial]
fn indirect_variadic_thunk_and_effective_flow_calls_use_the_selected_caller() {
    require_ghidra!();
    fixture(|client, _| {
        let callee = function(client, "callee");
        let explicit = run(
            client,
            "function_call_signature_set",
            json!({"target":"indirect_caller","at":"0x1204","signature":"int dispatch(int count)","convention":"__regparm3"}),
        );
        assert_eq!(explicit["after"]["calling_convention"], "__regparm3");
        let indirect = set(
            client,
            "indirect_caller",
            "0x1204",
            "void dispatch(int count, ...)",
        );
        assert_eq!(indirect["call_kind"], "indirect");
        assert_eq!(indirect["after"]["variadic"], true);
        assert_eq!(indirect["after"]["return"]["type"], "void");
        assert_eq!(indirect["after"]["params"][0]["name"], "count");
        // Omitting convention replaces the saved ABI with the Program default.
        assert_eq!(indirect["after"]["calling_convention"], "__cdecl");

        let thunk = set(
            client,
            "caller_thunk",
            "0x1300",
            "int local_proto(int value, int extra)",
        );
        assert_eq!(thunk["function"], "caller_thunk");
        assert_eq!(thunk["address"], "0x00001300");
        assert_eq!(thunk["call_kind"], "direct");
        assert!(get(client, "callee", "0x1300")["override"].is_null());
        assert_eq!(function(client, "callee"), callee);

        rejected(
            client,
            json!({"target":"branch_caller","at":"0x1400","signature":"int site(void)"}),
            "found 0",
        );
        run(
            client,
            "listing_flow_set",
            json!({"address":"0x1400","override":"call"}),
        );
        assert_eq!(
            set(client, "branch_caller", "0x1400", "int site(void)")["call_count"],
            1
        );
        run(
            client,
            "listing_flow_clear",
            json!({"address":"0x1400","override":true}),
        );
        let stale = get(client, "branch_caller", "0x1400");
        assert_eq!(stale["call_count"], 0);
        assert!(stale["override"].is_object());
        assert_eq!(clear(client, "branch_caller", "0x1400")["changed"], true);

        let before = get(client, "indirect_caller", "0x1204");
        for (args, diagnostic) in [
            (
                json!({"target":"caller","at":"0x1006","signature":"int site(void)"}),
                "exact instruction start",
            ),
            (
                json!({"target":"caller","at":"0x1204","signature":"int site(void)"}),
                "outside",
            ),
            (
                json!({"target":"caller","at":"0x1000","signature":"int site(void)"}),
                "found 0",
            ),
            (
                json!({"target":"indirect_caller","at":"0x1204","signature":"int site(const char *value)"}),
                "cannot preserve",
            ),
            (
                json!({"target":"indirect_caller","at":"0x1204","signature":"int __cdecl site(void)"}),
                "return type",
            ),
            (
                json!({"target":"indirect_caller","at":"0x1204","signature":"int site(int value)","convention":"imaginary_abi"}),
                "Unsupported calling convention",
            ),
            (
                json!({"target":"indirect_caller","at":"0x1204","signature":""}),
                "signature required",
            ),
        ] {
            rejected(client, args, diagnostic);
            assert_eq!(get(client, "indirect_caller", "0x1204"), before);
        }
    });
}

#[test]
#[serial]
fn stale_overrides_survive_body_reownership_and_can_be_cleared_after_code_removal() {
    require_ghidra!();
    fixture(|client, _| {
        let previous = set(client, "caller", "0x1005", "int original(int value)")["after"].clone();
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class ReownCallSite extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1000)).setBody(new AddressSet(toAddr(0x1000), toAddr(0x1004)));
        currentProgram.getFunctionManager().createFunction("new_owner", toAddr(0x1005),
            new AddressSet(toAddr(0x1005), toAddr(0x101a)), SourceType.USER_DEFINED);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let stale = get(client, "caller", "0x1005");
        assert_eq!(stale["in_body"], false);
        assert_eq!(stale["override"], previous);
        assert!(get(client, "new_owner", "0x1005")["override"].is_null());
        set(client, "new_owner", "0x1005", "void replacement(void)");
        assert_eq!(get(client, "caller", "0x1005")["override"], previous);
        clear(client, "new_owner", "0x1005");
        assert_eq!(get(client, "caller", "0x1005")["override"], previous);
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class RemoveOverriddenCall extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getListing().clearCodeUnits(toAddr(0x1005), toAddr(0x1009), false);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let no_instruction = get(client, "caller", "0x1005");
        assert_eq!(no_instruction["instruction_exists"], false);
        assert_eq!(no_instruction["call_count"], 0);
        assert_eq!(no_instruction["override"], previous);
        assert_eq!(clear(client, "caller", "0x1005")["changed"], true);
        assert_eq!(clear(client, "caller", "0x1005")["changed"], false);
        check(client, &["clean"]);
    });
}

#[test]
#[serial]
fn failed_native_replacement_rolls_back_removed_marker_and_preserves_saved_prototype() {
    require_ghidra!();
    fixture(|client, program| {
        set(client, "caller", "0x1005", "int original(int value)");
        let before = get(client, "caller", "0x1005");
        client
            .script_run_source(
                include_str!("call_signatures/ExhaustOverrideHashSlots.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        rejected(
            client,
            json!({"target":"caller","at":"0x1005","signature":"char *replacement(int value)","convention":"__cdecl"}),
            "Unable to create datatype",
        );
        assert_eq!(get(client, "caller", "0x1005"), before);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "caller", "0x1005"), before);
    });
}
