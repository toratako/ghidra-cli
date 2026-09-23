//! Fresh native decompilation across architectures, evidence levels, and scan failures.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;

const BOOTSTRAP_PROGRAM: &str = "virtual-callers-bootstrap.bin";

fn harness() -> &'static common::DaemonTestHarness {
    static HARNESS: OnceLock<common::DaemonTestHarness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let project = std::path::Path::new(common::test_project());
        let binary = project.parent().unwrap().join(BOOTSTRAP_PROGRAM);
        std::fs::write(&binary, [0xc3u8]).unwrap();
        let installation = ghidra_cli::config::Config::load()
            .unwrap()
            .get_ghidra_installation()
            .unwrap();
        let program = import_oneshot(
            project,
            &binary,
            &installation,
            &OneShotImportOptions {
                language: Some("x86:LE:64:default".to_owned()),
                loader: Some("BinaryLoader".to_owned()),
                ..Default::default()
            },
        )
        .expect("import minimal bootstrap for native fixture scripts");
        assert_eq!(program, BOOTSTRAP_PROGRAM);
        common::DaemonTestHarness::new(common::test_project(), &program).unwrap()
    })
}

fn fixture(arm: bool) -> &'static str {
    static X86: OnceLock<String> = OnceLock::new();
    static ARM: OnceLock<String> = OnceLock::new();
    let slot = if arm { &ARM } else { &X86 };
    slot.get_or_init(|| {
        let name = format!("virtual-callers-{}", uuid::Uuid::new_v4());
        let language = if arm {
            "AARCH64:LE:64:v8A"
        } else {
            "x86:LE:64:default"
        };
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("fixtures/virtual_callers/CreateVirtualCallersFixture.java"),
                &[name.clone(), language.to_owned()],
                &[],
                false,
            )
            .expect("create native virtual-call fixture");
        name
    })
}

fn with_fixture(arm: bool, check: impl FnOnce(&BridgeClient, &str)) {
    require_ghidra!();
    let program = fixture(arm);
    with_program(program, check);
}

fn with_program(program: &str, check: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&client, program)));
    client.open_program(BOOTSTRAP_PROGRAM).unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

fn request(extra: Value) -> Value {
    let mut args = json!({
        "function": "virtual_target", "vtable": "virtual_address_point",
        "entries": 4, "abi": "itanium", "limit": 0, "timeout_secs": 30
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    args
}

fn search(client: &BridgeClient, extra: Value) -> Value {
    client
        .send_command("find_virtual_callers", Some(request(extra)))
        .expect("search native virtual callers")
}

fn calls(result: &Value) -> &[Value] {
    result["calls"].as_array().expect("caller rows")
}

fn address(value: &Value) -> u64 {
    u64::from_str_radix(
        value
            .as_str()
            .expect("address string")
            .strip_prefix("0x")
            .expect("hex address"),
        16,
    )
    .unwrap()
}

fn single_call<'a>(result: &'a Value, caller: &str, slot: usize, evidence: &str) -> &'a Value {
    assert_eq!(calls(result).len(), 1, "{result}");
    let call = &calls(result)[0];
    assert_eq!(call["caller"], caller, "{result}");
    assert_eq!(call["slot_index"], slot, "{result}");
    assert_eq!(call["slot_offset"], slot * 8, "{result}");
    assert_eq!(address(&call["slot_address"]), 0x3020 + slot as u64 * 8);
    assert_eq!(call["evidence"], evidence, "{result}");
    assert_eq!(result["scope"]["function"], caller, "{result}");
    assert_eq!(result["scan"]["total_functions"], 1, "{result}");
    assert_eq!(result["scan"]["visited_functions"], 1, "{result}");
    assert_eq!(result["scan"]["successful_functions"], 1, "{result}");
    assert_eq!(result["scan"]["failed_functions"], json!([]), "{result}");
    assert_eq!(result["scan"]["unvisited_functions"], 0, "{result}");
    call
}

fn check_value_calls(arm: bool) {
    with_fixture(arm, |client, _| {
        for (caller, entry, slot) in [
            ("known_zero", 0x1100, 0),
            ("known_nonzero", 0x1140, 1),
            ("known_thunk", 0x1180, 2),
        ] {
            let found = search(client, json!({"within":caller}));
            let call = single_call(&found, caller, slot, "table_value");
            assert_eq!(address(&call["caller_address"]), entry);
            assert_eq!(
                address(&call["call_site"]),
                entry + if arm { 12 } else { 5 },
                "The call site must identify CALL/BLR, not its preceding LOAD: {found}"
            );
            assert_eq!(found["scan"]["complete"], true, "{found}");
            assert_eq!(found["target"]["function"], "virtual_target");
            assert_eq!(address(&found["target"]["address"]), 0x1000);
            let slots = found["slots"].as_array().unwrap();
            assert_eq!(slots.len(), 3, "{found}");
            assert_eq!(slots[0]["match"], "direct");
            assert_eq!(slots[1]["match"], "direct");
            assert_eq!(slots[2]["match"], "thunk");
            assert_eq!(slots[2]["function"], "virtual_thunk");
        }
        let thunk = search(
            client,
            json!({"function":"virtual_thunk", "within":"known_thunk"}),
        );
        single_call(&thunk, "known_thunk", 2, "table_value");
        assert_eq!(thunk["slots"].as_array().unwrap().len(), 1, "{thunk}");
        assert_eq!(thunk["slots"][0]["match"], "direct");

        let unrelated = search(client, json!({"within":"unrelated_table"}));
        assert!(calls(&unrelated).is_empty(), "{unrelated}");
        assert_eq!(unrelated["scan"]["complete"], true, "{unrelated}");
        let direct = search(client, json!({"within":"ordinary_direct_call"}));
        assert!(calls(&direct).is_empty(), "{direct}");
        assert_eq!(direct["scan"]["complete"], true, "{direct}");
    });
}

#[test]
#[serial]
fn x86_value_evidence_matches_all_target_slots_and_excludes_other_tables() {
    check_value_calls(false);
}

#[test]
#[serial]
fn aarch64_value_evidence_follows_loads_to_the_blr_instruction() {
    check_value_calls(true);
}

fn check_type_and_offset_candidates(arm: bool) {
    with_fixture(arm, |client, _| {
        for (caller, slot, evidence) in [
            ("unknown_zero", 0, "slot_offset"),
            ("unknown_nonzero", 1, "slot_offset"),
            ("typed_zero", 0, "table_type"),
            ("typed_nonzero", 1, "table_type"),
            ("twin_type", 1, "slot_offset"),
            ("mixed_phi", 1, "slot_offset"),
        ] {
            let found = search(client, json!({"within":caller}));
            let call = single_call(&found, caller, slot, evidence);
            if evidence == "table_type" {
                assert_eq!(call["table_type"], "/Virtual/Table", "{found}");
                assert!(
                    call["table_type_id"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                        > 0,
                    "{found}"
                );
                assert!(call["table_address"].is_null(), "{found}");
                if arm {
                    let load_site = if caller == "typed_zero" {
                        0x1288
                    } else {
                        0x12c8
                    };
                    assert_eq!(
                        call["slot_load_sites"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(address)
                            .collect::<Vec<_>>(),
                        [load_site]
                    );
                }
            }
            assert_eq!(found["scan"]["complete"], false, "{found}");
            assert!(
                !found["scan"]["unresolved"].as_array().unwrap().is_empty(),
                "Candidate evidence must retain its unresolved identity: {found}"
            );
        }
        let unmatched = search(client, json!({"within":"unmatched_offset"}));
        assert!(calls(&unmatched).is_empty(), "{unmatched}");
        if !arm {
            let split = search(client, json!({"within":"split_load"}));
            let call = single_call(&split, "split_load", 1, "table_type");
            assert_eq!(address(&call["call_site"]), 0x1447);
            assert_eq!(
                call["slot_load_sites"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(address)
                    .collect::<Vec<_>>(),
                [0x1443]
            );
        }
    });
}

#[test]
#[serial]
fn x86_unknown_vptr_types_and_phi_remain_explicit_candidates() {
    check_type_and_offset_candidates(false);
}

#[test]
#[serial]
fn aarch64_unknown_vptr_types_and_phi_remain_explicit_candidates() {
    check_type_and_offset_candidates(true);
}

#[test]
#[serial]
fn omitted_scope_scans_all_internal_bodies_and_reports_native_failures() {
    with_fixture(false, |client, _| {
        let found = search(client, json!({}));
        assert!(found["scope"].is_null(), "{found}");
        assert_eq!(
            found["scan"]["total_functions"], 21,
            "External functions are not scanned: {found}"
        );
        assert_eq!(found["scan"]["complete"], false, "{found}");
        assert_eq!(found["scan"]["unvisited_functions"], 0, "{found}");
        let failed = found["scan"]["failed_functions"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "{found}");
        assert_eq!(failed[0]["function"], "unmapped", "{found}");
        let names: Vec<_> = calls(&found)
            .iter()
            .map(|call| call["caller"].as_str().unwrap())
            .collect();
        for expected in [
            "known_zero",
            "known_nonzero",
            "known_thunk",
            "typed_zero",
            "mixed_phi",
            "split_load",
        ] {
            assert!(names.contains(&expected), "{found}");
        }
        assert!(!names.contains(&"unrelated_table"), "{found}");
        assert!(!names.contains(&"ordinary_direct_call"), "{found}");

        let failed_scope = search(client, json!({"within":"unmapped"}));
        assert!(calls(&failed_scope).is_empty(), "{failed_scope}");
        assert_eq!(failed_scope["scan"]["complete"], false, "{failed_scope}");
        assert_eq!(failed_scope["scan"]["total_functions"], 1, "{failed_scope}");
        assert_eq!(
            failed_scope["scan"]["successful_functions"], 0,
            "{failed_scope}"
        );
        assert_eq!(
            failed_scope["scan"]["failed_functions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    });
}

#[test]
#[serial]
fn bounded_scan_distinguishes_omitted_calls_and_unvisited_functions() {
    with_fixture(false, |client, _| {
        let full = search(client, json!({"within":"two_calls"}));
        assert_eq!(calls(&full).len(), 2, "{full}");
        assert_eq!(calls(&full)[0]["slot_index"], 0, "{full}");
        assert_eq!(calls(&full)[1]["slot_index"], 1, "{full}");
        let limited = search(client, json!({"within":"two_calls", "limit":1}));
        assert_eq!(calls(&limited), &calls(&full)[..1], "{limited}");
        assert_eq!(limited["scan"]["complete"], false, "{limited}");
        assert_eq!(limited["scan"]["omitted_calls"], 1, "{limited}");
        assert_eq!(limited["scan"]["unvisited_functions"], 0, "{limited}");
        let whole = search(client, json!({"limit":1}));
        assert_eq!(calls(&whole).len(), 1, "{whole}");
        assert_eq!(whole["scan"]["complete"], false, "{whole}");
        assert!(
            whole["scan"]["unvisited_functions"].as_u64().unwrap() > 0,
            "{whole}"
        );
    });
}

#[test]
#[serial]
fn empty_slot_sets_partial_tables_and_request_validation_are_distinct() {
    with_fixture(false, |client, _| {
        let empty = search(
            client,
            json!({"vtable":"other_address_point", "within":"known_zero"}),
        );
        assert_eq!(empty["slots"], json!([]), "{empty}");
        assert_eq!(empty["calls"], json!([]), "{empty}");
        assert_eq!(empty["scan"]["complete"], true, "{empty}");
        let partial = search(
            client,
            json!({"vtable":"0x30f8", "entries":3, "within":"known_zero"}),
        );
        assert_eq!(partial["vtable"]["complete"], false, "{partial}");
        assert_eq!(partial["vtable"]["read_entries"], 1, "{partial}");
        assert_eq!(partial["scan"]["complete"], false, "{partial}");
        let unreadable = search(
            client,
            json!({"vtable":"0x6000", "entries":1, "within":"known_zero"}),
        );
        assert_eq!(unreadable["slots"], json!([]), "{unreadable}");
        assert_eq!(unreadable["scan"]["complete"], false, "{unreadable}");
        let non_entries = search(
            client,
            json!({"vtable":"0x30a0", "entries":3, "within":"known_zero"}),
        );
        assert_eq!(non_entries["slots"], json!([]), "{non_entries}");
        assert_eq!(non_entries["scan"]["complete"], true, "{non_entries}");
        let null_target = search(
            client,
            json!({"function":"zero_target", "vtable":"0x30a8", "entries":1}),
        );
        assert_eq!(
            null_target["slots"],
            json!([]),
            "Null cannot name a function at address zero: {null_target}"
        );
        assert_eq!(null_target["scan"]["complete"], true, "{null_target}");
        for invalid in [
            json!({"entries":0}),
            json!({"entries":65537}),
            json!({"function":"missing_target"}),
            json!({"within":"missing_scope"}),
            json!({"function":"0x6000"}),
            json!({"within":"0x6000"}),
        ] {
            client
                .send_command("find_virtual_callers", Some(request(invalid.clone())))
                .expect_err(&format!("invalid search accepted: {invalid}"));
        }
        let recovered = search(client, json!({"within":"known_zero"}));
        single_call(&recovered, "known_zero", 0, "table_value");
        let interior = search(client, json!({"function":"0x1001", "within":"0x1101"}));
        assert_eq!(
            interior, recovered,
            "Read selectors resolve the containing function"
        );
    });
}

#[test]
#[serial]
fn cli_positional_callee_optional_scope_and_msvc_layout_reach_native_search() {
    with_fixture(false, |client, program| {
        let result = common::ghidra(harness())
            .with_project(common::test_project(), program)
            .args([
                "find",
                "virtual-callers",
                "virtual_target",
                "--vtable",
                "virtual_address_point",
                "--entries",
                "4",
                "--abi",
                "itanium",
                "--within",
                "known_nonzero",
            ])
            .json_format()
            .run();
        result.assert_success();
        let output: Value = result.json();
        assert_eq!(output["data"].as_array().unwrap().len(), 1, "{output}");
        assert_eq!(output["data"][0]["caller"], "known_nonzero", "{output}");
        assert_eq!(
            output["meta"]["scope"]["function"], "known_nonzero",
            "{output}"
        );
        let all = common::ghidra(harness())
            .with_project(common::test_project(), program)
            .args([
                "find",
                "virtual-callers",
                "virtual_target",
                "--vtable",
                "virtual_address_point",
                "--entries",
                "4",
                "--abi",
                "itanium",
                "--limit",
                "1",
            ])
            .json_format()
            .run();
        all.assert_success();
        let all: Value = all.json();
        assert!(all["meta"]["scope"].is_null(), "{all}");
        assert_eq!(all["data"][0]["caller"], "known_zero", "{all}");
        assert!(
            all["meta"]["scan"]["unvisited_functions"].as_u64().unwrap() > 0,
            "{all}"
        );
        let msvc = search(client, json!({"abi":"msvc", "within":"known_nonzero"}));
        single_call(&msvc, "known_nonzero", 1, "table_value");
        assert_eq!(msvc["vtable"]["abi"], "msvc");
    });
}

#[test]
#[serial]
fn saved_database_is_unchanged_and_native_cancel_timeout_recover() {
    with_fixture(false, |client, program| {
        let before = search(client, json!({"within":"known_nonzero"}));
        client
            .script_run_source(
                include_str!("fixtures/virtual_callers/CheckVirtualCallersReadOnly.java"),
                &[],
                &[],
                false,
            )
            .expect("read-only native cancellation and timeout probe");
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(search(client, json!({"within":"known_nonzero"})), before);
    });
}

#[test]
#[serial]
fn dynamic_slots_and_ordinary_callbacks_never_become_offset_zero_candidates() {
    with_fixture(false, |client, _| {
        for function in ["dynamic_slot", "ordinary_callback"] {
            let found = search(client, json!({"within":function}));
            assert!(calls(&found).is_empty(), "{found}");
            assert_eq!(found["scan"]["complete"], false, "{found}");
            assert!(
                !found["scan"]["unresolved"].as_array().unwrap().is_empty(),
                "{found}"
            );
        }
    });
}

#[test]
#[serial]
fn x86_32_bit_pointer_loads_use_four_byte_slot_offsets() {
    require_ghidra!();
    let name = format!("virtual-callers-32-{}", uuid::Uuid::new_v4());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("fixtures/virtual_callers/CreateVirtualCallers32Fixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .expect("create four-byte-pointer virtual calls");
    with_program(&name, |client, _| {
        for (caller, slot, site) in [("known_zero", 0, 0x1105), ("known_nonzero", 1, 0x1145)] {
            let found = search(client, json!({"within":caller, "entries":2}));
            assert_eq!(found["scan"]["complete"], true, "{found}");
            assert_eq!(found["vtable"]["pointer_size"], 4, "{found}");
            assert_eq!(found["vtable"]["entry_size"], 4, "{found}");
            assert_eq!(calls(&found).len(), 1, "{found}");
            let call = &calls(&found)[0];
            assert_eq!(call["evidence"], "table_value", "{found}");
            assert_eq!(call["slot_index"], slot, "{found}");
            assert_eq!(call["slot_offset"], slot * 4, "{found}");
            assert_eq!(address(&call["slot_address"]), 0x3020 + slot * 4);
            assert_eq!(address(&call["call_site"]), site);
        }
    });
}
