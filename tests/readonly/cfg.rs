//! Instruction CFGs retain Listing blocks, body boundaries and unresolved transfers.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

fn command(program: &str, function: &str, flags: &[&str]) -> Value {
    let result = ghidra(harness())
        .args(["graph", "cfg", function])
        .args(flags.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run();
    result.assert_success();
    result.data()
}

fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().unwrap()
}

fn at<'a>(value: &'a Value, key: &str, site: &str) -> &'a Value {
    rows(value, key)
        .iter()
        .find(|row| row["site"] == site)
        .unwrap_or_else(|| panic!("Missing {key} at {site}: {value}"))
}

fn check_references(value: &Value) {
    let nodes = rows(value, "nodes");
    for key in ["edges", "calls", "boundaries"] {
        for row in rows(value, key) {
            assert!(
                nodes.iter().any(|node| node["id"] == row["from"]),
                "{value}"
            );
            if !row["to"].is_null() {
                assert!(nodes.iter().any(|node| node["id"] == row["to"]), "{value}");
                assert_eq!(row["target_state"], "included", "{value}");
            }
        }
    }
}

#[test]
#[serial]
fn instruction_cfg_preserves_flows_body_boundaries_and_limits() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("instruction-cfg-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCfgFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    let checked = std::panic::catch_unwind(|| {
        let diamond = command(&program, "diamond", &[]);
        assert_eq!(diamond["representation"], "instruction_cfg");
        assert_eq!(diamond["id_scope"], "result");
        assert_eq!(diamond["function"], "diamond");
        assert_eq!(diamond["address"], "0x00001000");
        assert_eq!(
            diamond["completion"]["output"]["complete"], true,
            "{diamond}"
        );
        assert_eq!(rows(&diamond, "nodes").len(), 4, "{diamond}");
        assert_eq!(rows(&diamond, "edges").len(), 4, "{diamond}");
        assert_eq!(at(&diamond, "boundaries", "0x00001013")["kind"], "terminal");
        check_references(&diamond);
        let join = rows(&diamond, "nodes")
            .iter()
            .find(|node| node["entries"] == json!(["0x00001010"]))
            .unwrap();
        assert_eq!(
            rows(&diamond, "edges")
                .iter()
                .filter(|edge| edge["to"] == join["id"])
                .count(),
            2
        );
        let looping = command(&program, "looping", &[]);
        assert_eq!(at(&looping, "edges", "0x00001106")["target"], "0x00001102");
        check_references(&looping);

        let caller = command(&program, "caller", &[]);
        assert_eq!(rows(&caller, "nodes").len(), 1, "{caller}");
        assert_eq!(rows(&caller, "calls").len(), 2, "{caller}");
        assert_eq!(
            at(&caller, "calls", "0x00001200")["target_state"],
            "unresolved"
        );
        assert_eq!(at(&caller, "calls", "0x00001207")["target"], "0x00001400");
        assert_eq!(
            at(&caller, "calls", "0x00001207")["target_state"],
            "outside_function"
        );
        assert_eq!(caller["completion"]["scan"]["complete"], true);
        let pointer = command(&program, "pointer_caller", &[]);
        assert_eq!(at(&pointer, "calls", "0x00001250")["target"], "0x00001400");
        assert_eq!(rows(&pointer, "calls").len(), 1, "{pointer}");
        assert_eq!(rows(&pointer, "nodes").len(), 1, "{pointer}");
        let interior_pointer = command(&program, "interior_pointer_caller", &[]);
        let interior_call = at(&interior_pointer, "calls", "0x00001260");
        assert_eq!(
            interior_call["target_state"], "unresolved",
            "{interior_pointer}"
        );
        assert!(interior_call["target"].is_null(), "{interior_pointer}");
        let pointer_graph = client
            .graph_callees("pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(pointer_graph["count"], 1, "{pointer_graph}");
        assert_eq!(pointer_graph["calls"][0]["callee_address"], "0x00001400");
        let interior_graph = client
            .graph_callees("interior_pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(interior_graph["count"], 1, "{interior_graph}");
        assert_eq!(interior_graph["calls"][0]["callee_address"], "0x00002001");
        assert!(interior_graph["calls"][0]["callee"].is_null());
        let override_graph = client
            .graph_callees("overridden_pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(override_graph["count"], 1, "{override_graph}");
        assert_eq!(override_graph["calls"][0]["callee_address"], "0x00001440");
        for (function, site, target) in [
            ("overridden_pointer_caller", "0x00001270", "0x00001440"),
            ("inactive_pointer_caller", "0x00001290", "0x00001400"),
        ] {
            let cfg = command(&program, function, &[]);
            assert_eq!(rows(&cfg, "calls").len(), 1, "{cfg}");
            assert_eq!(at(&cfg, "calls", site)["target"], target, "{cfg}");
        }
        assert!(rows(&command(&program, "inert_call_override", &[]), "calls").is_empty());
        assert_eq!(
            client.graph_callers("unreachable", Some(1), None).unwrap()["count"],
            0
        );
        let external = command(&program, "external_caller", &[]);
        assert_eq!(
            at(&external, "calls", "0x00001280")["target_state"],
            "external"
        );

        let outside = command(&program, "outside", &[]);
        let exit = at(&outside, "edges", "0x00001300");
        assert_eq!(exit["target_state"], "outside_function");
        assert_eq!(exit["body_crossing"], "exit");
        assert!(exit["to"].is_null());
        let missing = command(&program, "missing", &[]);
        assert_eq!(
            at(&missing, "edges", "0x00001350")["target_state"],
            "missing_instruction"
        );
        let unresolved = command(&program, "unresolved", &[]);
        let unknown = at(&unresolved, "boundaries", "0x00001380");
        assert_eq!(unknown["kind"], "unresolved");
        assert_eq!(unknown["target_state"], "unresolved");
        assert!(unknown["target"].is_null());
        assert_eq!(unresolved["completion"]["scan"]["complete"], true);
        for (function, site) in [
            ("interior_pointer_jump", "0x000013a0"),
            ("scalar_jump", "0x000013c0"),
            ("inert_call_on_jump", "0x00001770"),
        ] {
            let cfg = command(&program, function, &[]);
            assert!(rows(&cfg, "edges").is_empty(), "{cfg}");
            let unknown = at(&cfg, "boundaries", site);
            assert_eq!(unknown["target_state"], "unresolved", "{cfg}");
            assert!(unknown["target"].is_null(), "{cfg}");
        }

        let disjoint = command(&program, "disjoint", &[]);
        assert_eq!(rows(&disjoint, "nodes").len(), 1, "{disjoint}");
        assert_eq!(
            disjoint["nodes"][0]["ranges"],
            json!([{ "start":"0x00001500", "end":"0x00001503" }])
        );
        assert_eq!(
            disjoint["nodes"][0]["body_intersection"],
            disjoint["body_ranges"]
        );
        assert_eq!(
            at(&disjoint, "boundaries", "0x00001500")["body_crossing"],
            "exit"
        );
        assert_eq!(
            at(&disjoint, "boundaries", "0x00001501")["body_crossing"],
            "entry"
        );
        assert_eq!(
            rows(&command(&program, "unreachable", &[]), "nodes").len(),
            2
        );

        let branch = command(&program, "override_branch", &[]);
        assert!(rows(&branch, "calls").is_empty(), "{branch}");
        assert_eq!(at(&branch, "edges", "0x00001700")["target"], "0x00001400");
        let terminal = command(&program, "terminal_call", &[]);
        assert_eq!(at(&terminal, "calls", "0x00001720")["target"], "0x00001400");
        assert_eq!(
            at(&terminal, "boundaries", "0x00001720")["kind"],
            "terminal"
        );
        let redirected = command(&program, "redirected", &[]);
        assert!(
            rows(&redirected, "edges")
                .iter()
                .any(|edge| edge["site"] == "0x00001740" && edge["target"] == "0x00001750"),
            "{redirected}"
        );

        let limited = command(&program, "diamond", &["--max-nodes", "1"]);
        assert_eq!(rows(&limited, "nodes").len(), 1);
        assert_eq!(limited["completion"]["output"]["complete"], false);
        assert_eq!(
            limited["completion"]["output"]["reasons"],
            json!(["max_nodes"])
        );
        assert!(limited["completion"]["collections"]["nodes"]
            .get("total")
            .is_none());
        assert!(rows(&limited, "edges")
            .iter()
            .all(|edge| edge["target_state"] == "omitted"));
        check_references(&limited);
        let limited = command(&program, "caller", &["--max-edges", "1"]);
        assert_eq!(limited["completion"]["output"]["edges"], 1);
        assert_eq!(
            limited["completion"]["output"]["reasons"],
            json!(["max_edges"])
        );
        assert_eq!(limited["nodes"][0]["flows_complete"], false);
        check_references(&limited);
        let exact = command(
            &program,
            "target",
            &["--max-nodes", "1", "--max-edges", "1"],
        );
        assert_eq!(exact["completion"]["output"]["complete"], true, "{exact}");
        // Exercise shared wire validation, also used by High P-code: the typed
        // CLI cannot send these malformed JSON budgets.
        for (key, value) in [
            ("max_nodes", json!(0)),
            ("max_edges", json!(1.5)),
            ("max_nodes", json!(2_147_483_648_u64)),
            ("max_edges", json!("2")),
        ] {
            let mut args = json!({"function":"target"});
            args[key] = value;
            let error = client.send_command("graph_cfg", Some(args)).unwrap_err();
            assert!(error.to_string().contains(key), "{error}");
        }
        assert_eq!(
            command(&program, "target", &[])["completion"]["scan"]["complete"],
            true
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[serial]
fn instruction_cfg_keeps_delay_slot_outside_body_and_branch_origin() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("instruction-cfg-mips-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCfgFixture.java"),
            &[program.clone(), "mips".into()],
            &[],
            false,
        )
        .unwrap();
    let checked = std::panic::catch_unwind(|| {
        let cfg = command(&program, "delay", &[]);
        let first = rows(&cfg, "nodes")
            .iter()
            .find(|node| node["entries"] == json!(["0x00001000"]))
            .unwrap();
        assert_eq!(
            first["ranges"],
            json!([{ "start":"0x00001000", "end":"0x00001007" }])
        );
        assert_eq!(
            first["body_intersection"],
            json!([{ "start":"0x00001000", "end":"0x00001003" }])
        );
        let delayed = rows(&cfg, "boundaries")
            .iter()
            .find(|row| row["kind"] == "delay_slot")
            .unwrap();
        assert_eq!(delayed["site"], "0x00001000");
        assert_eq!(delayed["target"], "0x00001004");
        assert_eq!(delayed["body_crossing"], "exit");
        let successors: Vec<_> = rows(&cfg, "edges")
            .iter()
            .filter(|edge| edge["from"] == first["id"])
            .collect();
        assert_eq!(successors.len(), 2, "{cfg}");
        for target in ["0x00001008", "0x00001010"] {
            let edge = successors
                .iter()
                .find(|edge| edge["target"] == target)
                .unwrap();
            assert_eq!(edge["site"], "0x00001000", "{cfg}");
        }
        assert_eq!(cfg["completion"]["scan"]["complete"], true);
        check_references(&cfg);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[serial]
fn instruction_cfg_excludes_external_targets_replaced_by_jump_overrides() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("instruction-cfg-jump-override-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCfgFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    let checked = std::panic::catch_unwind(|| {
        let original = command(&program, "external_jump", &[]);
        assert_eq!(rows(&original, "edges").len(), 1, "{original}");
        assert_eq!(original["edges"][0]["target_state"], "external");
        let overridden = command(&program, "overridden_external_jump", &[]);
        assert_eq!(rows(&overridden, "edges").len(), 1, "{overridden}");
        assert_eq!(overridden["edges"][0]["target"], "0x00001440");
        assert_eq!(overridden["edges"][0]["target_state"], "outside_function");
        check_references(&overridden);
        let bounded = command(&program, "overridden_external_jump", &["--max-edges", "1"]);
        assert_eq!(bounded["edges"], overridden["edges"], "{bounded}");
        assert_eq!(bounded["completion"]["output"]["complete"], true);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}

#[test]
#[serial]
fn instruction_cfg_does_not_resolve_unknown_pointer_table_indices() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("instruction-cfg-pointer-index-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCfgFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    let checked = std::panic::catch_unwind(|| {
        let indexed = command(&program, "indexed_pointer_caller", &[]);
        assert_eq!(rows(&indexed, "calls").len(), 1, "{indexed}");
        assert_eq!(
            indexed["calls"][0]["target_state"], "unresolved",
            "{indexed}"
        );
        assert!(indexed["calls"][0]["target"].is_null(), "{indexed}");
        let outgoing = client
            .graph_callees("indexed_pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(outgoing["count"], 0, "{outgoing}");
        let added_base = command(&program, "indexed_base_pointer_caller", &[]);
        assert_eq!(
            added_base["calls"][0]["target_state"], "unresolved",
            "{added_base}"
        );
        let outgoing = client
            .graph_callees("indexed_base_pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(outgoing["count"], 0, "{outgoing}");
        let incoming = client.graph_callers("target", Some(1), None).unwrap();
        assert!(
            rows(&incoming, "calls")
                .iter()
                .all(|call| call["caller"] != "indexed_pointer_caller"
                    && call["caller"] != "indexed_base_pointer_caller"),
            "{incoming}"
        );
        let graph = client.graph_calls(None).unwrap();
        assert!(
            rows(&graph, "edges")
                .iter()
                .all(|edge| edge["caller"] != "indexed_pointer_caller"
                    && edge["caller"] != "indexed_base_pointer_caller"),
            "{graph}"
        );
        let fixed = command(&program, "pointer_caller", &[]);
        assert_eq!(fixed["calls"][0]["target"], "0x00001400", "{fixed}");
        let resolved = command(&program, "resolved_indexed_caller", &[]);
        assert_eq!(rows(&resolved, "calls").len(), 1, "{resolved}");
        assert_eq!(resolved["calls"][0]["target"], "0x00001440", "{resolved}");
        let outgoing = client
            .graph_callees("resolved_indexed_caller", Some(1), None)
            .unwrap();
        assert_eq!(outgoing["count"], 1, "{outgoing}");
        assert_eq!(
            outgoing["calls"][0]["destination"],
            resolved["calls"][0]["target"]
        );
        let incoming = client
            .graph_callers("override_target", Some(1), None)
            .unwrap();
        assert!(
            rows(&incoming, "calls").contains(&outgoing["calls"][0]),
            "{incoming}"
        );
        assert_eq!(fixed["modification"], indexed["modification"]);
        assert_eq!(resolved["modification"], indexed["modification"]);
        let recorded = client
            .graph_callees("recorded_pointer_caller", Some(1), None)
            .unwrap();
        assert_eq!(recorded["count"], 1, "{recorded}");
        assert_eq!(
            recorded["calls"][0]["destination"], "0x00001400",
            "{recorded}"
        );
        let slot = client
            .graph_callees("recorded_indexed_slot_caller", Some(1), None)
            .unwrap();
        assert_eq!(slot["count"], 1, "{slot}");
        assert_eq!(slot["calls"][0]["destination"], "0x00001440", "{slot}");
        client
            .script_run_source(
                include_str!("../fixtures/readonly/CheckCallQueriesReadOnly.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}
