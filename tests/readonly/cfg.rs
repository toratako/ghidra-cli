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
            include_str!("CreateCfgFixture.java"),
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
        assert_eq!(rows(&pointer, "nodes").len(), 1, "{pointer}");
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
            include_str!("CreateCfgFixture.java"),
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
