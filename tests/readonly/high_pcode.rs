//! Native High IR identity, phi edges, operand roles, and bounded projections.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::Value;
use serial_test::serial;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("high-pcode-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("CreateHighPcodeFixture.java"),
                std::slice::from_ref(&name),
                &[],
                false,
            )
            .unwrap();
        name
    })
}

fn high(name: &str, extra: &[&str]) -> Value {
    let result = ghidra(harness())
        .args(["pcode", "function", name, "--high"])
        .args(extra.iter().copied())
        .with_project(test_project(), fixture())
        .arg("--json")
        .run();
    result.assert_success();
    result.data()
}

fn rows<'a>(result: &'a Value, field: &str) -> &'a [Value] {
    result[field].as_array().unwrap().as_slice()
}

fn id(row: &Value) -> &str {
    row["id"].as_str().unwrap()
}

fn by_id<'a>(result: &'a Value, field: &str) -> HashMap<&'a str, &'a Value> {
    rows(result, field)
        .iter()
        .map(|row| (id(row), row))
        .collect()
}

fn returned_relationships(result: &Value) -> usize {
    let mut definitions = HashSet::new();
    let mut count = rows(result, "edges").len();
    for operation in rows(result, "operations") {
        count += rows(operation, "inputs").len();
        count += usize::from(operation["block"]["id"].is_string());
        if let Some(value) = operation["output"]["id"].as_str() {
            definitions.insert((id(operation), value));
        }
    }
    for value in rows(result, "values") {
        count += usize::from(value["high_variable"]["id"].is_string());
        if let Some(operation) = value["definition"]["id"].as_str() {
            definitions.insert((operation, id(value)));
        }
    }
    for variable in rows(result, "high_variables") {
        count += usize::from(variable["representative"]["id"].is_string());
        count += usize::from(variable["symbol"]["id"].is_string());
    }
    count + definitions.len()
}

fn validate_complete(result: &Value) {
    assert_eq!(result["representation"], "high_pcode");
    assert_eq!(result["id_scope"], "result");
    assert_eq!(result["completion"]["scan"]["complete"], true);
    assert_eq!(result["completion"]["output"]["complete"], true, "{result}");
    assert_eq!(
        result["completion"]["output"]["edges"],
        returned_relationships(result),
        "{result}"
    );
    let operations = by_id(result, "operations");
    let values = by_id(result, "values");
    let blocks = by_id(result, "blocks");
    let edges = by_id(result, "edges");
    for operation in operations.values() {
        let block = blocks[operation["block"]["id"].as_str().unwrap()];
        let order = operation["block_order"].as_u64().unwrap() as usize;
        assert_eq!(block["operations"][order], operation["id"]);
        assert!(operation["instruction_address"].as_str().is_some());
        assert!(operation["sequence"].as_i64().is_some());
        if operation["output"]["state"] == "included" {
            let output = values[operation["output"]["id"].as_str().unwrap()];
            assert_eq!(output["definition"]["id"], operation["id"]);
        }
        for (slot, input) in rows(operation, "inputs").iter().enumerate() {
            assert_eq!(input["slot"], slot);
            if input["kind"] == "value" {
                let value = values[input["value"]["id"].as_str().unwrap()];
                assert!(rows(value, "uses").iter().any(|usage| {
                    usage["operation"] == operation["id"] && usage["slot"] == slot
                }));
                assert_eq!(value["uses_status"]["complete"], true);
            }
            if operation["mnemonic"] == "MULTIEQUAL" {
                let edge = edges[input["incoming_edge"]["id"].as_str().unwrap()];
                assert_eq!(edge["target"]["id"], operation["block"]["id"]);
                assert_eq!(edge["target_in_index"], slot);
                assert_eq!(block["incoming_edges"][slot], edge["id"]);
            }
        }
    }
    for edge in edges.values() {
        let source = blocks[edge["source"]["id"].as_str().unwrap()];
        let target = blocks[edge["target"]["id"].as_str().unwrap()];
        assert_eq!(
            source["outgoing_edges"][edge["source_out_index"].as_u64().unwrap() as usize],
            edge["id"]
        );
        assert_eq!(
            target["incoming_edges"][edge["target_in_index"].as_u64().unwrap() as usize],
            edge["id"]
        );
    }
}

fn restores_program(check: impl FnOnce()) {
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
fn high_pcode_preserves_ssa_identity_repeated_slots_and_loop_phi_edges() {
    require_ghidra!();
    restores_program(|| {
        let square = high("square", &[]);
        validate_complete(&square);
        let multiply = rows(&square, "operations")
            .iter()
            .find(|op| op["mnemonic"] == "INT_MULT")
            .unwrap();
        assert_eq!(
            multiply["inputs"][0]["value"],
            multiply["inputs"][1]["value"]
        );
        let values = by_id(&square, "values");
        let input = values[multiply["inputs"][0]["value"]["id"].as_str().unwrap()];
        let slots: Vec<_> = rows(input, "uses")
            .iter()
            .filter(|usage| usage["operation"] == multiply["id"])
            .map(|usage| usage["slot"].as_u64().unwrap())
            .collect();
        assert_eq!(slots, vec![0, 1]);

        let loops = high("sum_loop", &[]);
        validate_complete(&loops);
        let operations = by_id(&loops, "operations");
        let values = by_id(&loops, "values");
        let phis: Vec<_> = operations
            .values()
            .filter(|op| op["mnemonic"] == "MULTIEQUAL")
            .collect();
        assert!(phis.len() >= 2, "{loops}");
        // A phi depends on an update that directly depends on that same phi output.
        assert!(
            phis.iter().any(|phi| {
                rows(phi, "inputs").iter().any(|input| {
                    let value = values[input["value"]["id"].as_str().unwrap()];
                    let Some(definition) = value["definition"]["id"].as_str() else {
                        return false;
                    };
                    rows(operations[definition], "inputs")
                        .iter()
                        .any(|operand| operand["value"]["id"] == phi["output"]["id"])
                })
            }),
            "{loops}"
        );
        let mut storages: HashMap<(&str, &str, u64), HashSet<&str>> = HashMap::new();
        for value in values.values().filter(|v| v["type"] == "register") {
            storages
                .entry((
                    value["space"].as_str().unwrap(),
                    value["offset"].as_str().unwrap(),
                    value["size"].as_u64().unwrap(),
                ))
                .or_default()
                .insert(id(value));
        }
        assert!(storages.values().any(|ids| ids.len() > 1), "{loops}");
        let repeated = high("sum_loop", &[]);
        assert_ne!(loops["result_id"], repeated["result_id"]);
    });
}

#[test]
#[serial]
fn high_pcode_distinguishes_memory_operands_calls_and_partial_symbols() {
    require_ghidra!();
    restores_program(|| {
        let memory = high("memory_call", &[]);
        validate_complete(&memory);
        for mnemonic in ["LOAD", "STORE", "CALL"] {
            assert!(
                rows(&memory, "operations")
                    .iter()
                    .any(|op| op["mnemonic"] == mnemonic),
                "{memory}"
            );
        }
        for op in rows(&memory, "operations") {
            if op["mnemonic"] == "LOAD" || op["mnemonic"] == "STORE" {
                assert_eq!(op["inputs"][0]["kind"], "address_space");
                assert_eq!(op["inputs"][0]["state"], "resolved");
                assert_eq!(op["inputs"][0]["space"], "ram");
                assert_eq!(op["inputs"][1]["role"], "address");
                if op["mnemonic"] == "STORE" {
                    assert_eq!(op["inputs"][2]["role"], "stored_value");
                }
            }
            if op["mnemonic"] == "CALL" {
                assert_eq!(op["inputs"][0]["role"], "call_target");
                assert_eq!(op["inputs"][1]["role"], "argument");
            }
        }
        let partials = high("pair_sum", &[]);
        validate_complete(&partials);
        let variables = by_id(&partials, "high_variables");
        let parameter = rows(&partials, "symbols")
            .iter()
            .find(|symbol| symbol["name"] == "value")
            .unwrap();
        assert_eq!(parameter["kind"], "parameter");
        let offsets: HashSet<_> = rows(parameter, "high_variables")
            .iter()
            .map(|id| variables[id.as_str().unwrap()]["symbol_offset"].clone())
            .collect();
        assert!(
            offsets.contains(&Value::from(0)) && offsets.contains(&Value::from(4)),
            "{partials}"
        );
        let indirect = high("indirect_local", &[]);
        validate_complete(&indirect);
        let operation = rows(&indirect, "operations")
            .iter()
            .find(|op| op["mnemonic"] == "INDIRECT")
            .unwrap_or_else(|| panic!("{indirect}"));
        let reference = &operation["inputs"][1];
        assert_eq!(reference["kind"], "operation");
        // The decompiler's IOP relation is decoded as a constant sequence key by
        // the Java API. Preserve that storage while distinguishing its meaning.
        assert_eq!(reference["encoding"]["space"], "const");
        assert!(reference.get("value").is_none());
        assert_eq!(reference["operation"]["state"], "included");
        assert_eq!(
            by_id(&indirect, "operations")[reference["operation"]["id"].as_str().unwrap()]
                ["mnemonic"],
            "CALL"
        );
        let equate = high("equate_bias", &[]);
        validate_complete(&equate);
        let bias = rows(&equate, "symbols")
            .iter()
            .find(|symbol| symbol["name"] == "BIAS")
            .unwrap_or_else(|| panic!("{equate}"));
        assert_eq!(bias["kind"], "equate");
    });
}

#[test]
#[serial]
fn high_pcode_output_limits_preserve_slots_and_report_omitted_relations() {
    require_ghidra!();
    restores_program(|| {
        let full = high("sum_loop", &[]);
        for (nodes, edges) in [(1, 4000), (1000, 1), (12, 15)] {
            let limited = high(
                "sum_loop",
                &[
                    "--max-nodes",
                    &nodes.to_string(),
                    "--max-edges",
                    &edges.to_string(),
                ],
            );
            assert_eq!(limited["completion"]["scan"], full["completion"]["scan"]);
            assert_eq!(limited["completion"]["output"]["complete"], false);
            assert!(limited["completion"]["output"]["nodes"].as_u64().unwrap() <= nodes);
            assert!(limited["completion"]["output"]["edges"].as_u64().unwrap() <= edges);
            assert_eq!(
                limited["completion"]["output"]["edges"],
                returned_relationships(&limited),
                "{limited}"
            );
            let originals = by_id(&full, "operations");
            for op in rows(&limited, "operations") {
                assert_eq!(
                    rows(op, "inputs").len(),
                    rows(originals[id(op)], "inputs").len()
                );
                for (slot, input) in rows(op, "inputs").iter().enumerate() {
                    assert_eq!(input["slot"], slot);
                }
            }
            for value in rows(&limited, "values") {
                let expected = rows(by_id(&full, "values")[id(value)], "uses").len();
                assert_eq!(value["uses_status"]["total"], expected);
                assert_eq!(
                    value["uses_status"]["complete"],
                    rows(value, "uses").len() == expected
                );
            }
            let encoded = limited.to_string();
            assert!(encoded.len() < full.to_string().len(), "{limited}");
            assert!(!encoded.contains("\"state\":\"unresolved\""), "{limited}");
        }
        // Native decompilation and full scans remain usable after output limits.
        validate_complete(&high("sum_loop", &[]));
    });
}
