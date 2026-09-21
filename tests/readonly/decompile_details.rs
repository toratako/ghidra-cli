//! Native decompiler blocks and recovered switch destinations.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("decompile-control-flow-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("CreateDecompileControlFlowFixture.java"),
                std::slice::from_ref(&name),
                &[],
                false,
            )
            .unwrap();
        name
    })
}

fn command(args: &[&str]) -> crate::common::helpers::GhidraResult {
    ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), fixture())
        .arg("--json")
        .run()
}

fn decompile(name: &str, jump_tables: bool) -> Value {
    let mut args = vec!["decompile", name];
    if jump_tables {
        args.push("--with-jump-tables");
    }
    let result = command(&args);
    result.assert_success();
    result.json::<Value>()[0].clone()
}

#[test]
#[serial]
fn native_blocks_and_opt_in_jump_tables_preserve_recovered_case_mappings() {
    require_ghidra!();
    let checked = std::panic::catch_unwind(|| {
        let straight = decompile("straight", false);
        // The fixture verifies two listing blocks, including an unreachable RET.
        assert_eq!(straight["basic_block_count"], 1, "{straight}");
        assert!(straight.get("jump_tables").is_none(), "{straight}");
        let branching = decompile("branching", true);
        assert!(
            branching["basic_block_count"].as_u64().unwrap() > 1,
            "{branching}"
        );
        assert_eq!(branching["jump_tables"], json!([]), "{branching}");
        assert_eq!(decompile("straight", true)["jump_tables"], json!([]));

        for (name, switch, destinations, labels, default) in [
            (
                "signed_switch",
                "0x0000110c",
                ["0x00001140", "0x00001150", "0x00001160", "0x00001150"],
                [-2_i64, -1, 0, 1],
                "0x00001130",
            ),
            (
                "unsigned_switch",
                "0x0000120e",
                ["0x00001240", "0x00001250", "0x00001260", "0x00001250"],
                [-2147483648_i64, -2147483647, -2147483646, -2147483645],
                "0x00001230",
            ),
        ] {
            let without = decompile(name, false);
            assert!(without.get("jump_tables").is_none(), "{without}");
            let with = decompile(name, true);
            assert_eq!(with["code"], without["code"]);
            assert_eq!(with["basic_block_count"], without["basic_block_count"]);
            assert!(with["basic_block_count"].as_u64().unwrap() > 1, "{with}");
            assert!(with["code"].as_str().unwrap().contains("switch"), "{with}");
            let tables = with["jump_tables"].as_array().unwrap();
            assert_eq!(tables.len(), 1, "{with}");
            assert_eq!(tables[0]["switch_address"], switch, "{with}");
            let cases = tables[0]["cases"].as_array().unwrap();
            for (label, destination) in labels.into_iter().zip(destinations) {
                let case = cases
                    .iter()
                    .find(|case| case["label"] == label)
                    .unwrap_or_else(|| panic!("Missing case {label}: {with}"));
                assert_eq!(case["address"], destination, "{with}");
                assert_eq!(case["is_default"], false, "{with}");
            }
            let defaults: Vec<_> = cases
                .iter()
                .filter(|case| case["is_default"] == true)
                .collect();
            assert_eq!(defaults.len(), 1, "{with}");
            assert_eq!(defaults[0]["address"], default, "{with}");
            assert!(
                defaults[0]["label"].is_null() || defaults[0]["label"] == -1160664095_i64,
                "{with}"
            );
            assert_eq!(cases.len(), 5, "{with}");

            let c = command(&["decompile", name, "--with-jump-tables", "--format", "c"]);
            c.assert_success();
            assert_eq!(c.stdout, with["code"].as_str().unwrap());
            for format in ["compact", "full"] {
                command(&["decompile", name, "--with-jump-tables", "--format", format])
                    .assert_success()
                    .assert_stdout_contains("Basic blocks (decompiler):")
                    .assert_stdout_contains(&format!("Switch at {switch}:"))
                    .assert_stdout_contains(&format!("default -> {default}"));
            }
        }
    });
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}
