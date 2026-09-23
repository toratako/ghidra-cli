//! Native token-to-instruction provenance and alignment with the exact returned C.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::Value;
use serial_test::serial;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("decompile-addresses-{}", uuid::Uuid::new_v4());
        harness()
            .client()
            .unwrap()
            .script_run_source(
                include_str!("CreateDecompileAddressesFixture.java"),
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

fn decompile(name: &str, with_addresses: bool) -> Value {
    let mut args = vec!["decompile", name];
    if with_addresses {
        args.push("--with-addresses");
    }
    let result = command(&args);
    result.assert_success();
    result.data()
}

fn mappings(result: &Value) -> BTreeMap<usize, Vec<&str>> {
    let code = result["code"].as_str().unwrap();
    let lines: Vec<_> = code.lines().collect();
    let mut previous = 0;
    result["line_addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let line = row["line"].as_u64().unwrap() as usize;
            assert!(line > previous && line <= lines.len(), "{result}");
            previous = line;
            let addresses: Vec<_> = row["addresses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|address| address.as_str().unwrap())
                .collect();
            assert!(!addresses.is_empty(), "{result}");
            // All fixture addresses have equal-width canonical offsets in one space.
            assert!(
                addresses.windows(2).all(|pair| pair[0] < pair[1]),
                "{result}"
            );
            (line, addresses)
        })
        .collect()
}

fn line_containing(result: &Value, needle: &str) -> usize {
    let matches: Vec<_> = result["code"]
        .as_str()
        .unwrap()
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(needle))
        .map(|(index, _)| index + 1)
        .collect();
    assert_eq!(matches.len(), 1, "Expected one {needle:?} line: {result}");
    matches[0]
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
fn native_line_addresses_preserve_code_and_distinguish_call_sites_from_callees() {
    require_ghidra!();
    restores_program(|| {
        let plain = decompile("address-caller", false);
        assert!(plain.get("line_addresses").is_none(), "{plain}");
        let with = decompile("address-caller", true);
        assert_eq!(with["code"], plain["code"]);
        let code = with["code"].as_str().unwrap();
        assert!(code.starts_with('\n'), "{code}");
        assert!(code.contains("address_caller("), "{code}");
        assert!(code.contains("Japanese 日本語\n"), "{code}");
        assert!(code.contains("second comment line"), "{code}");

        let mapped = mappings(&with);
        let call_line = line_containing(&with, "address_sink(");
        assert_eq!(mapped[&call_line], ["0x00001004"], "{with}");
        assert_eq!(
            mapped[&line_containing(&with, "return ")],
            ["0x0000100c", "0x0000100f"],
            "{with}"
        );
        // Blank lines, declarations, braces, and the address-bearing native comment
        // token must not acquire a guessed nearest/parent address.
        assert_eq!(mapped.len(), 2, "{with}");

        let raw = command(&["decompile", "address-caller", "--format", "c"]);
        raw.assert_success();
        assert_eq!(raw.stdout, code);
        let annotated = command(&[
            "decompile",
            "address-caller",
            "--with-addresses",
            "--format",
            "c",
        ]);
        annotated.assert_success();
        let expected: String = code
            .split_inclusive('\n')
            .enumerate()
            .map(|(index, line)| match mapped.get(&(index + 1)) {
                Some(addresses) => format!(
                    "{} // @ {}\n",
                    line.strip_suffix('\n').unwrap(),
                    addresses.join(", ")
                ),
                None => line.to_owned(),
            })
            .collect();
        assert_eq!(annotated.stdout, expected);
    });
}

#[test]
#[serial]
fn wrapped_call_keeps_multiple_addresses_and_reuses_its_site_on_distinct_lines() {
    require_ghidra!();
    restores_program(|| {
        let plain = decompile("wrapped_arguments", false);
        let with = decompile("wrapped_arguments", true);
        assert_eq!(with["code"], plain["code"]);
        let mapped = mappings(&with);
        let call_line = line_containing(
            &with,
            "address_sink_with_eight_arguments_and_a_wrapped_call",
        );
        assert!(mapped[&call_line].contains(&"0x0000121b"), "{with}");
        let call_lines: Vec<_> = mapped
            .iter()
            .filter(|(_, addresses)| addresses.contains(&"0x0000121b"))
            .map(|(line, _)| *line)
            .collect();
        assert!(call_lines.len() >= 2, "{with}");
        assert!(
            mapped.values().any(|addresses| addresses.len() > 1),
            "{with}"
        );
        assert_eq!(
            mapped[&line_containing(&with, "return ")],
            ["0x00001223"],
            "{with}"
        );
        assert!(
            mapped
                .values()
                .flatten()
                .all(|address| address.starts_with("0x000012")),
            "{with}"
        );
    });
}

#[test]
#[serial]
fn line_addresses_preserve_disjoint_body_locations_and_overlay_spaces() {
    require_ghidra!();
    restores_program(|| {
        for (name, expected) in [
            ("disjoint_sum", ["0x00001604", "0x00001680"]),
            (
                "overlay_sum",
                ["address_overlay:0x00001004", "address_overlay:0x00001007"],
            ),
        ] {
            let plain = decompile(name, false);
            let with = decompile(name, true);
            assert_eq!(with["code"], plain["code"]);
            let mapped = mappings(&with);
            assert_eq!(mapped.len(), 1, "{with}");
            assert_eq!(
                mapped[&line_containing(&with, "return ")],
                expected,
                "{with}"
            );
        }
    });
}
