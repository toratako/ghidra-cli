use super::{deletion::create_symbol_fixture_program, harness, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;
use std::collections::HashSet;

#[test]
#[serial]
fn symbol_list_includes_non_address_symbols_and_pages_without_duplicates() {
    require_ghidra!();
    let program = create_symbol_fixture_program();
    let client = harness().client().unwrap();
    let checked = std::panic::catch_unwind(|| {
        client
            .script_run_source(
                include_str!("../fixtures/symbols/CreateAllSymbolKinds.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let listed = client.symbol_list(None, None, None).unwrap();
        let rows = listed["symbols"].as_array().unwrap();
        let ids: HashSet<_> = rows.iter().map(|row| row["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), rows.len(), "{listed}");
        for name in [
            "list_scope",
            "list_class",
            "list_label",
            "list_function",
            "list_parameter",
            "list_local",
            "list_library",
            "list_external",
            "0x1030",
        ] {
            let found = client.symbol_get(name).unwrap();
            assert_eq!(found["symbols"].as_array().unwrap().len(), 1, "{found}");
            assert!(
                rows.contains(&found["symbols"][0]),
                "Missing {name}: {listed}"
            );
        }
        assert_eq!(rows.len(), 9, "{listed}");
        // The first phase retains the address iterator's order and dynamic labels.
        let memory_names: Vec<_> = rows
            .iter()
            .filter(|row| row["is_default_address_space"] == true)
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        assert_eq!(&memory_names[..2], &["list_label", "list_function"]);
        let filtered = client.symbol_list(None, Some("LIST_"), None).unwrap();
        let filtered_rows = filtered["symbols"].as_array().unwrap();
        assert_eq!(filtered_rows.len(), 8, "{filtered}");
        for (filter, expected) in [(None, rows), (Some("LIST_"), filtered_rows)] {
            let mut pages: Vec<Value> = Vec::new();
            for offset in (0..expected.len()).step_by(2) {
                let page = client.symbol_list(Some(2), filter, Some(offset)).unwrap();
                pages.extend(page["symbols"].as_array().unwrap().iter().cloned());
            }
            assert_eq!(&pages, expected);
            assert_eq!(
                client
                    .symbol_list(Some(2), filter, Some(expected.len()))
                    .unwrap()["symbols"],
                json!([])
            );
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(error) = checked {
        std::panic::resume_unwind(error);
    }
}
