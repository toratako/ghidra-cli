use super::{harness, TEST_PROGRAM};
use crate::common::{
    get_function_addresses, ghidra,
    helpers::matches_function_name,
    schemas::{Function, Validate},
    test_project,
};
use serial_test::serial;

/// Known exported function names from sample_binary
const KNOWN_FUNCTIONS: &[&str] = &[
    "add_numbers",
    "multiply",
    "factorial",
    "fibonacci",
    "process_string",
    "xor_encrypt",
    "simple_hash",
    "init_struct",
    "main",
];

#[test]
#[serial]
fn test_function_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(!functions.is_empty(), "Function list should not be empty");

    for func in &functions {
        func.assert_valid();
    }

    let has_main = functions.iter().any(|f| f.name == "main");
    assert!(has_main, "Should contain main function");
}

#[test]
#[serial]
fn test_function_list_contains_expected_functions() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

    // main must always be present
    assert!(
        names.iter().any(|n| matches_function_name(n, "main")),
        "Should have main function. Found: {:?}",
        &names[..names.len().min(20)]
    );

    // Binary should have many functions (stdlib + user code)
    assert!(
        functions.len() >= 5,
        "Should have at least 5 functions, found {}",
        functions.len()
    );

    for expected in KNOWN_FUNCTIONS {
        assert!(
            names
                .iter()
                .any(|name| matches_function_name(name, expected)),
            "Missing fixture function: {expected}"
        );
    }
}

#[test]
#[serial]
fn test_function_list_limit() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("3")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        functions.len() <= 3,
        "Limit 3 should return at most 3 functions, got {}",
        functions.len()
    );
}

#[test]
#[serial]
fn test_function_list_filter() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("name~main")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter 'name~main' should match at least one function"
    );

    // The filter must actually filter: EVERY returned row matches, not just one
    // (a bare-word filter used to silently dump the whole unfiltered dataset).
    assert!(
        functions
            .iter()
            .all(|f| f.name.to_lowercase().contains("main")),
        "All filtered results should contain 'main'. Got: {:?}",
        functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
#[serial]
fn test_function_list_address_range_filter() {
    require_ghidra!();
    let harness = harness();

    // Regression: `address` comes back from the bridge as a hex string
    // (e.g. "0x00401000"), never a JSON number. A numeric range filter
    // against it used to fall through to the evaluator's catch-all
    // `Ok(false)` for every row -- exit 0, empty result, no error -- instead
    // of comparing addresses. Derive real bounds from the binary so this
    // isn't tied to one platform's address layout.
    let mut addrs: Vec<u64> = get_function_addresses(harness, test_project(), TEST_PROGRAM, 50)
        .iter()
        .map(|a| {
            let hex = a.strip_prefix("0x").expect("prefixed address");
            u64::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("bad address {}: {}", a, e))
        })
        .collect();
    addrs.sort_unstable();
    let lo = addrs[0];
    let hi = addrs[addrs.len() / 2];

    let filter = format!("address >= 0x{:x} AND address <= 0x{:x}", lo, hi);
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg(&filter)
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter '{}' should match at least one function (addresses {}..={})",
        filter,
        lo,
        hi
    );
    for f in &functions {
        let hex = f.address.strip_prefix("0x").expect("prefixed address");
        let addr = u64::from_str_radix(hex, 16)
            .unwrap_or_else(|e| panic!("bad address {}: {}", f.address, e));
        assert!(
            addr >= lo && addr <= hi,
            "Function {} at {} is outside the filtered range {}..={}",
            f.name,
            f.address,
            lo,
            hi
        );
    }
}

#[test]
#[serial]
fn test_function_list_bare_word_filter_rejected() {
    require_ghidra!();
    let harness = harness();

    // A bare word is not a valid filter expression. It must fail with a
    // nonzero exit instead of dumping the entire unfiltered dataset.
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("main")
        .run();

    result.assert_failure();
}
