use super::{harness, TEST_PROGRAM};
use crate::common::{
    get_function_address, ghidra,
    schemas::{GraphResult, XRef},
    test_project,
};
use serial_test::serial;

// XRef Tests

#[test]
#[serial]
fn test_xref_to() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "add_numbers");

    let result = ghidra(harness)
        .arg("xref")
        .arg("to")
        .arg(&addr)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "add_numbers should have incoming cross-references (called by main)"
    );
    // Every xref should point TO the target address
    for xref in &xrefs {
        assert_eq!(xref.to, addr, "xref 'to' field should match target address");
    }
}

#[test]
#[serial]
fn test_xref_from() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("xref")
        .arg("from")
        .arg(&main_addr)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "main should have outgoing cross-references (calls other functions)"
    );
    // Every xref should originate FROM within main
    for xref in &xrefs {
        assert!(
            xref.from_function
                .as_deref()
                .is_some_and(|f| f.contains("main")),
            "xref from_function should be main, got: {:?}",
            xref.from_function
        );
    }
}

#[test]
#[serial]
fn test_xref_list() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "add_numbers");

    let result = ghidra(harness)
        .arg("xref")
        .arg("list")
        .arg(&addr)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let xrefs: Vec<XRef> = result.json();
    assert!(
        !xrefs.is_empty(),
        "add_numbers should have cross-references in list view"
    );
    // Should have both directions when function has incoming refs and outgoing refs
    let has_to = xrefs.iter().any(|x| x.direction.as_deref() == Some("to"));
    let has_from = xrefs.iter().any(|x| x.direction.as_deref() == Some("from"));
    // add_numbers is called by main, so it must have "to" xrefs
    assert!(has_to, "xref list should include incoming (to) references");
    // add_numbers has a function body, so it should have "from" xrefs too
    // (at minimum, stack/register references)
    eprintln!(
        "xref list: {} total, has_to={}, has_from={}",
        xrefs.len(),
        has_to,
        has_from
    );
}

#[test]
#[serial]
fn test_xref_to_external_import_resolves_thunk() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().expect("bridge client");

    let imports = client.list_imports(Some(100)).expect("list imports");
    let imports = imports
        .get("imports")
        .and_then(|v| v.as_array())
        .expect("imports array");

    // Pick any import that actually has a reference in this platform's fixture.
    // This avoids hard-coding libc vs Darwin import names while exercising the
    // EXTERNAL-address -> local thunk resolution path.
    for import in imports {
        let Some(address) = import.get("address").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(name) = import.get("name").and_then(|v| v.as_str()) else {
            continue;
        };

        let by_address = client
            .xrefs_to(address.to_string())
            .expect("xref external address");
        let address_refs = by_address
            .get("xrefs")
            .and_then(|v| v.as_array())
            .expect("xrefs array");
        if address_refs.is_empty() {
            continue;
        }

        let by_name = client.xrefs_to(name.to_string()).expect("xref import name");
        let name_refs = by_name
            .get("xrefs")
            .and_then(|v| v.as_array())
            .expect("xrefs array");
        assert!(
            !name_refs.is_empty(),
            "used import {name} ({address}) should resolve by name as well as EXTERNAL address"
        );
        return;
    }

    panic!("fixture has no imported symbol with incoming references");
}

// Graph Tests

#[test]
#[serial]
fn test_graph_calls() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("calls")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("nodes");
    result.assert_stdout_contains("edges");
}

#[test]
#[serial]
fn test_graph_callers() {
    require_ghidra!();
    let harness = harness();

    // Use "main" instead of "add_numbers" since add_numbers may be inlined on macOS
    let result = ghidra(harness)
        .arg("graph")
        .arg("callers")
        .arg("main")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        eprintln!("Callers graph for main has {} nodes", graph.nodes.len());
    }
}

#[test]
#[serial]
fn test_graph_callees() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg("main")
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        let node_labels: Vec<_> = graph
            .nodes
            .iter()
            .filter_map(|n| n.label.as_deref())
            .collect();

        let has_add_numbers = node_labels
            .iter()
            .any(|l| l.contains("add_numbers") || l.contains("_add_numbers"));
        let has_multiply = node_labels
            .iter()
            .any(|l| l.contains("multiply") || l.contains("_multiply"));

        if has_add_numbers {
            eprintln!("Found add_numbers in callees");
        }
        if has_multiply {
            eprintln!("Found multiply in callees");
        }
    }
}

#[test]
#[serial]
fn test_graph_callees_limit_is_enforced_by_bridge() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().expect("bridge client");

    // depth=0 means recursive/unbounded depth; a tiny bridge-side limit must
    // stop traversal before the full graph is constructed.
    let result = client
        .graph_callees("main", Some(0), Some(2))
        .expect("bounded callees graph");
    let callees = result
        .get("callees")
        .and_then(|v| v.as_array())
        .expect("callees array");
    assert_eq!(
        callees.len(),
        2,
        "fixture main should hit the bridge traversal cap exactly"
    );

    // Exercise the callers path too. The fixture may naturally have fewer than
    // two callers for main on some platforms, so only assert the hard ceiling.
    let callers = client
        .graph_callers("main", Some(0), Some(2))
        .expect("bounded callers graph");
    assert!(
        callers
            .get("callers")
            .and_then(|v| v.as_array())
            .is_some_and(|rows| rows.len() <= 2),
        "callers bridge response must respect the traversal cap"
    );
}

#[test]
#[serial]
fn test_graph_export_dot() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("export")
        .arg("dot")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("digraph");
}
