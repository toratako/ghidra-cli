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
fn test_xref_list_wire_command_is_rejected() {
    require_ghidra!();
    let harness = harness();
    let error = harness
        .client()
        .unwrap()
        .send_command("xrefs_list", Some(serde_json::json!({"address": "main"})))
        .unwrap_err();
    assert!(
        error.to_string().contains("Unknown command: xrefs_list"),
        "{error}"
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
fn test_graph_calls_queries_match_bridge_nodes_and_outgoing_edges() {
    require_ghidra!();
    let harness = harness();
    let all = harness.client().unwrap().graph_calls(None).unwrap();
    let mut nodes = all["nodes"].as_array().unwrap().clone();
    let edges = all["edges"].as_array().unwrap();
    assert!(nodes.len() > 2);
    assert!(!edges.is_empty());
    nodes.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let query = |flags: &[&str]| -> serde_json::Value {
        let result = ghidra(harness)
            .args(["graph", "calls"])
            .args(flags.iter().copied())
            .with_project(test_project(), TEST_PROGRAM)
            .json_format()
            .run();
        result.assert_success();
        result.json()
    };
    let page_flags = ["--sort", "name", "--offset", "1", "--limit", "2"];
    let page = query(&page_flags);
    let selected = &nodes[1..3];
    assert_eq!(page[0]["nodes"], serde_json::json!(selected));
    let outgoing: Vec<_> = edges
        .iter()
        .filter(|edge| selected.iter().any(|node| node["id"] == edge["from"]))
        .collect();
    assert_eq!(page[0]["edges"], serde_json::json!(outgoing));
    assert_eq!(page[0]["node_count"], 2);
    assert_eq!(page[0]["edge_count"], outgoing.len());
    assert_eq!(query(&["--count"]), serde_json::json!(nodes.len()));
    assert_eq!(query(&["--limit", "2", "--count"]), 2);
    assert_eq!(
        query(&["--offset", &nodes.len().to_string(), "--limit", "2"]),
        serde_json::json!([{"nodes": [], "edges": [], "node_count": 0, "edge_count": 0}])
    );
    let matching = query(&["--filter", "name~add_numbers", "--limit", "0"]);
    let matching = matching[0]["nodes"].as_array().unwrap();
    assert!(!matching.is_empty());
    assert_eq!(
        matching.len(),
        nodes
            .iter()
            .filter(|node| node["name"].as_str().unwrap().contains("add_numbers"))
            .count()
    );
    assert!(matching
        .iter()
        .all(|node| node["name"].as_str().unwrap().contains("add_numbers")));

    let batch_dir = tempfile::tempdir().unwrap();
    let batch_file = batch_dir.path().join("graph.txt");
    std::fs::write(
        &batch_file,
        "graph calls --sort name --offset 1 --limit 2\n",
    )
    .unwrap();
    let batch = ghidra(harness)
        .arg("batch")
        .arg(batch_file.to_str().unwrap())
        .with_project(test_project(), TEST_PROGRAM)
        .arg("--json")
        .run();
    batch.assert_success();
    let batch: serde_json::Value = batch.json();
    assert_eq!(batch[0]["results"][0]["result"], page);
}

#[test]
#[serial]
fn test_graph_callers() {
    require_ghidra!();
    let harness = harness();
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("graph")
        .arg("callers")
        .arg(&main_addr)
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
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg(&main_addr)
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
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let client = harness.client().expect("bridge client");

    // depth=0 means recursive/unbounded depth; a tiny bridge-side limit must
    // stop traversal before the full graph is constructed.
    let result = client
        .graph_callees(&main_addr, Some(0), Some(2))
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
        .graph_callers(&main_addr, Some(0), Some(2))
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
fn test_graph_depth_uses_shortest_path_through_diamond_and_cycle() {
    require_ghidra!();
    let client = harness().client().expect("bridge client");
    let program = format!("graph-depth-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateGraphDepthFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("graph depth fixture");
            try {
                String[] names = {"root", "long1", "long2", "short", "join", "tail", "leaf"};
                int[][] edges = {{0, 1}, {0, 3}, {1, 2}, {2, 4}, {3, 4}, {4, 5}, {5, 6}, {6, 4}};
                for (int direction = 0; direction < 2; direction++) {
                    String prefix = direction == 0 ? "callees_" : "callers_";
                    Address base = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x1000 + direction * 0x1000);
                    program.getMemory().createInitializedBlock(prefix + "code", base,
                        0x100, (byte) 0, monitor, false);
                    for (int i = 0; i < names.length; i++) {
                        Address entry = base.add(i * 0x10);
                        program.getFunctionManager().createFunction(prefix + names[i], entry,
                            new AddressSet(entry, entry.add(0xf)), SourceType.USER_DEFINED);
                    }
                    int[] sites = new int[names.length];
                    for (int[] edge : edges) {
                        int from = edge[direction];
                        int to = edge[1 - direction];
                        Address site = base.add(from * 0x10 + 2 * sites[from]++);
                        program.getMemory().setBytes(site, new byte[] {(byte)0xff, (byte)0xd0});
                        if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false).applyTo(program, monitor)) {
                            throw new IllegalStateException("Could not disassemble call at " + site);
                        }
                        program.getReferenceManager().addMemoryReference(
                            site, base.add(to * 0x10),
                            RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
                    }
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .expect("create isolated graph program");
    client.open_program(&program).expect("open graph program");

    // Restore the shared suite's selection even if a regression assertion fails.
    let checked = std::panic::catch_unwind(|| {
        for (direction, base, sites) in [
            (
                "callees",
                0x1000,
                [0x00, 0x02, 0x10, 0x30, 0x20, 0x40, 0x50, 0x60],
            ),
            (
                "callers",
                0x2000,
                [0x10, 0x30, 0x20, 0x42, 0x40, 0x50, 0x60, 0x44],
            ),
        ] {
            let root = format!("{direction}_root");
            let query = |depth, limit| {
                if direction == "callees" {
                    client.graph_callees(&root, depth, limit)
                } else {
                    client.graph_callers(&root, depth, limit)
                }
                .expect("query graph")
            };

            // Both directions traverse this shape, with the long branch first:
            // root -> long1 -> long2 -> join -> tail -> leaf -> join (cycle)
            //      -> short ---------> join
            // DFS expanded join first at distance 3, then missed leaf at depth 4.
            let bounded = query(Some(4), None);
            let rows = bounded[direction].as_array().expect("graph rows");
            assert!(
                rows.iter()
                    .any(|row| row["name"] == format!("{direction}_leaf")),
                "{direction} must include leaf via the shorter branch: {bounded}"
            );

            let expected = [
                ("long1", 1, 0),
                ("short", 3, 0),
                ("long2", 2, 1),
                ("join", 4, 1),
                ("join", 4, 2),
                ("tail", 5, 2),
                ("leaf", 6, 3),
                ("join", 4, 4),
            ];
            let unbounded = query(Some(0), Some(0));
            let all = unbounded[direction].as_array().expect("unbounded rows");
            assert_eq!(
                all.len(),
                expected.len(),
                "cycle must terminate: {unbounded}"
            );
            for ((row, (name, index, depth)), site) in all.iter().zip(expected).zip(sites) {
                assert_eq!(row.as_object().unwrap().len(), 4, "row shape: {row}");
                assert_eq!(row["name"], format!("{direction}_{name}"));
                assert_eq!(row["depth"], depth, "row depth: {row}");
                for (field, offset) in [("address", index * 0x10), ("call_site", site)] {
                    assert_eq!(
                        u64::from_str_radix(
                            row[field]
                                .as_str()
                                .expect("address string")
                                .strip_prefix("0x")
                                .expect("prefixed address"),
                            16
                        )
                        .expect("hex address"),
                        base + offset,
                        "{field}: {row}"
                    );
                }
            }

            // Immediate references retain depth 0; depth 0 and limit 0 mean unbounded.
            for (depth, count) in [(1, 2), (2, 4), (3, 6), (4, 7), (5, 8), (0, 8)] {
                let result = query(Some(depth), None);
                assert_eq!(result["function"], root);
                assert_eq!(result["count"], count);
                assert_eq!(result[direction].as_array().unwrap(), &all[..count]);
                for limit in [1, 2, 5, 20] {
                    let limited = query(Some(depth), Some(limit));
                    let retained = count.min(limit);
                    assert_eq!(limited["count"], retained);
                    assert_eq!(limited[direction].as_array().unwrap(), &all[..retained]);
                }
            }
            assert_eq!(query(None, None)[direction].as_array().unwrap(), &all[..2]);
        }
    });
    client
        .open_program(TEST_PROGRAM)
        .expect("restore shared suite program");
    client
        .program_delete(&program)
        .expect("delete graph fixture program");
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
