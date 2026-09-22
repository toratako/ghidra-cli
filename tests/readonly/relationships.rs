use super::{harness, TEST_PROGRAM};
use crate::common::{get_function_address, ghidra, schemas::XRef, test_project};
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

    let xrefs: Vec<XRef> = result.data();
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
fn test_xref_from_explicit_address_and_function_scope() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let run = |target: &str, function: bool| -> serde_json::Value {
        let mut command = ghidra(harness)
            .args(["xref", "from", target, "--limit", "0"])
            .with_project(test_project(), TEST_PROGRAM)
            .json_format();
        if function {
            command = command.arg("--function");
        }
        let result = command.run();
        result.assert_success();
        result.data()
    };

    let body = run(&main_addr, true);
    let rows = body.as_array().unwrap();
    let inside = rows
        .iter()
        .find_map(|row| row["from"].as_str().filter(|address| *address != main_addr))
        .expect("main must reference something from an interior address");
    // An interior selector explicitly selects the same entire body.
    assert_eq!(run(inside, true), body);
    // Without --function, even the entry selects only one source address.
    for address in [main_addr.as_str(), inside] {
        let expected: Vec<_> = rows
            .iter()
            .filter(|row| row["from"] == address)
            .cloned()
            .collect();
        assert_eq!(run(address, false), serde_json::json!(expected));
        assert_eq!(
            client.xrefs_from(address.to_owned(), false).unwrap()["xrefs"],
            serde_json::json!(expected)
        );
    }
}

#[test]
#[serial]
fn test_xref_to_external_import_resolves_thunk() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().expect("bridge client");

    let imports = client.symbol_externals(Some(100)).expect("list imports");
    let imports = imports
        .get("externals")
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

#[test]
#[serial]
fn xref_metadata_preserves_operand_distinct_references_in_both_directions() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("xref-metadata-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreateXrefMetadataFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let checked = std::panic::catch_unwind(|| {
        use serde_json::{json, Value};
        let normalize = |result: &Value| {
            let mut rows = result["xrefs"].as_array().unwrap().clone();
            assert_eq!(result["count"], rows.len());
            rows.sort_by_key(|row| row["operand_index"].as_i64().unwrap());
            rows
        };
        let incoming = normalize(&client.xrefs_to("xref_target".to_owned()).unwrap());
        let expected: Vec<_> = [
            (-1, "IMPORTED", true),
            (0, "USER_DEFINED", false),
            (1, "ANALYSIS", true),
        ]
        .into_iter()
        .map(|(operand, source, primary)| {
            json!({
                "from":"0x00001000", "to":"0x00002000", "ref_type":"DATA",
                "from_function":"xref_source", "to_function":"xref_target",
                "operand_index":operand, "source":source, "primary":primary,
            })
        })
        .collect();
        assert_eq!(incoming, expected);
        assert_eq!(
            normalize(&client.xrefs_to("0x2000".to_owned()).unwrap()),
            incoming
        );
        for (target, function) in [("0x1000", false), ("xref_source", false), ("0x1002", true)] {
            assert_eq!(
                normalize(&client.xrefs_from(target.to_owned(), function).unwrap()),
                incoming
            );
        }
        for args in [
            vec!["xref", "to", "xref_target", "--limit", "0"],
            vec!["xref", "from", "xref_source", "--function", "--limit", "0"],
        ] {
            let result = ghidra(harness)
                .args(args)
                .with_project(test_project(), &program)
                .arg("--json")
                .run();
            result.assert_success();
            let mut rows: Vec<Value> = result.data();
            rows.sort_by_key(|row| row["operand_index"].as_i64().unwrap());
            assert_eq!(rows, expected);
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
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
        result.data()
    };
    let page_flags = ["--sort", "name", "--offset", "1", "--limit", "2"];
    let page = query(&page_flags);
    let selected = &nodes[1..3];
    assert_eq!(page["nodes"], serde_json::json!(selected));
    let outgoing: Vec<_> = edges
        .iter()
        .filter(|edge| selected.iter().any(|node| node["id"] == edge["from"]))
        .collect();
    assert_eq!(page["edges"], serde_json::json!(outgoing));
    assert_eq!(page["node_count"], 2);
    assert_eq!(page["edge_count"], outgoing.len());
    assert_eq!(query(&["--count"]), serde_json::json!(nodes.len()));
    assert_eq!(query(&["--limit", "2", "--count"]), 2);
    assert_eq!(
        query(&["--offset", &nodes.len().to_string(), "--limit", "2"]),
        serde_json::json!({"nodes": [], "edges": [], "node_count": 0, "edge_count": 0})
    );
    let matching = query(&["--filter", "name~add_numbers", "--limit", "0"]);
    let matching = matching["nodes"].as_array().unwrap();
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
    let batch: serde_json::Value = batch.data();
    assert_eq!(batch["results"][0]["result"]["data"], page);
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
        .get("calls")
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
            .get("calls")
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
            let endpoint = if direction == "callees" {
                "callee"
            } else {
                "caller"
            };
            let endpoint_address = format!("{endpoint}_address");
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
            let rows = bounded["calls"].as_array().expect("graph rows");
            assert!(
                rows.iter()
                    .any(|row| row[endpoint] == format!("{direction}_leaf")),
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
            let all = unbounded["calls"].as_array().expect("unbounded rows");
            assert_eq!(
                all.len(),
                expected.len(),
                "cycle must terminate: {unbounded}"
            );
            assert_eq!(
                query(Some(i32::MAX as usize), Some(i32::MAX as usize)),
                unbounded,
                "{direction}: maximum supported bounds must retain all rows"
            );
            let wire = format!("graph_{direction}");
            let defaults = client
                .send_command(
                    &wire,
                    Some(serde_json::json!({"function":root, "depth":null, "limit":null})),
                )
                .unwrap();
            assert_eq!(defaults, query(None, None));
            for field in ["depth", "limit"] {
                for value in [
                    serde_json::json!(-1),
                    serde_json::json!(1.5),
                    serde_json::json!("1"),
                    serde_json::json!(2147483648u64),
                    serde_json::json!(4294967296u64),
                    serde_json::json!(4294967297u64),
                    serde_json::json!(u64::MAX),
                ] {
                    let mut args = serde_json::json!({"function":root});
                    args[field] = value;
                    let error = client
                        .send_command(&wire, Some(args.clone()))
                        .expect_err(&format!("{wire} accepted {args}"));
                    assert!(
                        error
                            .to_string()
                            .contains(&format!("{field} must be an integer from 0 to 2147483647")),
                        "{wire}: {args}: {error}"
                    );
                }
            }
            for ((row, (name, index, depth)), site) in all.iter().zip(expected).zip(sites) {
                assert_eq!(row.as_object().unwrap().len(), 9, "row shape: {row}");
                assert_eq!(row[endpoint], format!("{direction}_{name}"));
                assert_eq!(row["depth"], depth, "row depth: {row}");
                for (field, offset) in [
                    (endpoint_address.as_str(), index * 0x10),
                    ("call_site", site),
                ] {
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
                assert_eq!(result["target"], root);
                assert_eq!(result["count"], count);
                assert_eq!(result["calls"].as_array().unwrap(), &all[..count]);
                for limit in [1, 2, 5, 20] {
                    let limited = query(Some(depth), Some(limit));
                    let retained = count.min(limit);
                    assert_eq!(limited["count"], retained);
                    assert_eq!(limited["calls"].as_array().unwrap(), &all[..retained]);
                }
            }
            assert_eq!(query(None, None)["calls"].as_array().unwrap(), &all[..2]);
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
