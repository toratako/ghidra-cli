use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project, with_temporary_program};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn direct_call_targets_are_not_dereferenced_as_pointer_operands() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("call-pointer-destination-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCallPointerDestination.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    with_temporary_program(&client, &program, TEST_PROGRAM, || {
        for function in ["direct", "overridden"] {
            let graph = client.graph_callees(function, None, None).unwrap();
            assert_eq!(graph["count"], 1, "{graph}");
            let call = &graph["calls"][0];
            assert_eq!(call["callee_address"], "0x00002000", "{graph}");
            assert_eq!(call["destination"], "0x00002000", "{graph}");
            assert!(call["callee"].is_null(), "{graph}");
            let incoming = client
                .graph_callers(call["callee_address"].as_str().unwrap(), None, None)
                .unwrap();
            assert!(
                incoming["calls"].as_array().unwrap().contains(call),
                "{incoming}"
            );
        }
        let indirect = client.graph_callees("indirect", None, None).unwrap();
        assert_eq!(indirect["count"], 1, "{indirect}");
        assert_eq!(indirect["calls"][0]["callee"], "pointee", "{indirect}");
        assert_eq!(indirect["calls"][0]["callee_address"], "0x00003000");
        let callers = client.graph_callers("pointee", None, None).unwrap();
        assert_eq!(callers["count"], 1, "{callers}");
        assert_eq!(callers["calls"][0]["caller"], "indirect", "{callers}");
        let graph = client.graph_calls(None).unwrap();
        for edge in graph["edges"].as_array().unwrap() {
            let target = if edge["caller"] == "indirect" {
                "0x00003000"
            } else {
                "0x00002000"
            };
            assert_eq!(edge["to"], target, "{graph}");
        }
    });
}

#[test]
#[serial]
fn call_graphs_share_resolution_and_retain_undefined_endpoints() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("call-search-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/readonly/CreateCallSearchFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let address = |row: &Value, field: &str| {
            u64::from_str_radix(row[field].as_str().unwrap().strip_prefix("0x").unwrap(), 16)
                .unwrap()
        };
        let outgoing = client.graph_callees("search_caller", None, None).unwrap();
        let rows = outgoing["calls"].as_array().unwrap();
        let mut actual: Vec<_> = rows
            .iter()
            .map(|row| (address(row, "call_site"), row["callee"].as_str()))
            .collect();
        actual.sort_unstable();
        assert_eq!(
            actual,
            vec![
                (0x1000, Some("search_helper")),
                (0x1008, Some("CreateProcessA")),
                (0x1010, Some("CreateProcessA")),
                (0x1020, Some("CreateProcessA")),
                (0x1040, Some("search_helper")),
                (0x1090, Some("search_leaf")),
                (0x1098, None),
                (0x10a0, Some("CreateProcessA")),
                (0x10a8, Some("search_helper")),
                (0x10a8, Some("search_leaf")),
                (0x10a8, Some("search_leaf")),
                (0x10b0, Some("CreateProcessA")),
                (0x10b8, None),
                (0x10c0, Some("search_leaf")),
                (0x10d8, Some("CreateProcessA")),
                (0x10e0, Some("search_helper")),
                (0x10e8, Some("search_leaf")),
                (0x2500, Some("search_leaf")),
            ],
            "{outgoing}"
        );
        assert_eq!(outgoing["count"], rows.len());
        for row in rows {
            assert_eq!(row["caller"], "search_caller");
            assert_eq!(address(row, "caller_address"), 0x1000);
            assert_eq!(row["depth"], 0);
            // Every outgoing edge is returned identically by incoming resolution.
            let incoming = client
                .graph_callers(row["callee_address"].as_str().unwrap(), None, None)
                .unwrap();
            assert!(
                incoming["calls"].as_array().unwrap().contains(row),
                "{row}: {incoming}"
            );
        }
        for (site, callee, via) in [
            (0x1090, 0x1200, 0x1204),
            (0x1098, 0x2200, 0x2200),
            (0x10b8, 0x3030, 0x3030),
        ] {
            let row = rows
                .iter()
                .find(|row| address(row, "call_site") == site)
                .unwrap();
            assert_eq!(address(row, "callee_address"), callee);
            assert_eq!(address(row, "via"), via);
        }
        let landings: Vec<_> = rows
            .iter()
            .filter(|row| address(row, "call_site") == 0x10a8 && row["callee"] == "search_leaf")
            .map(|row| address(row, "destination"))
            .collect();
        assert_eq!(landings, [0x1200, 0x1204]);
        let local = client.graph_callers("search_helper", None, None).unwrap();
        assert_eq!(local["count"], 5, "{local}");
        let orphan = local["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| address(row, "call_site") == 0x2100)
            .unwrap();
        assert!(orphan["caller"].is_null());
        assert!(orphan["caller_address"].is_null());
        assert_eq!(orphan["callee"], "search_helper");
        // Undefined callers are retained as leaves, including unlimited traversal.
        assert_eq!(
            client
                .graph_callers("search_helper", Some(0), None)
                .unwrap(),
            local
        );
        let expected_imports: Vec<_> = rows
            .iter()
            .filter(|row| row["callee"] == "CreateProcessA")
            .cloned()
            .collect();
        for target in [
            "CreateProcessA",
            "__imp_CreateProcessA",
            "0x2000",
            "0x3000",
            "0x3020",
        ] {
            let found = client.graph_callers(target, None, None).unwrap();
            let mut found_rows = found["calls"].as_array().unwrap().clone();
            found_rows.sort_by_key(|row| address(row, "call_site"));
            assert_eq!(found_rows, expected_imports, "{target}: {found}");
            for limit in [1, 2] {
                assert_eq!(
                    client.graph_callers(target, Some(0), Some(limit)).unwrap()["count"],
                    limit
                );
            }
        }
        assert_eq!(
            client.graph_callers("0x1204", None, None).unwrap()["calls"],
            client.graph_callers("search_leaf", None, None).unwrap()["calls"]
        );
        assert_eq!(
            client.graph_callees("0x1001", None, None).unwrap()["calls"],
            outgoing["calls"]
        );
        assert_eq!(
            client.graph_callees("0x2050", None, None).unwrap()["count"],
            0,
            "a thunk body must not be replaced with its canonical callee's body"
        );
        let deep = client
            .graph_callees("search_caller", Some(0), None)
            .unwrap();
        assert_eq!(deep["count"], 19, "{deep}");
        let second = deep["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["depth"] == 1)
            .unwrap();
        assert_eq!(second["caller"], "search_helper");
        assert_eq!(second["callee"], "search_leaf");

        // Whole-program function graphs use the same edges, including undefined destinations.
        let graph = client.graph_calls(None).unwrap();
        let edges = graph["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 19, "{graph}");
        for node in graph["nodes"].as_array().unwrap() {
            let outgoing = client
                .graph_callees(node["address"].as_str().unwrap(), None, None)
                .unwrap();
            let expected: Vec<_> = outgoing["calls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row.as_object_mut().unwrap().remove("depth");
                    row["from"] = row["caller_address"].clone();
                    row["to"] = row["callee_address"].clone();
                    row
                })
                .collect();
            let actual: Vec<_> = edges
                .iter()
                .filter(|edge| edge["from"] == node["id"])
                .cloned()
                .collect();
            assert_eq!(actual, expected, "{node}");
        }
        let limited = client.graph_calls(Some(1)).unwrap();
        assert_eq!(limited["node_count"], 1);
        assert_eq!(limited["edge_count"], rows.len());

        // Shared row fields support selection after traversal, standalone and in batches.
        let flags = [
            "--filter",
            "callee=search_leaf",
            "--sort",
            "call_site",
            "--skip",
            "1",
            "--limit",
            "1",
            "--fields",
            "caller,callee,call_site",
        ];
        let selected = ghidra(harness())
            .args(["graph", "callees", "search_caller"])
            .args(flags)
            .with_project(test_project(), &name)
            .json_format()
            .run();
        selected.assert_success();
        let selected: Value = selected.data();
        assert_eq!(selected.as_array().unwrap().len(), 1);
        assert_eq!(address(&selected[0], "call_site"), 0x10a8);
        assert_eq!(selected[0]["caller"], "search_caller");
        assert_eq!(selected[0]["callee"], "search_leaf");
        let count = ghidra(harness())
            .args(["graph", "callees", "search_caller", "--count"])
            .with_project(test_project(), &name)
            .json_format()
            .run();
        count.assert_success();
        assert_eq!(count.data::<Value>(), json!(18));
        let dir = tempfile::tempdir().unwrap();
        let batch_file = dir.path().join("calls.txt");
        std::fs::write(&batch_file,
            "graph callees search_caller --filter 'callee=search_leaf' --sort call_site --skip 1 --limit 1 --fields caller,callee,call_site\n").unwrap();
        let batch = ghidra(harness())
            .arg("batch")
            .arg(batch_file.to_str().unwrap())
            .with_project(test_project(), &name)
            .arg("--json")
            .run();
        batch.assert_success();
        assert_eq!(
            batch.data::<Value>()["results"][0]["result"]["data"],
            selected
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
