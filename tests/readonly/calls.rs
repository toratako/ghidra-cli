use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn call_graphs_share_resolution_and_retain_undefined_endpoints() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("call-search-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateCallSearchFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("call search fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var fm = program.getFunctionManager();
                var refs = program.getReferenceManager();
                var source = SourceType.USER_DEFINED;
                program.getMemory().createInitializedBlock("code", space.getAddress(0x1000), 0x3000, (byte) 0, monitor, false);
                String[] names = {"search_caller", "search_helper", "search_leaf"};
                for (int i = 0; i < names.length; i++) {
                    var entry = space.getAddress(0x1000 + i * 0x100);
                    fm.createFunction(names[i], entry, new AddressSet(entry, entry.add(0xff)), source);
                }
                for (int address : new int[] {0x1000, 0x1008, 0x1010, 0x1100, 0x1060,
                        0x1090, 0x1098, 0x10a0, 0x10a8, 0x10b0, 0x10b8, 0x10c0, 0x2100, 0x2500}) {
                    var site = space.getAddress(address);
                    program.getMemory().setBytes(site, new byte[] {(byte)0xff, (byte)0xd0});
                    if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble call at " + site);
                    }
                }
                refs.addMemoryReference(space.getAddress(0x1000), space.getAddress(0x1100), RefType.UNCONDITIONAL_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x1100), space.getAddress(0x1200), RefType.UNCONDITIONAL_CALL, source, 0);
                var external = program.getExternalManager().addExtFunction("KERNEL32.dll", "CreateProcessA", null, source);
                var thunkEntry = space.getAddress(0x2000);
                var thunk = fm.createFunction("CreateProcessA", thunkEntry, new AddressSet(thunkEntry, thunkEntry.add(5)), source);
                thunk.setThunkedFunction(external.getFunction());
                var localThunkEntry = space.getAddress(0x2050);
                var localThunk = fm.createFunction("helper_thunk", localThunkEntry,
                    new AddressSet(localThunkEntry, localThunkEntry.add(5)), source);
                localThunk.setThunkedFunction(fm.getFunctionAt(space.getAddress(0x1100)));
                refs.addExternalReference(space.getAddress(0x1008), 0, external, source, RefType.UNCONDITIONAL_CALL);
                refs.addMemoryReference(space.getAddress(0x1010), thunkEntry, RefType.UNCONDITIONAL_CALL, source, 0);
                var slot = space.getAddress(0x3000);
                program.getListing().createData(slot, PointerDataType.dataType);
                refs.addExternalReference(slot, 0, external, source, RefType.DATA);
                var indirect = space.getAddress(0x1020);
                program.getMemory().setBytes(indirect, new byte[] {(byte)0xff, 0x15, (byte)0xda, 0x1f, 0, 0});
                new DisassembleCommand(indirect, new AddressSet(indirect, indirect.add(5)), false).applyTo(program, monitor);
                refs.addMemoryReference(indirect, slot, RefType.READ, source, 0);
                // A pointer to local code can use the flow-type INDIRECTION.
                var localSlot = space.getAddress(0x3010);
                program.getListing().createData(localSlot, PointerDataType.dataType);
                refs.addMemoryReference(localSlot, space.getAddress(0x1100), RefType.INDIRECTION, source, 0);
                var localIndirect = space.getAddress(0x1040);
                program.getMemory().setBytes(localIndirect, new byte[] {(byte)0xff, 0x15, (byte)0xca, 0x1f, 0, 0});
                if (!new DisassembleCommand(localIndirect, new AddressSet(localIndirect, localIndirect.add(5)), false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble local indirect call");
                }
                refs.addMemoryReference(localIndirect, localSlot, RefType.READ, source, 0);
                program.getSymbolTable().createLabel(slot, "__imp_CreateProcessA", source);
                // Interior and undefined destinations, an unowned call site, and a disjoint body.
                refs.addMemoryReference(space.getAddress(0x1090), space.getAddress(0x1204), RefType.UNCONDITIONAL_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x1098), space.getAddress(0x2200), RefType.UNCONDITIONAL_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x2100), space.getAddress(0x1100), RefType.UNCONDITIONAL_CALL, source, 0);
                var body = new AddressSet(fm.getFunctionAt(space.getAddress(0x1000)).getBody());
                body.add(space.getAddress(0x2500), space.getAddress(0x2501));
                fm.getFunctionAt(space.getAddress(0x1000)).setBody(body);
                refs.addMemoryReference(space.getAddress(0x2500), space.getAddress(0x1200), RefType.UNCONDITIONAL_CALL, source, 0);
                // A pointer table inside another function must still resolve as a pointer.
                var leafBody = new AddressSet(fm.getFunctionAt(space.getAddress(0x1200)).getBody());
                leafBody.add(localSlot, localSlot.add(7));
                fm.getFunctionAt(space.getAddress(0x1200)).setBody(leafBody);
                // Multiple known destinations must survive, while duplicate evidence is one call.
                refs.addMemoryReference(space.getAddress(0x10a8), space.getAddress(0x1100), RefType.COMPUTED_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x10a8), space.getAddress(0x1200), RefType.COMPUTED_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x10a8), space.getAddress(0x1204), RefType.COMPUTED_CALL, source, 0);
                refs.addMemoryReference(space.getAddress(0x10b0), slot, RefType.READ, source, 0);
                refs.addExternalReference(space.getAddress(0x10b0), 1, external, source, RefType.COMPUTED_CALL);
                // Pointer chains resolve in both directions; pointer cycles terminate.
                var chainedSlot = space.getAddress(0x3020);
                program.getListing().createData(chainedSlot, PointerDataType.dataType);
                refs.addMemoryReference(chainedSlot, slot, RefType.DATA, source, 0);
                refs.addMemoryReference(space.getAddress(0x10a0), chainedSlot, RefType.READ, source, 0);
                for (int address : new int[] {0x3030, 0x3040}) {
                    program.getListing().createData(space.getAddress(address), PointerDataType.dataType);
                }
                refs.addMemoryReference(space.getAddress(0x3030), space.getAddress(0x3040), RefType.DATA, source, 0);
                refs.addMemoryReference(space.getAddress(0x3040), space.getAddress(0x3030), RefType.DATA, source, 0);
                refs.addMemoryReference(space.getAddress(0x10b8), space.getAddress(0x3030), RefType.READ, source, 0);
                // Argument references do not call the API, including on an unrelated CALL.
                for (int address : new int[] {0x1030, 0x1050, 0x1070, 0x10c8, 0x10d0}) {
                    var site = space.getAddress(address);
                    program.getMemory().setByte(site, (byte)0x90);
                    new DisassembleCommand(site, new AddressSet(site, site), false).applyTo(program, monitor);
                }
                refs.addExternalReference(space.getAddress(0x1030), 0, external, source, RefType.DATA);
                refs.addExternalReference(space.getAddress(0x1050), 0, external, source, RefType.PARAM);
                refs.addExternalReference(space.getAddress(0x1060), 0, external, source, RefType.PARAM);
                var override = refs.addMemoryReference(space.getAddress(0x10c0), space.getAddress(0x1200), RefType.CALL_OVERRIDE_UNCONDITIONAL, source, 0);
                refs.setPrimary(override, true);
                var inactive = refs.addMemoryReference(space.getAddress(0x10c8), space.getAddress(0x1200), RefType.CALL_OVERRIDE_UNCONDITIONAL, source, 0);
                refs.setPrimary(inactive, false);
                // A primary call override on NOP has no CALL/CALLIND to override.
                var inert = refs.addMemoryReference(space.getAddress(0x10d0), space.getAddress(0x1200), RefType.CALL_OVERRIDE_UNCONDITIONAL, source, 0);
                refs.setPrimary(inert, true);
                // A direct call can have symbolic EXTERNAL relocation evidence,
                // whose EXTERNAL address is not represented in memory-space p-code.
                var relocated = space.getAddress(0x10d8);
                program.getMemory().setBytes(relocated, new byte[] {(byte)0xe8, 0x23, 1, 0, 0});
                if (!new DisassembleCommand(relocated, new AddressSet(relocated, relocated.add(4)), false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble relocated call");
                }
                if (!program.getListing().getInstructionAt(relocated).getFlowType().isCall()) {
                    throw new IllegalStateException("Relocated instruction must be an effective CALL");
                }
                refs.removeAllReferencesFrom(relocated);
                refs.addExternalReference(relocated, 0, external, source, RefType.UNCONDITIONAL_CALL);
                // Even a mislabeled CALL reference from a NOP or undefined bytes is not a call.
                refs.addExternalReference(space.getAddress(0x1070), 0, external, source, RefType.UNCONDITIONAL_CALL);
                refs.addExternalReference(space.getAddress(0x1080), 0, external, source, RefType.UNCONDITIONAL_CALL);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
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
        assert_eq!(local["count"], 4, "{local}");
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
        assert_eq!(deep["count"], 17, "{deep}");
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
        assert_eq!(edges.len(), 17, "{graph}");
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
        assert_eq!(count.data::<Value>(), json!(16));
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
