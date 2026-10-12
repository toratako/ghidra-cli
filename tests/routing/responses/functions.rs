//! Recorded functions response fixtures.

use serde_json::{json, Value};

pub(crate) fn flow_fixture(high: bool, program: &str) -> Value {
    let mut result = json!({
        "representation": if high { "high_pcode" } else { "instruction_cfg" },
        "result_id": "flow-result",
        "id_scope": "result",
        "project": {"location": "/projects", "name": "project"},
        "program": program, "modification": "42", "function": "main", "address": "0x1000",
        "body_ranges": [{"start": "0x1000", "end": "0x1010"}, {"start": "0x2000", "end": "0x2010"}],
        "limits": {"max_nodes": 1000, "max_edges": 4000},
        "completion": {"complete": false, "reasons": ["max_edges"], "returned_nodes": 2, "returned_edges": 2},
        "edges": [
            {"id": "e0", "from": "b0", "to": "b1", "kind": "fallthrough"},
            {"id": "e1", "from": "b1", "to": {"state": "omitted", "id": "b2"}, "kind": "conditional"}
        ]
    });
    if high {
        result["operations"] = json!([
            {"id": "op0", "opcode": "INT_ADD", "inputs": [{"slot": 0, "value": "v0"}, {"slot": 1, "value": "v0"}], "output": "v1"},
            {"id": "op1", "opcode": "RETURN", "inputs": [{"slot": 0, "value": "v1"}], "output": null}
        ]);
        result["values"] = json!([
            {"id": "v0", "definition": null, "uses": [{"operation": "op0", "slot": 0}, {"operation": "op0", "slot": 1}]},
            {"id": "v1", "definition": "op0", "uses": [{"operation": "op1", "slot": 0}]}
        ]);
        result["blocks"] = json!([
            {"id": "b0", "operations": ["op0"]}, {"id": "b1", "operations": ["op1"]}
        ]);
        result["high_variables"] = json!([{"id": "h0", "values": ["v0", "v1"]}]);
        result["symbols"] = json!([]);
    } else {
        result["nodes"] = json!([
            {"id": "b0", "entries": ["0x1000"], "ranges": [{"start": "0x1000", "end": "0x1010"}]},
            {"id": "b1", "entries": ["0x2000"], "ranges": [{"start": "0x2000", "end": "0x2010"}]}
        ]);
        result["calls"] = json!([
            {"block": "b0", "address": "0x1004", "target": "0x3000"},
            {"block": "b1", "address": "0x2004", "target": null, "state": "unresolved"}
        ]);
        result["boundaries"] = json!([
            {"block": "b1", "address": "0x2010", "kind": "return"}
        ]);
    }
    result
}
