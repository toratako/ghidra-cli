use super::format_json_value;
use serde_json::Value;

/// These are whole analysis results: each section retains its own identities and
/// completeness instead of being summarized as a generic object row.
pub(super) fn format_result(value: &Value, output: &mut String, full: bool) -> bool {
    let title = match value["representation"].as_str() {
        Some("instruction_cfg") => "Instruction CFG",
        Some("high_pcode") => "High P-code",
        _ => return false,
    };
    output.push_str(&format!(
        "{title}: {} ({})\n",
        text(&value["function"]),
        text(&value["address"])
    ));
    output.push_str(&format!(
        "Program: {}  project={}/{}  modification={}\n",
        text(&value["program"]),
        text(&value["project"]["location"]),
        text(&value["project"]["name"]),
        text(&value["modification"])
    ));
    output.push_str(&format!(
        "Result: {} (IDs scoped to this result)\nBody: {}\n",
        text(&value["result_id"]),
        ranges(&value["body_ranges"])
    ));
    completion(value, output, full);
    if value["representation"] == "instruction_cfg" {
        cfg(value, output, full);
    } else {
        high(value, output, full);
    }
    true
}

fn text(value: &Value) -> String {
    if value.is_null() {
        "-".to_string()
    } else {
        format_json_value(value)
    }
}

fn rows(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn ranges(value: &Value) -> String {
    rows(value)
        .iter()
        .map(|range| {
            let start = text(&range["start"]);
            if range["start"] == range["end"] {
                start
            } else {
                format!("{start}..{}", text(&range["end"]))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn complete(value: &Value) -> &'static str {
    match value.as_bool() {
        Some(true) => "complete",
        Some(false) => "INCOMPLETE",
        None => "unknown",
    }
}

fn fields(value: &Value, excluded: &[&str]) -> String {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| !excluded.contains(&key.as_str()))
        .map(|(key, val)| format!("{key}={}", text(val)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn completion(value: &Value, output: &mut String, full: bool) {
    let completion = &value["completion"];
    output.push_str(&format!(
        "Scan: {}  Output: {}\n",
        complete(&completion["scan"]["complete"]),
        complete(&completion["output"]["complete"])
    ));
    for key in ["scan", "output"] {
        let details = fields(&completion[key], &["complete"]);
        if !details.is_empty() {
            output.push_str(&format!("  {key}: {details}\n"));
        }
    }
    if let Some(collections) = completion["collections"].as_object() {
        for (name, counts) in collections {
            if full || counts["complete"] == false {
                output.push_str(&format!(
                    "  {name}: {} {}\n",
                    complete(&counts["complete"]),
                    fields(counts, &["complete"])
                ));
            }
        }
    }
    if full {
        output.push_str(&format!("Limits: {}\n", fields(&value["limits"], &[])));
    }
    for warning in rows(&value["warnings"]) {
        let detail =
            super::human::format_decompile_warning(warning).unwrap_or_else(|| text(warning));
        output.push_str(&format!("Warning: {detail}\n"));
    }
}

fn cfg(value: &Value, output: &mut String, full: bool) {
    output.push_str(&format!("\nBlocks ({}):\n", rows(&value["nodes"]).len()));
    for block in rows(&value["nodes"]) {
        output.push_str(&format!(
            "  {}  {}  entries={}{}\n",
            text(&block["id"]),
            ranges(&block["ranges"]),
            text(&block["entries"]),
            if block["flows_complete"] == false {
                "  [flows INCOMPLETE]"
            } else {
                ""
            }
        ));
        if full || block["body_intersection"] != block["ranges"] {
            output.push_str(&format!(
                "    In body: {}\n",
                ranges(&block["body_intersection"])
            ));
        }
    }
    for (key, title) in [
        ("edges", "Edges"),
        ("calls", "Calls"),
        ("boundaries", "Boundaries"),
    ] {
        output.push_str(&format!("\n{title} ({}):\n", rows(&value[key]).len()));
        for flow in rows(&value[key]) {
            let kind = flow["kind"]
                .as_str()
                .map(|kind| format!("{kind} "))
                .unwrap_or_default();
            output.push_str(&format!(
                "  {kind}{} -> {}  at {} -> {}  {} [{}]",
                text(&flow["from"]),
                text(&flow["to"]),
                text(&flow["site"]),
                text(&flow["target"]),
                text(&flow["flow_type"]),
                text(&flow["target_state"])
            ));
            for field in ["via", "body_crossing"] {
                if !flow[field].is_null() {
                    output.push_str(&format!(" {field}={}", text(&flow[field])));
                }
            }
            if full || flow["site_in_body"] == false || flow["target_in_body"] == false {
                output.push_str(&format!(
                    " site_in_body={} target_in_body={}",
                    text(&flow["site_in_body"]),
                    text(&flow["target_in_body"])
                ));
            }
            output.push('\n');
        }
    }
}

fn reference(value: &Value) -> String {
    let id = text(&value["id"]);
    match value["state"].as_str() {
        Some("included") => id,
        Some(state) => format!("{id} [{state}]"),
        None => id,
    }
}

fn storage(value: &Value) -> String {
    format!(
        "{}:{}:{}",
        text(&value["space"]),
        text(&value["offset"]),
        text(&value["size"])
    )
}

fn collection(value: &Value, key: &str) -> String {
    let mut detail = text(&value[key]);
    let status = &value[format!("{key}_status")];
    if status["complete"] == false {
        detail.push_str(&format!(
            " [INCOMPLETE: returned={} total={}]",
            text(&status["returned"]),
            text(&status["total"])
        ));
    }
    detail
}

fn high(value: &Value, output: &mut String, full: bool) {
    output.push_str(&format!(
        "\nOperations ({}):\n",
        rows(&value["operations"]).len()
    ));
    for operation in rows(&value["operations"]) {
        output.push_str(&format!(
            "  {}  {} sequence={}  block={} order={}  {} = {}\n",
            text(&operation["id"]),
            text(&operation["instruction_address"]),
            text(&operation["sequence"]),
            reference(&operation["block"]),
            text(&operation["block_order"]),
            reference(&operation["output"]),
            text(&operation["mnemonic"])
        ));
        for input in rows(&operation["inputs"]) {
            let operand = match input["kind"].as_str() {
                Some("operation") => reference(&input["operation"]),
                Some("address_space") => {
                    format!("{} [{}]", text(&input["space"]), text(&input["state"]))
                }
                _ => reference(&input["value"]),
            };
            output.push_str(&format!(
                "    [{}] {}: {operand}",
                text(&input["slot"]),
                text(&input["role"])
            ));
            if input.get("incoming_edge").is_some() {
                output.push_str(&format!(" via {}", reference(&input["incoming_edge"])));
            }
            if full && !input["encoding"].is_null() {
                output.push_str(&format!(" encoding={}", storage(&input["encoding"])));
            }
            output.push('\n');
        }
    }
    output.push_str(&format!("\nValues ({}):\n", rows(&value["values"]).len()));
    for value in rows(&value["values"]) {
        output.push_str(&format!(
            "  {}  {}  {}  def={}  high={}",
            text(&value["id"]),
            storage(value),
            text(&value["origin"]),
            reference(&value["definition"]),
            reference(&value["high_variable"])
        ));
        if let Some(register) = value["register"].as_str() {
            output.push_str(&format!(" register={register}"));
        }
        output.push('\n');
        let uses = rows(&value["uses"])
            .iter()
            .map(|usage| {
                format!(
                    "{}[{}] ({})",
                    text(&usage["operation"]),
                    text(&usage["slot"]),
                    text(&usage["role"])
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!("    Uses: [{uses}]"));
        if value["uses_status"]["complete"] == false {
            output.push_str(&format!(
                " [INCOMPLETE: returned={} total={}]",
                text(&value["uses_status"]["returned"]),
                text(&value["uses_status"]["total"])
            ));
        }
        output.push('\n');
        if full {
            output.push_str(&format!(
                "    {}\n",
                fields(
                    value,
                    &[
                        "id",
                        "space",
                        "offset",
                        "size",
                        "origin",
                        "definition",
                        "high_variable",
                        "register",
                        "uses",
                        "uses_status"
                    ]
                )
            ));
        }
    }
    output.push_str(&format!(
        "\nHigh blocks ({}):\n",
        rows(&value["blocks"]).len()
    ));
    for block in rows(&value["blocks"]) {
        output.push_str(&format!(
            "  {}  {}..{}\n    Operations: {}\n    Incoming: {}\n    Outgoing: {}\n",
            text(&block["id"]),
            text(&block["start"]),
            text(&block["stop"]),
            collection(block, "operations"),
            collection(block, "incoming_edges"),
            collection(block, "outgoing_edges")
        ));
    }
    output.push_str(&format!(
        "\nHigh edges ({}):\n",
        rows(&value["edges"]).len()
    ));
    for edge in rows(&value["edges"]) {
        output.push_str(&format!(
            "  {}  {} out[{}] -> {} in[{}]\n",
            text(&edge["id"]),
            reference(&edge["source"]),
            text(&edge["source_out_index"]),
            reference(&edge["target"]),
            text(&edge["target_in_index"])
        ));
    }
    for (key, title, links) in [
        ("high_variables", "High variables", "values"),
        ("symbols", "Symbols", "high_variables"),
    ] {
        output.push_str(&format!("\n{title} ({}):\n", rows(&value[key]).len()));
        for variable in rows(&value[key]) {
            output.push_str(&format!(
                "  {}  {} {} ({})  {links}={}\n",
                text(&variable["id"]),
                text(&variable["type"]),
                text(&variable["name"]),
                text(&variable["kind"]),
                collection(variable, links)
            ));
            if key == "high_variables" {
                output.push_str(&format!(
                    "    symbol={} offset={} representative={}\n",
                    reference(&variable["symbol"]),
                    text(&variable["symbol_offset"]),
                    reference(&variable["representative"])
                ));
            } else {
                output.push_str(&format!("    storage={}\n", text(&variable["storage"])));
            }
            if full {
                output.push_str(&format!(
                    "    {}\n",
                    fields(
                        variable,
                        &[
                            "id",
                            "type",
                            "name",
                            "kind",
                            "values",
                            "values_status",
                            "high_variables",
                            "high_variables_status",
                            "symbol",
                            "symbol_offset",
                            "representative",
                            "storage"
                        ]
                    )
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::format::{DefaultFormatter, Formatter, OutputFormat};
    use serde_json::json;

    #[test]
    fn cfg_preserves_incomplete_flows_and_distinct_boundary_states() {
        let result = json!({
            "representation": "instruction_cfg", "function": "parser", "address": "0x1000",
            "program": "/sample", "project": {"location": "/tmp", "name": "analysis"},
            "modification": "7", "result_id": "capture-1", "id_scope": "result",
            "body_ranges": [{"start": "0x1000", "end": "0x1003"}],
            "nodes": [{"id": "b0", "entries": ["0x1000"],
                "ranges": [{"start": "0x1000", "end": "0x1007"}],
                "body_intersection": [{"start": "0x1000", "end": "0x1003"}],
                "flows_complete": false}],
            "edges": [{"from": "b0", "to": null, "site": "0x1003", "target": "0x1010",
                "flow_type": "CONDITIONAL_JUMP", "target_state": "omitted",
                "site_in_body": true, "target_in_body": true, "body_crossing": null}],
            "calls": [{"from": "b0", "to": null, "site": "0x1001", "target": null,
                "flow_type": "COMPUTED_CALL", "target_state": "unresolved",
                "site_in_body": true, "target_in_body": null, "body_crossing": null}],
            "boundaries": [{"kind": "delay_slot", "from": "b0", "to": "b0",
                "site": "0x1003", "target": "0x1004", "flow_type": "FALL_THROUGH",
                "target_state": "included", "site_in_body": true, "target_in_body": false,
                "body_crossing": "exit"}],
            "completion": {"scan": {"complete": false, "instructions": 4},
                "output": {"complete": false, "nodes": 1, "edges": 3, "reasons": ["max_edges"]},
                "collections": {"calls": {"complete": false, "returned": 1}}},
            "warnings": [{"source": "decompiler", "address": "0x1001", "message": "test warning"}]
        });
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            let output = DefaultFormatter
                .format(std::slice::from_ref(&result), format)
                .unwrap();
            for expected in [
                "Instruction CFG: parser (0x1000)",
                "Result: capture-1 (IDs scoped to this result)",
                "Scan: INCOMPLETE  Output: INCOMPLETE",
                "reasons=[max_edges]",
                "calls: INCOMPLETE returned=1",
                "b0  0x1000..0x1007",
                "In body: 0x1000..0x1003",
                "[flows INCOMPLETE]",
                "at 0x1003 -> 0x1010  CONDITIONAL_JUMP [omitted]",
                "at 0x1001 -> -  COMPUTED_CALL [unresolved]",
                "delay_slot b0 -> b0",
                "body_crossing=exit",
                "target_in_body=false",
                "Warning: [decompiler at 0x1001] test warning",
            ] {
                assert!(output.contains(expected), "missing {expected}:\n{output}");
            }
        }
        let json = DefaultFormatter
            .format(std::slice::from_ref(&result), OutputFormat::JsonCompact)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            json!([result])
        );
    }

    #[test]
    fn high_preserves_value_identity_slots_phi_order_and_omitted_uses() {
        let result = json!({
            "representation": "high_pcode", "function": "merge", "address": "0x1000",
            "operations": [{"id": "op2", "instruction_address": "0x1010", "sequence": 9,
                "block": {"id": "b1", "state": "included"}, "block_order": 0,
                "mnemonic": "MULTIEQUAL", "output": {"id": "v1", "state": "included"},
                "inputs": [
                    {"slot": 0, "role": "phi_input", "kind": "value",
                        "value": {"id": "v0", "state": "included"},
                        "incoming_edge": {"id": "e0", "state": "included"}},
                    {"slot": 1, "role": "phi_input", "kind": "value",
                        "value": {"id": "v0", "state": "included"},
                        "incoming_edge": {"id": "e1", "state": "omitted"}}
                ]}],
            "values": [
                {"id": "v0", "space": "register", "offset": "0x0", "size": 4, "origin": "input",
                    "definition": {"id": null, "state": "none"},
                    "high_variable": {"id": "h0", "state": "omitted"},
                    "uses": [{"operation": "op2", "slot": 0, "role": "phi_input"},
                        {"operation": "op2", "slot": 1, "role": "phi_input"}],
                    "uses_status": {"complete": false, "returned": 2, "total": 3}},
                {"id": "v1", "space": "register", "offset": "0x0", "size": 4, "origin": "defined",
                    "definition": {"id": "op2", "state": "included"},
                    "high_variable": {"id": null, "state": "none"},
                    "uses": [], "uses_status": {"complete": true, "returned": 0, "total": 0}}
            ],
            "blocks": [{"id": "b1", "start": "0x1010", "stop": "0x1013",
                "operations": ["op2"], "operations_status": {"complete": true},
                "incoming_edges": ["e0"], "incoming_edges_status": {"complete": false, "returned": 1, "total": 2},
                "outgoing_edges": [], "outgoing_edges_status": {"complete": true}}],
            "edges": [{"id": "e0", "source": {"id": "b0", "state": "omitted"},
                "target": {"id": "b1", "state": "included"}, "source_out_index": 1, "target_in_index": 0}],
            "completion": {"scan": {"complete": true},
                "output": {"complete": false, "reasons": ["max_nodes"]}}
        });
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            let output = DefaultFormatter
                .format(std::slice::from_ref(&result), format)
                .unwrap();
            for expected in [
                "Scan: complete  Output: INCOMPLETE",
                "reasons=[max_nodes]",
                "op2  0x1010 sequence=9  block=b1 order=0  v1 = MULTIEQUAL",
                "[0] phi_input: v0 via e0",
                "[1] phi_input: v0 via e1 [omitted]",
                "v0  register:0x0:4  input  def=- [none]  high=h0 [omitted]",
                "v1  register:0x0:4  defined  def=op2",
                "Uses: [op2[0] (phi_input), op2[1] (phi_input)] [INCOMPLETE: returned=2 total=3]",
                "Incoming: [e0] [INCOMPLETE: returned=1 total=2]",
                "e0  b0 [omitted] out[1] -> b1 in[0]",
            ] {
                assert!(output.contains(expected), "missing {expected}:\n{output}");
            }
        }
    }
}
