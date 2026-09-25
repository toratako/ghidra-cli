use super::{fields, rows, text};
use serde_json::Value;

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

pub(super) fn format(value: &Value, output: &mut String, full: bool) {
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
