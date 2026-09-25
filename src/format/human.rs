use super::{decompile, flow, format_json_value, frame, signature, structure, vtable};
use crate::error::Result;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// Compact human-readable format: one line per item with key fields.
pub(super) fn format_compact<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for item in &json_data {
        match item {
            JsonValue::Object(map) => {
                if flow::format_result(item, &mut result, false) {
                    continue;
                }
                if structure::format_result(item, &mut result, false) {
                    continue;
                }
                if vtable::format_result(item, &mut result, false) {
                    continue;
                }
                if decompile::format_result(item, &mut result, false) {
                    continue;
                }

                // Special case: disasm instruction with mnemonic
                if let (Some(addr), Some(mnem)) = (
                    map.get("address").and_then(|v| v.as_str()),
                    map.get("mnemonic").and_then(|v| v.as_str()),
                ) {
                    let bytes = map.get("bytes").and_then(|v| v.as_str()).unwrap_or("");
                    let operands = match map.get("operands") {
                        Some(JsonValue::Array(ops)) => ops
                            .iter()
                            .map(format_json_value)
                            .collect::<Vec<_>>()
                            .join(", "),
                        _ => String::new(),
                    };
                    result.push_str(&format!(
                        "{:<12} {:<16} {} {}\n",
                        addr, bytes, mnem, operands
                    ));
                    continue;
                }

                // General object: render primary fields in a compact line
                if map.len() == 1 && map.contains_key("frame_details") {
                    frame::format_details(&map["frame_details"], &mut result);
                    continue;
                }
                if map.len() == 1 && map.contains_key("signature_details") {
                    signature::format_details(&map["signature_details"], &mut result);
                    continue;
                }
                let address = map.get("address").and_then(|v| v.as_str());
                let name = map.get("name").and_then(|v| v.as_str());
                let size = map.get("size").and_then(|v| v.as_u64());
                let value_str = map.get("value").and_then(|v| v.as_str());

                // Build compact line from available fields
                let mut parts: Vec<String> = Vec::new();

                if let Some(addr) = address {
                    parts.push(addr.to_string());
                }
                if let Some(n) = name {
                    parts.push(n.to_string());
                }
                if let Some(s) = size {
                    parts.push(format!("({})", s));
                }
                if let Some(v) = value_str {
                    // Truncate long strings
                    if v.len() > 80 {
                        let mut end = 77;
                        while !v.is_char_boundary(end) {
                            end -= 1;
                        }
                        parts.push(format!("\"{}...\"", &v[..end]));
                    } else {
                        parts.push(format!("\"{}\"", v));
                    }
                } else if let Some(v) = map.get("value") {
                    parts.push(format!("value={}", format_json_value(v)));
                }

                // If we only have unknown fields, render as key=value pairs
                if parts.is_empty() {
                    let kv: Vec<String> = map
                        .iter()
                        .filter(|(k, _)| {
                            !matches!(k.as_str(), "signature_details" | "frame_details")
                        })
                        .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                        .collect();
                    result.push_str(&kv.join("  "));
                } else {
                    result.push_str(&parts.join("  "));

                    // Add secondary fields only when the fallback has not rendered them.
                    let secondary: Vec<String> = map
                        .iter()
                        .filter(|(k, _)| {
                            !matches!(
                                k.as_str(),
                                "address"
                                    | "name"
                                    | "size"
                                    | "value"
                                    | "mnemonic"
                                    | "bytes"
                                    | "operands"
                                    | "code"
                                    | "signature"
                                    | "signature_details"
                                    | "frame_details"
                            )
                        })
                        .filter_map(|(k, v)| {
                            let s = format_json_value(v);
                            if s.is_empty()
                                || (s == "null"
                                    && !matches!(
                                        k.as_str(),
                                        "entry_memory"
                                            | "database"
                                            | "before"
                                            | "after"
                                            | "override"
                                    ))
                                || s == "\"\""
                            {
                                None
                            } else {
                                Some(format!("{}={}", k, s))
                            }
                        })
                        .collect();

                    if !secondary.is_empty() {
                        result.push_str("  ");
                        result.push_str(&secondary.join("  "));
                    }
                }

                result.push('\n');
                if let Some(details) = map.get("signature_details") {
                    signature::format_details(details, &mut result);
                }
                if let Some(details) = map.get("frame_details") {
                    frame::format_details(details, &mut result);
                }
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

/// Full human-readable format: multi-line labeled blocks per item.
pub(super) fn format_full<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for (i, item) in json_data.iter().enumerate() {
        if i > 0 {
            result.push_str("---\n");
        }

        match item {
            JsonValue::Object(map) => {
                if flow::format_result(item, &mut result, true) {
                    continue;
                }
                if structure::format_result(item, &mut result, true) {
                    continue;
                }
                if vtable::format_result(item, &mut result, true) {
                    continue;
                }
                if decompile::format_result(item, &mut result, true) {
                    continue;
                }

                // Calculate max key width for alignment
                let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);

                for (key, val) in map {
                    if key == "signature_details" {
                        signature::format_details(val, &mut result);
                        continue;
                    }
                    if key == "frame_details" {
                        frame::format_details(val, &mut result);
                        continue;
                    }
                    let formatted = format_json_value(val);
                    result.push_str(&format!(
                        "{:width$}  {}\n",
                        format!("{}:", key),
                        formatted,
                        width = max_key + 1
                    ));
                }
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

pub(super) fn format_minimal<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut result = String::new();

    for item in &json_data {
        if let JsonValue::Object(map) = item {
            // Try to get address or name or first field
            let value = map
                .get("address")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("id"))
                .or_else(|| map.values().next())
                .map(format_json_value)
                .unwrap_or_else(|| "".to_string());

            result.push_str(&value);
            result.push('\n');
        } else {
            result.push_str(&format_json_value(item));
            result.push('\n');
        }
    }

    Ok(result)
}
