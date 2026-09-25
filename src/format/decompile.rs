use serde_json::Value as JsonValue;
use std::collections::HashMap;

pub(crate) fn format_decompile_warning(warning: &JsonValue) -> Option<String> {
    let message = warning.get("message")?.as_str()?;
    let source = warning.get("source")?.as_str()?;
    let location = warning
        .get("address")
        .and_then(JsonValue::as_str)
        .map(|address| format!(" at {address}"))
        .unwrap_or_default();
    Some(format!("[{source}{location}] {message}"))
}

/// Render a decompiler result before the generic object formatter handles it.
pub(super) fn format_result(value: &JsonValue, output: &mut String, full: bool) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    let Some(code) = map.get("code").and_then(JsonValue::as_str) else {
        return false;
    };

    if let Some(signature) = map.get("signature").and_then(JsonValue::as_str) {
        if full {
            output.push_str(&format!("Signature: {signature}\n"));
        } else {
            output.push_str(signature);
            output.push('\n');
        }
    }
    if full {
        if let Some(name) = map.get("name").and_then(JsonValue::as_str) {
            output.push_str(&format!("Function:  {name}\n"));
        }
    }
    format_function_attributes(map, output);
    if full {
        output.push('\n');
    }
    output.push_str(&format_code(
        code,
        map.get("line_addresses"),
        AddressStyle::Gutter,
    ));
    if !code.ends_with('\n') {
        output.push('\n');
    }
    format_decompile_details(map, output);
    true
}

fn format_function_attributes(map: &serde_json::Map<String, JsonValue>, result: &mut String) {
    if let Some(external) = map.get("is_external").and_then(JsonValue::as_bool) {
        result.push_str(&format!("External: {external}\n"));
    }
    if let Some(memory) = map.get("entry_memory") {
        if memory.is_null() {
            result.push_str("Entry memory: none\n");
        } else {
            let name = memory
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or("?");
            let permissions = memory
                .get("permissions")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            result.push_str(&format!("Entry memory: {name} ({permissions})\n"));
        }
    }
}

/// Append decompiler diagnostics and requested analysis details.
fn format_decompile_details(map: &serde_json::Map<String, JsonValue>, result: &mut String) {
    if let Some(count) = map.get("basic_block_count") {
        let count = count
            .as_u64()
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unavailable".to_string());
        result.push_str(&format!("\nBasic blocks (decompiler): {count}\n"));
    }
    if let Some(tables) = map.get("jump_tables") {
        match tables.as_array() {
            None => result.push_str("\nJump tables: unavailable\n"),
            Some(tables) if tables.is_empty() => {
                result.push_str("\nJump tables: none recovered\n");
            }
            Some(tables) => {
                result.push_str("\nJump tables:\n");
                for table in tables {
                    let address = table
                        .get("switch_address")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("?");
                    result.push_str(&format!("  Switch at {address}:\n"));
                    if let Some(cases) = table.get("cases").and_then(JsonValue::as_array) {
                        for case in cases {
                            let address = case
                                .get("address")
                                .and_then(JsonValue::as_str)
                                .unwrap_or("?");
                            let label = if case.get("is_default").and_then(JsonValue::as_bool)
                                == Some(true)
                            {
                                "default".to_string()
                            } else {
                                case.get("label")
                                    .and_then(JsonValue::as_i64)
                                    .map(|label| format!("case {label}"))
                                    .unwrap_or_else(|| "label unavailable".to_string())
                            };
                            result.push_str(&format!("    {label} -> {address}\n"));
                        }
                    }
                }
            }
        }
    }
    if let Some(warnings) = map
        .get("warnings")
        .and_then(JsonValue::as_array)
        .filter(|v| !v.is_empty())
    {
        result.push_str("\nWarnings:\n");
        for warning in warnings {
            if let Some(text) = format_decompile_warning(warning) {
                result.push_str(&format!("  {text}\n"));
            }
        }
    }
    for (key, title) in [("params", "Parameters"), ("variables", "Variables")] {
        if let Some(rows) = map
            .get(key)
            .and_then(JsonValue::as_array)
            .filter(|rows| !rows.is_empty())
        {
            result.push_str(&format!("\n{title}:\n"));
            for row in rows {
                if let Some(obj) = row.as_object() {
                    let name = obj.get("name").and_then(JsonValue::as_str).unwrap_or("?");
                    let typ = obj.get("type").and_then(JsonValue::as_str).unwrap_or("?");
                    let storage = obj
                        .get("storage")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("?");
                    result.push_str(&format!("  {typ} {name} ({storage})\n"));
                }
            }
        }
    }
}

pub(super) enum AddressStyle {
    Gutter,
    Comments,
}

/// Render annotations against physical lines of the unchanged decompiler text.
pub(super) fn format_code(
    code: &str,
    line_addresses: Option<&JsonValue>,
    style: AddressStyle,
) -> String {
    let Some(entries) = line_addresses.and_then(JsonValue::as_array) else {
        return code.to_string();
    };
    let addresses: HashMap<_, _> = entries
        .iter()
        .filter_map(|entry| {
            let line = entry.get("line")?.as_u64()?;
            let addresses = entry
                .get("addresses")?
                .as_array()?
                .iter()
                .filter_map(JsonValue::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            (!addresses.is_empty()).then_some((line, addresses))
        })
        .collect();
    let line_width = code.split_inclusive('\n').count().to_string().len();
    let address_width = addresses.values().map(String::len).max().unwrap_or(1);
    let mut result = String::new();
    for (index, line) in code.split_inclusive('\n').enumerate() {
        let number = index as u64 + 1;
        let address = addresses.get(&number);
        match style {
            AddressStyle::Gutter => {
                let address = address.map(String::as_str).unwrap_or("-");
                result.push_str(&format!(
                    "{number:>line_width$}  {address:<address_width$} | {line}"
                ));
            }
            AddressStyle::Comments => {
                // Preserve both LF/CRLF and the presence of a final newline.
                let (text, newline) = if let Some(text) = line.strip_suffix("\r\n") {
                    (text, "\r\n")
                } else if let Some(text) = line.strip_suffix('\n') {
                    (text, "\n")
                } else {
                    (line, "")
                };
                result.push_str(text);
                if let Some(address) = address {
                    result.push_str(" // @ ");
                    result.push_str(address);
                }
                result.push_str(newline);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn comment_annotations_preserve_line_endings_and_final_newlines() {
        let addresses = json!([{ "line": 2, "addresses": ["0x1004", "0x1018"] }]);
        for newline in ["\n", "\r\n"] {
            for ending in ["", newline] {
                let code = format!("{newline}  return 日本語;{ending}");
                assert_eq!(
                    format_code(&code, Some(&addresses), AddressStyle::Comments),
                    format!("{newline}  return 日本語; // @ 0x1004, 0x1018{ending}")
                );
            }
        }
    }
}
