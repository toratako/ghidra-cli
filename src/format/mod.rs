pub use crate::cli::OutputFormat;
use crate::error::Result;
use comfy_table::{presets::UTF8_FULL, Table};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashSet;

mod signature;

pub trait Formatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
}

pub struct DefaultFormatter;

impl Formatter for DefaultFormatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(data).map_err(|e| e.into()),
            OutputFormat::JsonCompact => serde_json::to_string(data).map_err(|e| e.into()),
            OutputFormat::JsonStream => {
                let mut result = String::new();
                for item in data {
                    let json = serde_json::to_string(item)?;
                    result.push_str(&json);
                    result.push('\n');
                }
                Ok(result)
            }
            OutputFormat::Table => format_table(data),
            OutputFormat::Csv => format_csv(data, ','),
            OutputFormat::Tsv => format_csv(data, '\t'),
            OutputFormat::Compact => format_compact(data),
            OutputFormat::Full => format_full(data),
            OutputFormat::Minimal => format_minimal(data),
            OutputFormat::C | OutputFormat::Asm => format_code(data, format),
        }
    }
}

fn format_code<T: Serialize>(data: &[T], format: OutputFormat) -> Result<String> {
    let rows = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut output = String::new();
    for row in &rows {
        match format {
            OutputFormat::C if row.get("code").and_then(JsonValue::as_str).is_some() => {
                output.push_str(row["code"].as_str().unwrap());
            }
            OutputFormat::Asm if row.get("mnemonic").and_then(JsonValue::as_str).is_some() => {
                let address = row
                    .get("address")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("?");
                let bytes = row.get("bytes").and_then(JsonValue::as_str).unwrap_or("");
                let mnemonic = row["mnemonic"].as_str().unwrap();
                let operands = row
                    .get("operands")
                    .and_then(JsonValue::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(format_json_value)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                output.push_str(&format!("{address}  {bytes:<12} {mnemonic}"));
                if !operands.is_empty() {
                    output.push(' ');
                    output.push_str(&operands);
                }
            }
            // Preserve the existing single JSON document for unrelated result
            // shapes (or projections that removed the code fields).
            _ => return serde_json::to_string_pretty(&rows).map_err(Into::into),
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

/// Preserve the first row's column order, appending new keys as they appear.
/// Only the rows selected for output participate; no extra fetch is needed.
fn column_keys(rows: &[JsonValue]) -> Vec<String> {
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        if let Some(object) = row.as_object() {
            for key in object.keys() {
                if seen.insert(key) {
                    keys.push(key.clone());
                }
            }
        }
    }
    keys
}

fn format_table<T: Serialize>(data: &[T]) -> Result<String> {
    if data.is_empty() {
        return Ok("No results".to_string());
    }

    // Convert to JSON values to inspect structure
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let keys = column_keys(&json_data);
    if keys.is_empty() {
        return Ok(format!("{} results", data.len()));
    }

    let mut table = Table::new();
    table.load_style(UTF8_FULL);

    // Add header
    table.set_header(&keys);

    // Add rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys
                .iter()
                .map(|k| {
                    map.get(k)
                        .map(format_json_value)
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            table.add_row(row);
        }
    }

    Ok(table.to_string())
}

fn format_csv<T: Serialize>(data: &[T], delimiter: char) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok(String::new());
    }

    let keys = column_keys(&json_data);
    if keys.is_empty() {
        return Ok(String::new());
    }

    // Cell rendering owns array/object representation; the CSV writer owns
    // quoting (including headers and a single empty cell) and record framing.
    let mut writer = csv::WriterBuilder::new()
        .delimiter(delimiter as u8)
        .from_writer(Vec::new());
    writer.write_record(&keys).map_err(std::io::Error::other)?;

    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row = keys
                .iter()
                .map(|key| map.get(key).map(format_csv_value).unwrap_or_default());
            writer.write_record(row).map_err(std::io::Error::other)?;
        }
    }

    let bytes = writer.into_inner().map_err(|error| error.into_error())?;
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error).into())
}

/// Preserve the established semicolon-separated representation of array cells.
fn format_csv_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Array(arr) => arr
            .iter()
            .map(format_csv_value)
            .collect::<Vec<_>>()
            .join(";"),
        other => format_json_value(other),
    }
}

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

/// Compact human-readable format: one line per item with key fields.
fn format_compact<T: Serialize>(data: &[T]) -> Result<String> {
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
                // Special case: decompile response with "code" key
                if let Some(code) = map.get("code").and_then(|v| v.as_str()) {
                    if let Some(sig) = map.get("signature").and_then(|v| v.as_str()) {
                        result.push_str(sig);
                        result.push('\n');
                    }
                    format_function_attributes(map, &mut result);
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
                    format_decompile_details(map, &mut result);
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
                        .filter(|(k, _)| k.as_str() != "signature_details")
                        .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                        .collect();
                    result.push_str(&kv.join("  "));
                } else {
                    result.push_str(&parts.join("  "));
                }

                // Add extra context from secondary fields
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
                        )
                    })
                    .filter_map(|(k, v)| {
                        let s = format_json_value(v);
                        if s.is_empty() || (s == "null" && k != "entry_memory") || s == "\"\"" {
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

                result.push('\n');
                if let Some(details) = map.get("signature_details") {
                    signature::format_details(details, &mut result);
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
fn format_full<T: Serialize>(data: &[T]) -> Result<String> {
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
                // Special case: decompile response
                if let Some(code) = map.get("code").and_then(|v| v.as_str()) {
                    if let Some(sig) = map.get("signature").and_then(|v| v.as_str()) {
                        result.push_str(&format!("Signature: {}\n", sig));
                    }
                    if let Some(name) = map.get("name").and_then(|v| v.as_str()) {
                        result.push_str(&format!("Function:  {}\n", name));
                    }
                    format_function_attributes(map, &mut result);
                    result.push('\n');
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
                    format_decompile_details(map, &mut result);
                    continue;
                }

                // Calculate max key width for alignment
                let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);

                for (key, val) in map {
                    if key == "signature_details" {
                        signature::format_details(val, &mut result);
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

fn format_minimal<T: Serialize>(data: &[T]) -> Result<String> {
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

fn format_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(arr) => {
            format!(
                "[{}]",
                arr.iter()
                    .map(format_json_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        JsonValue::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

pub fn auto_detect_format(is_tty: bool) -> OutputFormat {
    if is_tty {
        OutputFormat::Compact
    } else {
        OutputFormat::JsonCompact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ndjson_uses_its_canonical_name_and_keeps_one_row_per_line() {
        let format = "ndjson".parse::<OutputFormat>().unwrap();
        assert_eq!(serde_json::to_string(&format).unwrap(), "\"ndjson\"");
        assert_eq!(
            serde_json::from_str::<OutputFormat>("\"ndjson\"").unwrap(),
            format
        );
        let rows = [
            json!({"value": "first\nsecond"}),
            json!({"value": "日本語"}),
        ];
        let output = DefaultFormatter.format(&rows, format).unwrap();
        let decoded: Vec<JsonValue> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(decoded, rows);
        assert!(output.ends_with('\n'));
        assert_eq!(
            DefaultFormatter.format::<JsonValue>(&[], format).unwrap(),
            ""
        );
    }

    #[test]
    fn human_decompile_formats_include_requested_parameters_and_variables() {
        let code = "int example(int count) { return count; }\n";
        for format in [auto_detect_format(true), OutputFormat::Full] {
            for (params, variables) in [(false, false), (true, false), (false, true), (true, true)]
            {
                let mut response = json!({"code": code});
                if params {
                    response["params"] =
                        json!([{ "name": "count", "type": "int", "storage": "register:0" }]);
                }
                if variables {
                    response["variables"] =
                        json!([{ "name": "local", "type": "char *", "storage": "stack:8" }]);
                }
                let output = DefaultFormatter.format(&[response], format).unwrap();
                assert!(output.contains(code));
                assert_eq!(
                    output.contains("Parameters:\n  int count (register:0)\n"),
                    params
                );
                assert_eq!(
                    output.contains("Variables:\n  char * local (stack:8)\n"),
                    variables
                );
            }
            let empty = json!({"code": code, "params": [], "variables": []});
            let absent = json!({"code": code});
            assert_eq!(
                DefaultFormatter.format(&[empty], format).unwrap(),
                DefaultFormatter.format(&[absent], format).unwrap()
            );
        }
        assert_eq!(auto_detect_format(false), OutputFormat::JsonCompact);
    }

    #[test]
    fn human_decompile_formats_preserve_case_destinations_and_default_meaning() {
        let code = "int choose(int value) { return value; }\n";
        let response = json!({
            "code": code,
            "basic_block_count": 5,
            "jump_tables": [{"switch_address": "0x1007", "cases": [
                {"address": "0x1040", "label": 0, "is_default": false},
                {"address": "0x1040", "label": 2, "is_default": false},
                {"address": "0x1050", "label": -1, "is_default": false},
                {"address": "0x1060", "label": -1160664095_i64, "is_default": true},
                {"address": "0x1070", "label": null, "is_default": false}
            ]}]
        });
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            let output = DefaultFormatter
                .format(std::slice::from_ref(&response), format)
                .unwrap();
            assert!(output.contains(code));
            assert!(output.contains("Basic blocks (decompiler): 5\n"));
            assert!(output.contains(concat!(
                "Jump tables:\n  Switch at 0x1007:\n",
                "    case 0 -> 0x1040\n",
                "    case 2 -> 0x1040\n",
                "    case -1 -> 0x1050\n",
                "    default -> 0x1060\n",
                "    label unavailable -> 0x1070\n"
            )));
            assert!(!output.contains("-1160664095"));
            for (tables, expected) in [
                (json!([]), "none recovered"),
                (JsonValue::Null, "unavailable"),
            ] {
                let row = json!({"code": code, "basic_block_count": null, "jump_tables": tables});
                let output = DefaultFormatter.format(&[row], format).unwrap();
                assert!(output.contains("Basic blocks (decompiler): unavailable\n"));
                assert!(output.contains(&format!("Jump tables: {expected}\n")));
            }
            let output = DefaultFormatter
                .format(&[json!({"code": code, "basic_block_count": 1})], format)
                .unwrap();
            assert!(!output.contains("Jump tables:"));
        }
        assert_eq!(
            DefaultFormatter
                .format(&[response], OutputFormat::C)
                .unwrap(),
            code
        );
    }

    #[test]
    fn c_and_asm_formats_render_code_without_json_escaping() {
        let code = "int main(void) {\n  return 0; /* 日本語 */\n}\n";
        assert_eq!(
            DefaultFormatter
                .format(&[json!({"code": code, "name": "main"})], OutputFormat::C)
                .unwrap(),
            code
        );
        let instructions = [
            json!({"address": "0x1000", "bytes": "4889e5", "mnemonic": "MOV", "operands": ["RBP", "RSP"]}),
            json!({"address": "0x1003", "bytes": "c3", "mnemonic": "RET", "operands": []}),
        ];
        assert_eq!(
            DefaultFormatter
                .format(&instructions, OutputFormat::Asm)
                .unwrap(),
            "0x1000  4889e5       MOV RBP, RSP\n0x1003  c3           RET\n"
        );
        for format in [OutputFormat::C, OutputFormat::Asm] {
            assert_eq!(
                DefaultFormatter.format::<JsonValue>(&[], format).unwrap(),
                ""
            );
            let rows = [
                json!({"error": "could not read code"}),
                json!({"name": "other"}),
            ];
            let rendered = DefaultFormatter.format(&rows, format).unwrap();
            assert_eq!(
                serde_json::from_str::<JsonValue>(&rendered).unwrap(),
                json!(rows)
            );
        }
    }

    #[test]
    fn tabular_output_keeps_fields_first_seen_in_later_rows() {
        let data = [
            json!({"name": "foo"}),
            json!({"comment": "解析済み,\t\"yes\"\nnext", "name": "bar"}),
        ];
        for (format, delimiter) in [(OutputFormat::Csv, b','), (OutputFormat::Tsv, b'\t')] {
            let output = DefaultFormatter.format(&data, format).unwrap();
            let mut reader = csv::ReaderBuilder::new()
                .delimiter(delimiter)
                .from_reader(output.as_bytes());
            assert_eq!(
                reader.headers().unwrap(),
                &csv::StringRecord::from(vec!["name", "comment"])
            );
            let rows: Vec<_> = reader
                .records()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(rows[0], csv::StringRecord::from(vec!["foo", ""]));
            assert_eq!(
                rows[1],
                csv::StringRecord::from(vec!["bar", "解析済み,\t\"yes\"\nnext"])
            );

            let output = DefaultFormatter
                .format(&[json!({}), json!({"later": "value"})], format)
                .unwrap();
            let mut reader = csv::ReaderBuilder::new()
                .delimiter(delimiter)
                .from_reader(output.as_bytes());
            assert_eq!(reader.headers().unwrap().get(0), Some("later"));
            assert_eq!(reader.records().count(), 2);
        }
        let output = DefaultFormatter.format(&data, OutputFormat::Table).unwrap();
        for expected in ["name", "comment", "foo", "bar", "解析済み"] {
            assert!(output.contains(expected), "{output}");
        }
        assert_eq!(
            serde_json::from_str::<JsonValue>(
                &DefaultFormatter
                    .format(&data, OutputFormat::JsonCompact)
                    .unwrap()
            )
            .unwrap(),
            json!(data)
        );
    }

    #[test]
    fn test_format_json() {
        let data = vec![json!({"name": "test", "value": 123})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn minimal_prefers_address_then_name_then_id() {
        let data = [
            json!({"address": "0x1000", "name": "main", "id": 1}),
            json!({"name": "helper", "id": 2}),
            json!({"id": 3}),
        ];
        let result = DefaultFormatter
            .format(&data, OutputFormat::Minimal)
            .unwrap();
        assert_eq!(result, "0x1000\nhelper\n3\n");
    }

    #[test]
    fn compact_preserves_typed_option_values_beside_their_names() {
        let data = [
            json!({"name": "Switch", "value": false}),
            json!({"name": "Limit", "value": 17}),
            json!({"name": "Empty", "value": null}),
        ];
        let output = DefaultFormatter
            .format(&data, OutputFormat::Compact)
            .unwrap();
        assert_eq!(
            output,
            "Switch  value=false\nLimit  value=17\nEmpty  value=null\n"
        );
    }

    #[test]
    fn compact_truncation_preserves_utf8_and_existing_byte_budget() {
        for (value, displayed) in [
            ("x".repeat(80), "x".repeat(80)),
            ("x".repeat(81), format!("{}...", "x".repeat(77))),
            ("あ".repeat(30), format!("{}...", "あ".repeat(25))),
            ("😀".repeat(21), format!("{}...", "😀".repeat(19))),
            (
                format!("{}ああ", "x".repeat(76)),
                format!("{}...", "x".repeat(76)),
            ),
        ] {
            let output = DefaultFormatter
                .format(&[json!({"value": value})], OutputFormat::Compact)
                .unwrap();
            assert_eq!(output, format!("\"{displayed}\"\n"));
        }
    }

    #[test]
    fn delimited_output_round_trips_special_cells_and_array_representation() {
        for (format, delimiter) in [(OutputFormat::Csv, b','), (OutputFormat::Tsv, b'\t')] {
            let values = [
                "void f(int a, int b)",
                "a\tb",
                "say \"hello\"",
                "first\nsecond",
                "first\rsecond",
                "",
                "日本語",
            ];
            let data: Vec<_> = values
                .iter()
                .map(|value| json!({"tags": ["crypto", "reviewed"], "value": value}))
                .collect();
            let output = DefaultFormatter.format(&data, format).unwrap();
            let mut reader = csv::ReaderBuilder::new()
                .delimiter(delimiter)
                .from_reader(output.as_bytes());
            assert_eq!(
                reader.headers().unwrap(),
                &csv::StringRecord::from(vec!["tags", "value"])
            );
            let records: Vec<_> = reader
                .records()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(records.len(), values.len());
            for (record, expected) in records.iter().zip(values) {
                assert_eq!(&record[0], "crypto;reviewed");
                assert_eq!(&record[1], expected);
            }
        }
    }

    #[test]
    fn delimited_headers_arrays_and_objects_are_escaped_as_complete_cells() {
        let key = "field,\t\"\n";
        for (format, delimiter) in [(OutputFormat::Csv, b','), (OutputFormat::Tsv, b'\t')] {
            for (value, expected) in [
                (
                    json!(["a,b", "c\td", "e\nf", "\"g\""]),
                    "a,b;c\td;e\nf;\"g\"".to_string(),
                ),
                (
                    json!({"name": "a,b\tc"}),
                    r#"{"name":"a,b\tc"}"#.to_string(),
                ),
            ] {
                let output = DefaultFormatter
                    .format(&[json!({key: value})], format)
                    .unwrap();
                let mut reader = csv::ReaderBuilder::new()
                    .delimiter(delimiter)
                    .from_reader(output.as_bytes());
                assert_eq!(reader.headers().unwrap().get(0), Some(key));
                let records: Vec<_> = reader
                    .records()
                    .collect::<std::result::Result<_, _>>()
                    .unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].get(0), Some(expected.as_str()));
            }
        }
    }

    #[test]
    fn delimited_single_empty_cells_remain_records() {
        for (format, delimiter) in [(OutputFormat::Csv, b','), (OutputFormat::Tsv, b'\t')] {
            let output = DefaultFormatter
                .format(&[json!({"value": ""}), json!({})], format)
                .unwrap();
            let mut reader = csv::ReaderBuilder::new()
                .delimiter(delimiter)
                .from_reader(output.as_bytes());
            let records: Vec<_> = reader
                .records()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|record| record.get(0) == Some("")));
            assert_eq!(
                DefaultFormatter.format::<JsonValue>(&[], format).unwrap(),
                ""
            );
        }
    }
}
