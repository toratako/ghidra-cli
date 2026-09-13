use crate::error::{GhidraError, Result};
use clap::ValueEnum;
use comfy_table::{presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    Full,
    Compact,
    Minimal,
    Json,
    JsonCompact,
    #[value(alias = "ndjson", help = "One JSON object per line (alias: ndjson)")]
    #[serde(alias = "ndjson")]
    JsonStream,
    Csv,
    Tsv,
    Table,
    Ids,
    Count,
    #[value(help = "Currently rendered as JSON")]
    Tree,
    #[value(help = "Currently rendered as JSON")]
    Hex,
    #[value(help = "Currently rendered as JSON")]
    Asm,
    #[value(help = "Currently rendered as JSON")]
    C,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        <Self as ValueEnum>::from_str(s, true)
            .map_err(|_| GhidraError::InvalidFormat(format!("Unknown format: {}", s)))
    }
}

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
            OutputFormat::Count => Ok(format!("{}", data.len())),
            OutputFormat::Table => format_table(data),
            OutputFormat::Csv => format_csv(data, ','),
            OutputFormat::Tsv => format_csv(data, '\t'),
            OutputFormat::Compact => format_compact(data),
            OutputFormat::Full => format_full(data),
            OutputFormat::Minimal | OutputFormat::Ids => format_minimal(data),
            _ => {
                // For other formats, default to JSON
                serde_json::to_string_pretty(data).map_err(|e| e.into())
            }
        }
    }
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

    // Get all keys from first object
    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(format!("{} results", data.len()));
    };

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

    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(String::new());
    };

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
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
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
                }

                // If we only have unknown fields, render as key=value pairs
                if parts.is_empty() {
                    let kv: Vec<String> = map
                        .iter()
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
                        )
                    })
                    .filter_map(|(k, v)| {
                        let s = format_json_value(v);
                        if s.is_empty() || s == "null" || s == "\"\"" {
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
                    result.push('\n');
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
                    if let Some(JsonValue::Array(params)) = map.get("params") {
                        if !params.is_empty() {
                            result.push_str("\nParameters:\n");
                            for p in params {
                                if let JsonValue::Object(obj) = p {
                                    let name =
                                        obj.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                    let typ =
                                        obj.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                    let storage =
                                        obj.get("storage").and_then(|v| v.as_str()).unwrap_or("?");
                                    result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                                }
                            }
                        }
                    }
                    if let Some(JsonValue::Array(vars)) = map.get("variables") {
                        if !vars.is_empty() {
                            result.push_str("\nVariables:\n");
                            for v in vars {
                                if let JsonValue::Object(obj) = v {
                                    let name =
                                        obj.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                    let typ =
                                        obj.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                    let storage =
                                        obj.get("storage").and_then(|v| v.as_str()).unwrap_or("?");
                                    result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                                }
                            }
                        }
                    }
                    continue;
                }

                // Calculate max key width for alignment
                let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);

                for (key, val) in map {
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
    fn test_format_json() {
        let data = vec![json!({"name": "test", "value": 123})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn test_format_count() {
        let data = vec![json!({"name": "test1"}), json!({"name": "test2"})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Count).unwrap();
        assert_eq!(result, "2");
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
