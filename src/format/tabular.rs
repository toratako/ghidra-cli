use super::format_json_value;
use crate::error::Result;
use comfy_table::{presets::UTF8_FULL, Table};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashSet;

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

pub(super) fn format_table<T: Serialize>(data: &[T]) -> Result<String> {
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

pub(super) fn format_csv<T: Serialize>(data: &[T], delimiter: char) -> Result<String> {
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
