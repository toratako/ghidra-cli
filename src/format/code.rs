use super::{decompile, format_json_value, OutputFormat};
use crate::error::Result;
use serde::Serialize;
use serde_json::Value as JsonValue;

pub(super) fn format_code<T: Serialize>(data: &[T], format: OutputFormat) -> Result<String> {
    let rows = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut output = String::new();
    for row in &rows {
        match format {
            OutputFormat::C if row.get("code").and_then(JsonValue::as_str).is_some() => {
                output.push_str(&decompile::format_code(
                    row["code"].as_str().unwrap(),
                    row.get("line_addresses"),
                    decompile::AddressStyle::Comments,
                ));
            }
            OutputFormat::Asm
                if row.get("mnemonic").and_then(JsonValue::as_str).is_some()
                    && row.get("operands").and_then(JsonValue::as_array).is_some() =>
            {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn asm_keeps_raw_pcode_results_as_json() {
        let rows = [json!({
            "address": "0x1000", "mnemonic": "MOV", "instruction": "MOV EAX,EDX",
            "count": 1, "pcode": [{"mnemonic": "COPY", "output": {"register": "EAX"},
                "inputs": [{"register": "EDX"}]}]
        })];
        let rendered = format_code(&rows, OutputFormat::Asm).unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&rendered).unwrap(),
            json!(rows)
        );
    }
}
