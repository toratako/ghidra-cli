use serde_json::Value as JsonValue;
use std::collections::HashMap;

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
