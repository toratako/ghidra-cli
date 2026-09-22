use serde_json::Value;

pub(super) fn format_details(details: &Value, output: &mut String) {
    let text = |key| details[key].as_str().unwrap_or("?");
    output.push_str(&format!(
        "Program signature: source={} storage={} variadic={}\n",
        text("source"),
        text("storage_mode"),
        details["variadic"]
    ));
    if let Some(target) = details["thunk_function"].as_str() {
        output.push_str(&format!(
            "  Direct thunk target: {target} ({})\n",
            text("thunk_address")
        ));
    }
    if let Some(owner) = details["effective_function"].as_str() {
        output.push_str(&format!(
            "  Metadata owner: {owner} ({})\n",
            text("effective_address")
        ));
    }
    output.push_str("  Return: ");
    format_variable(&details["return"], output);
    if let Some(params) = details["params"].as_array() {
        if params.is_empty() {
            output.push_str("  Parameters: none defined\n");
        } else {
            output.push_str("  Parameters:\n");
            for param in params {
                output.push_str(&format!(
                    "    [{}] {}: ",
                    param["ordinal"],
                    param["name"].as_str().unwrap_or("?")
                ));
                format_variable(param, output);
            }
        }
    }
}

fn format_variable(var: &Value, output: &mut String) {
    output.push_str(&format!(
        "{} ({} bytes; {})",
        var["type"].as_str().unwrap_or("?"),
        var["size"],
        var["storage"].as_str().unwrap_or("?")
    ));
    if let Some(auto) = var["auto_parameter"].as_str() {
        output.push_str(&format!(" auto={auto}"));
    }
    if var["forced_indirect"] == true {
        output.push_str(&format!(
            " indirect from {}",
            var["formal_type_path"].as_str().unwrap_or("?")
        ));
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use crate::format::{DefaultFormatter, Formatter, OutputFormat};
    use serde_json::json;

    #[test]
    fn signature_details_render_types_storage_and_provenance_after_projection() {
        let details = json!({
            "source": "USER_DEFINED", "storage_mode": "dynamic", "variadic": false,
            "effective_function": "callee", "effective_address": "0x1000",
            "thunk_function": "middle", "thunk_address": "0x2000",
            "return": {"type": "Result *", "size": 4, "storage": "EAX:4",
                "forced_indirect": true, "formal_type_path": "/Recovered/Result"},
            "params": [{"ordinal": 0, "name": "__return_storage_ptr__", "type": "Result *",
                "size": 4, "storage": "Stack[0x4]:4", "auto_parameter": "RETURN_STORAGE_PTR",
                "forced_indirect": false}]
        });
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            for response in [
                json!({"name": "thunk", "signature_details": details}),
                json!({"signature_details": details}),
            ] {
                let output = DefaultFormatter.format(&[response], format).unwrap();
                assert!(output.contains(
                    "Program signature: source=USER_DEFINED storage=dynamic variadic=false"
                ));
                assert!(output.contains("Direct thunk target: middle (0x2000)"));
                assert!(output.contains("Metadata owner: callee (0x1000)"));
                assert!(output
                    .contains("Return: Result * (4 bytes; EAX:4) indirect from /Recovered/Result"));
                assert!(output.contains("[0] __return_storage_ptr__: Result * (4 bytes; Stack[0x4]:4) auto=RETURN_STORAGE_PTR"));
                assert!(!output.contains("signature_details="));
                assert_eq!(output.matches("Program signature:").count(), 1);
            }
            let output = DefaultFormatter.format(&[json!({"signature_details": {
                "source": "DEFAULT", "storage_mode": "custom", "variadic": true,
                "return": {"type": "void", "size": 0, "storage": "<VOID>", "forced_indirect": false},
                "params": []
            }})], format).unwrap();
            assert!(output.contains("Return: void (0 bytes; <VOID>)"));
            assert!(output.contains("Parameters: none defined"));
        }
    }
}
