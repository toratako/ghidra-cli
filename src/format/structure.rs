use super::format_json_value;
use serde_json::Value;

/// Keep the candidate and omitted-evidence information visible in human output.
pub(super) fn format_result(value: &Value, output: &mut String, full: bool) -> bool {
    let Some(structure) = value.get("structure") else {
        return false;
    };
    output.push_str("Structure inference");
    if let Some(function) = value.get("function").and_then(Value::as_str) {
        output.push_str(&format!(": {function}"));
    }
    if let Some(address) = value.get("address").and_then(Value::as_str) {
        output.push_str(&format!(" ({address})"));
    }
    output.push('\n');
    if let Some(variable) = value.get("variable") {
        output.push_str(&format!("Variable: {}\n", format_json_value(variable)));
    }
    if structure.is_null() {
        output.push_str("No structure inferred\n");
    } else {
        output.push_str(&format!(
            "Candidate size: {} bytes (Ghidra inference)\n",
            format_json_value(&structure["size"])
        ));
        if full {
            output.push_str(&format!(
                "Packing enabled: {}\n",
                format_json_value(&structure["packing_enabled"])
            ));
        }
        if let Some(components) = structure["components"].as_array() {
            output.push_str("Components:\n");
            for component in components {
                output.push_str(&format!("  {}\n", format_json_value(component)));
            }
        }
    }
    if let Some(accesses) = value.get("accesses").and_then(Value::as_array) {
        output.push_str("Recorded accesses:\n");
        for access in accesses {
            output.push_str(&format!("  {}\n", format_json_value(access)));
        }
    }
    if let Some(status) = value.get("accesses_status") {
        output.push_str(&format!(
            "Accesses returned: {} of {} recorded{}\n",
            format_json_value(&status["returned"]),
            format_json_value(&status["total"]),
            if status["truncated"] == true {
                " (truncated)"
            } else {
                ""
            }
        ));
    }
    if let Some(warnings) = value.get("warnings").and_then(Value::as_array) {
        for warning in warnings {
            if let Some(text) = super::decompile::format_decompile_warning(warning) {
                output.push_str(&format!("Warning: {text}\n"));
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn human_inference_distinguishes_empty_candidates_and_truncated_evidence() {
        let result = json!({
            "function":"process", "address":"0x1000", "variable":{"name":"ctx"},
            "structure":{"size":20,"packing_enabled":false,"components":[{"offset":16,"type":"int","size":4}]},
            "accesses":[{"offset":16,"mnemonic":"LOAD","instruction_address":"0x1004"}],
            "accesses_status":{"returned":1,"total":2,"truncated":true},
            "warnings":[{"source":"decompiler","message":"partial recovery","address":null}]
        });
        for full in [false, true] {
            let mut text = String::new();
            assert!(format_result(&result, &mut text, full));
            for expected in [
                "ctx",
                "Candidate size: 20",
                "int",
                "LOAD",
                "0x1004",
                "1 of 2 recorded (truncated)",
                "partial recovery",
            ] {
                assert!(text.contains(expected), "{text}");
            }
            text.clear();
            assert!(format_result(&json!({"structure":null}), &mut text, full));
            assert!(text.contains("No structure inferred"));
        }
    }
}
