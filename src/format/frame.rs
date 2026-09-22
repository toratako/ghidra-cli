use serde_json::Value;

pub(super) fn format_details(details: &Value, output: &mut String) {
    output.push_str(&format!(
        "Saved stack frame: size={} local={} parameters={} grows_negative={}\n",
        details["frame_size"],
        details["local_size"],
        details["parameter_size"],
        details["grows_negative"]
    ));
    if let Some(owner) = details["effective_function"].as_str() {
        output.push_str(&format!(
            "  Metadata owner: {owner} ({})\n",
            details["effective_address"].as_str().unwrap_or("?")
        ));
    }
    output.push_str(&format!(
        "  Parameter offset: {}; return-address offset: {}\n",
        details["parameter_offset"], details["return_address_offset"]
    ));
    if let Some(variables) = details["stack_variables"].as_array() {
        if variables.is_empty() {
            output.push_str("  Stack variables: none saved\n");
        } else {
            output.push_str("  Stack variables:\n");
            for variable in variables {
                output.push_str(&format!(
                    "    {} {}: {} ({}; offset={} stack_size={} source={})\n",
                    variable["kind"].as_str().unwrap_or("?"),
                    variable["name"].as_str().unwrap_or("?"),
                    variable["type"].as_str().unwrap_or("?"),
                    variable["storage"].as_str().unwrap_or("?"),
                    variable["stack_offset"],
                    variable["stack_size"],
                    variable["source"].as_str().unwrap_or("?")
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::format::{DefaultFormatter, Formatter, OutputFormat};
    use serde_json::json;

    #[test]
    fn frame_rendering_keeps_saved_owner_offsets_and_variables_after_projection() {
        let details = json!({
            "effective_function": "callee", "effective_address": "0x1000",
            "frame_size": 12, "local_size": 8, "parameter_size": 4,
            "parameter_offset": 4, "return_address_offset": 0, "grows_negative": true,
            "stack_variables": [{"kind": "local", "name": "count", "type": "int",
                "storage": "Stack[-0x8]:4", "stack_offset": -8, "stack_size": 4,
                "source": "USER_DEFINED"}],
        });
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            for response in [
                json!({"name": "thunk", "frame_details": details}),
                json!({"frame_details": details}),
            ] {
                let rendered = DefaultFormatter.format(&[response], format).unwrap();
                assert!(rendered.contains("Saved stack frame: size=12 local=8 parameters=4"));
                assert!(rendered.contains("Metadata owner: callee (0x1000)"));
                assert!(rendered.contains("Parameter offset: 4; return-address offset: 0"));
                assert!(rendered.contains(
                    "local count: int (Stack[-0x8]:4; offset=-8 stack_size=4 source=USER_DEFINED)"
                ));
                assert_eq!(rendered.matches("Saved stack frame:").count(), 1);
            }
        }
    }

    #[test]
    fn compact_variable_and_override_results_preserve_explicit_absence() {
        for response in [
            json!({"address": "0x1000", "database": null}),
            json!({"address": "0x1000", "before": null, "after": {"name": "count"}}),
            json!({"address": "0x1000", "call_site": "0x1010", "override": null}),
        ] {
            let rendered = DefaultFormatter
                .format(&[&response], OutputFormat::Compact)
                .unwrap();
            for field in ["database", "before", "override"] {
                if response.get(field).is_some() {
                    assert!(rendered.contains(&format!("{field}=null")), "{rendered}");
                }
            }
        }
    }
}
