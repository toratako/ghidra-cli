use super::format_json_value;
use serde_json::Value;

/// Keep slot identities, local failures, and header completeness visible together.
pub(super) fn format_result(value: &Value, output: &mut String, full: bool) -> bool {
    let (
        Some(abi @ ("itanium" | "msvc")),
        Some(encoding @ ("absolute" | "relative32")),
        Some(entries),
    ) = (
        value["abi"].as_str(),
        value["encoding"].as_str(),
        value["entries"].as_array(),
    )
    else {
        return false;
    };
    output.push_str("Vtable");
    if let Some(address) = value.get("address") {
        output.push_str(&format!(": {}", format_json_value(address)));
    }
    output.push_str(&format!(" ({abi}, {encoding})\n"));
    if value.get("requested_entries").is_some()
        || value.get("read_entries").is_some()
        || value.get("complete").is_some()
    {
        output.push_str("Read:");
        field(value, "requested_entries", "requested", output);
        field(value, "read_entries", "read", output);
        completion(value, output);
        output.push('\n');
    }
    if full {
        for key in ["pointer_size", "entry_size", "endian"] {
            if let Some(value) = value.get(key) {
                output.push_str(&format!("{key}: {}\n", format_json_value(value)));
            }
        }
    }
    if let Some(header) = value.get("header") {
        if header.is_null() {
            output.push_str("Header: null\n");
        } else {
            output.push_str("Header:");
            completion(header, output);
            field(header, "error", "error", output);
            output.push('\n');
            for (key, label) in [
                ("offset_to_top", "Offset-to-top"),
                ("rtti_reference", "RTTI reference"),
                ("rtti", "RTTI"),
                ("complete_object_locator", "Complete Object Locator"),
            ] {
                if let Some(value) = header.get(key) {
                    output.push_str(&format!("  {label}:"));
                    pointer(value, output, full);
                    output.push('\n');
                }
            }
            if let Some(locator) = header.get("locator") {
                output.push_str("  Locator:");
                if locator.is_null() {
                    output.push_str(" null");
                } else {
                    for key in [
                        "address",
                        "signature",
                        "offset",
                        "cd_offset",
                        "image_base",
                        "self_matches",
                    ] {
                        field(locator, key, key, output);
                    }
                    completion(locator, output);
                    if locator["readable"] == false {
                        output.push_str(" [unreadable]");
                    }
                    field(locator, "error", "error", output);
                }
                output.push('\n');
                for (key, label) in [
                    ("type_descriptor", "Type descriptor"),
                    ("class_descriptor", "Class descriptor"),
                    ("self", "Self"),
                ] {
                    if let Some(value) = locator.get(key) {
                        output.push_str(&format!("    {label}:"));
                        pointer(value, output, full);
                        output.push('\n');
                    }
                }
            }
        }
    }
    output.push_str(&format!("Slots ({}):\n", entries.len()));
    for entry in entries {
        output.push_str("  ");
        if let Some(index) = entry.get("index") {
            output.push_str(&format!("[{}]", format_json_value(index)));
        }
        pointer(entry, output, full);
        output.push('\n');
    }
    true
}

fn field(value: &Value, key: &str, label: &str, output: &mut String) {
    if let Some(value) = value.get(key) {
        output.push_str(&format!(" {label}={}", format_json_value(value)));
    }
}

fn completion(value: &Value, output: &mut String) {
    if let Some(complete) = value.get("complete") {
        output.push_str(match complete.as_bool() {
            Some(true) => " [complete]",
            Some(false) => " [INCOMPLETE]",
            None => " [completion unknown]",
        });
    }
}

fn pointer(value: &Value, output: &mut String, full: bool) {
    if value.is_null() {
        output.push_str(" null");
        return;
    }
    for (key, label) in [
        ("address", "storage"),
        ("value", "raw"),
        ("signed_value", "signed"),
        ("displacement", "displacement"),
        ("rva", "rva"),
        ("target_address", "target"),
        ("function", "function"),
        ("function_address", "function_address"),
    ] {
        field(value, key, label, output);
    }
    for (key, label) in [
        ("symbol", "symbol"),
        ("thunk_target", "thunk"),
        ("thunk_final_target", "final"),
    ] {
        if full || value.get(key).is_some_and(|value| !value.is_null()) {
            field(value, key, label, output);
        }
    }
    if let Some(readable) = value.get("readable") {
        match readable.as_bool() {
            Some(false) => output.push_str(" [unreadable]"),
            None => output.push_str(" [readability unknown]"),
            Some(true) => {}
        }
    }
    if let Some(is_null) = value.get("is_null") {
        match is_null.as_bool() {
            Some(true) => output.push_str(" [null]"),
            None => output.push_str(" [null unknown]"),
            Some(false) => {}
        }
    }
    if value["mapped"] == false {
        output.push_str(" [unmapped]");
    }
    if full {
        for key in ["offset", "size", "relative_base", "code_address", "mapped"] {
            field(value, key, key, output);
        }
    }
    field(value, "error", "error", output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{DefaultFormatter, Formatter, OutputFormat};
    use serde_json::json;

    #[test]
    fn incomplete_tables_keep_null_unreadable_unresolved_and_thunks_distinct() {
        let value = json!({
            "address":"0x4000", "abi":"itanium", "encoding":"absolute",
            "pointer_size":8, "entry_size":8, "endian":"little",
            "requested_entries":4, "read_entries":3, "complete":false,
            "header":{"complete":false,
                "offset_to_top":{"address":"0x3ff0","value":"0xfffffffffffffff0","signed_value":-16,"readable":true},
                "rtti":{"address":"0x3ff8","readable":false,"error":"header memory unavailable"}},
            "entries":[
                {"index":0,"address":"0x4000","value":"0x1001","target_address":"0x1001",
                    "function":"Base::thunk","function_address":"0x1000","readable":true,"is_null":false,
                    "thunk_target":{"name":"Base::adjust","address":"0x1100"},
                    "thunk_final_target":{"name":"Derived::run","address":"0x1200"}},
                {"index":1,"address":"0x4008","value":"0x0000","target_address":"0x0","readable":true,"is_null":true},
                {"index":2,"address":"0x4010","value":null,"target_address":null,"readable":false,"is_null":null,
                    "error":"slot memory unavailable"},
                {"index":3,"address":"0x4018","value":"0xffff","target_address":null,"readable":true,"is_null":false,
                    "error":"Relative target exceeds the address space"},
            ]
        });
        for full in [false, true] {
            let format = if full {
                OutputFormat::Full
            } else {
                OutputFormat::Compact
            };
            let text = DefaultFormatter
                .format(std::slice::from_ref(&value), format)
                .unwrap();
            for expected in [
                "Vtable: 0x4000 (itanium, absolute)",
                "requested=4 read=3 [INCOMPLETE]",
                "Header: [INCOMPLETE]",
                "signed=-16",
                "header memory unavailable",
                "target=0x1001",
                "function_address=0x1000",
                "Base::adjust",
                "Derived::run",
                "slot memory unavailable",
                "Relative target exceeds the address space",
            ] {
                assert!(text.contains(expected), "missing {expected}:\n{text}");
            }
            let null = text.lines().find(|line| line.starts_with("  [1]")).unwrap();
            assert!(
                null.contains("[null]") && !null.contains("unreadable"),
                "{text}"
            );
            let unreadable = text.lines().find(|line| line.starts_with("  [2]")).unwrap();
            assert!(
                unreadable.contains("[unreadable]") && unreadable.contains("[null unknown]"),
                "{text}"
            );
            let unresolved = text.lines().find(|line| line.starts_with("  [3]")).unwrap();
            assert!(
                unresolved.contains("target=null") && !unresolved.contains("[null]"),
                "{text}"
            );
            assert_eq!(text.contains("pointer_size: 8"), full);
        }
    }

    #[test]
    fn locator_errors_and_relative_metadata_remain_visible() {
        let mut output = String::new();
        assert!(format_result(
            &json!({
                "abi":"msvc", "encoding":"absolute", "entries":[],
                "header":{"complete":false,
                    "complete_object_locator":{"address":"0x3ff8","value":"0x5000","target_address":"0x5000"},
                    "locator":{"address":"0x5000","signature":1,"offset":16,"cd_offset":0,"self_matches":false,
                        "complete":false,"error":"COL self RVA mismatch",
                        "type_descriptor":{"value":"0x6000","rva":24576,"target_address":"0x406000"}}}
            }),
            &mut output,
            false
        ));
        for expected in [
            "Complete Object Locator:",
            "target=0x5000",
            "signature=1",
            "offset=16",
            "self_matches=false",
            "COL self RVA mismatch",
            "Type descriptor:",
            "rva=24576",
            "target=0x406000",
        ] {
            assert!(output.contains(expected), "{output}");
        }
    }

    #[test]
    fn projections_omit_unselected_fields_and_fall_back_without_layout_identity() {
        for value in [
            json!({"entries":[{"index":0}]}),
            json!({"abi":"itanium","encoding":"absolute","address":"0x4000"}),
            json!({"abi":"other","encoding":"absolute","entries":[]}),
        ] {
            let mut output = String::from("unchanged");
            assert!(!format_result(&value, &mut output, false));
            assert_eq!(output, "unchanged");
        }
        let mut output = String::new();
        assert!(format_result(
            &json!({
                "abi":"itanium","encoding":"relative32","entries":[{"index":2,"target_address":null}]
            }),
            &mut output,
            true
        ));
        assert!(output.contains("[2] target=null"), "{output}");
        for absent in [
            "Read:",
            "Header:",
            "storage=",
            "raw=",
            "[null]",
            "INCOMPLETE",
            "pointer_size:",
        ] {
            assert!(!output.contains(absent), "unexpected {absent}: {output}");
        }
    }
}
