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
        for (params, variables) in [(false, false), (true, false), (false, true), (true, true)] {
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
fn human_decompile_addresses_follow_physical_lines_and_preserve_details() {
    let code = concat!(
        "\nint 日本語(void)\n\n{\n",
        "  /* first\n     second */\n  \n",
        "  return call(1) + call(2);\n}\n\n"
    );
    let response = json!({
        "code": code,
        "name": "日本語",
        "signature": "int 日本語(void)",
        "line_addresses": [{"line": 8, "addresses": ["0x1004", "0x1010", "0x1017"]}],
        "basic_block_count": 1,
        "warnings": [{"source": "decompiler", "address": null, "message": "partial recovery"}],
        "params": [{"name": "count", "type": "int", "storage": "register:0"}]
    });
    for format in [OutputFormat::Compact, OutputFormat::Full] {
        let output = DefaultFormatter.format(&[&response], format).unwrap();
        let rendered_lines: Vec<_> = output
            .lines()
            .filter_map(|line| line.split_once(" | "))
            .collect();
        assert_eq!(rendered_lines.len(), 10);
        for (index, ((gutter, text), original)) in
            rendered_lines.iter().zip(code.lines()).enumerate()
        {
            assert_eq!(*text, original);
            let (line, addresses) = gutter.trim().split_once("  ").unwrap();
            assert_eq!(line.parse::<usize>().unwrap(), index + 1);
            assert_eq!(
                addresses.trim(),
                if index == 7 {
                    "0x1004, 0x1010, 0x1017"
                } else {
                    "-"
                }
            );
        }
        assert!(rendered_lines[0].0.starts_with(" 1"));
        assert!(rendered_lines[9].0.starts_with("10"));
        assert!(output.contains("Basic blocks (decompiler): 1\n"));
        assert!(output.contains("Warnings:\n  [decompiler] partial recovery\n"));
        assert!(output.contains("Parameters:\n  int count (register:0)\n"));
    }
}

#[test]
fn c_decompile_addresses_preserve_comments_and_escaped_literals() {
    // Native comment tokens have no operation mapping. Quoted literals are
    // emitted as whole tokens, including escaped backslashes and newlines.
    let code = concat!(
        "\nvoid example(void)\n{\n",
        "  /* 日本語 \\\n",
        "     second line */\n",
        "  print(\"a\\\\b\\n\");\n",
        "  return; // existing comment\n}\n\n"
    );
    let response = json!({
        "code": code,
        "line_addresses": [
            {"line": 6, "addresses": ["0x1004", "0x1008"]},
            {"line": 7, "addresses": ["0x1010"]}
        ],
        "warnings": [{"source": "decompiler", "address": null, "message": "partial recovery"}]
    });
    let output = DefaultFormatter
        .format(&[&response], OutputFormat::C)
        .unwrap();
    assert_eq!(
        output,
        concat!(
            "\nvoid example(void)\n{\n",
            "  /* 日本語 \\\n",
            "     second line */\n",
            "  print(\"a\\\\b\\n\"); // @ 0x1004, 0x1008\n",
            "  return; // existing comment // @ 0x1010\n}\n\n"
        )
    );
    for format in [
        OutputFormat::Json,
        OutputFormat::JsonCompact,
        OutputFormat::JsonStream,
    ] {
        let output = DefaultFormatter.format(&[&response], format).unwrap();
        let value: JsonValue = serde_json::from_str(&output).unwrap();
        assert_eq!(
            if format == OutputFormat::JsonStream {
                &value
            } else {
                &value[0]
            },
            &response
        );
    }
}

#[test]
fn empty_decompile_addresses_are_distinct_from_absent_annotations() {
    let code = "return 1;\n\n";
    let requested = json!({"code": code, "line_addresses": []});
    let absent = json!({"code": code});
    for format in [OutputFormat::Compact, OutputFormat::Full] {
        let requested = DefaultFormatter.format(&[&requested], format).unwrap();
        let absent = DefaultFormatter.format(&[&absent], format).unwrap();
        assert!(requested.contains("1  - | return 1;\n2  - | \n"));
        assert!(absent.ends_with(code));
        assert!(!absent.contains(" | "));
    }
    assert_eq!(
        DefaultFormatter
            .format(&[requested], OutputFormat::C)
            .unwrap(),
        code
    );
}

#[test]
fn decompile_field_projection_controls_annotations_and_code_fallback() {
    use crate::query::{FieldSelector, Query};

    let code = "return 1;\n";
    let rows = [json!({
        "code": code,
        "name": "example",
        "line_addresses": [{"line": 1, "addresses": ["0x1004"]}]
    })];
    let query = Query::default();
    let plain = query
        .select_fields(
            &rows,
            &FieldSelector::exclude(vec!["line_addresses".into()]),
        )
        .unwrap();
    for format in [OutputFormat::Compact, OutputFormat::Full, OutputFormat::C] {
        let output = DefaultFormatter.format(&plain, format).unwrap();
        assert!(output.ends_with(code));
        assert!(!output.contains("0x1004"));
    }
    let without_code = query
        .select_fields(&rows, &FieldSelector::exclude(vec!["code".into()]))
        .unwrap();
    let output = DefaultFormatter
        .format(&without_code, OutputFormat::C)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<JsonValue>>(&output).unwrap(),
        without_code
    );
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
