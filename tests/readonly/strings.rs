use super::*;
use serde_json::{json, Value};

#[test]
#[serial]
fn string_refs_include_interior_destinations_and_report_byte_offsets() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("string-interior-refs-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/scripts/CreateStringFixture.java"),
            &[name.clone(), "é_suffix".into()],
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
public class AddInteriorStringRefs extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        currentProgram.getMemory().createInitializedBlock("references", space.getAddress(0x1000),
            0x100, (byte) 0, monitor, false);
        var refs = currentProgram.getReferenceManager();
        for (int encoding = 0; encoding < 2; encoding++) {
            var start = space.getAddress(0x2000 + encoding * 0x1000);
            var data = currentProgram.getListing().getDataAt(start);
            var from = space.getAddress(0x1000 + encoding * 0x10);
            var suffix = start.add(encoding == 0 ? 3 : 4);
            refs.addMemoryReference(from, start, RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(1), suffix, RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(1), suffix, RefType.DATA, SourceType.USER_DEFINED, 1);
            refs.addMemoryReference(from.add(2), data.getMaxAddress(),
                RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(3), start.subtract(1),
                RefType.DATA, SourceType.USER_DEFINED, 0);
            refs.addMemoryReference(from.add(4), data.getMaxAddress().add(1),
                RefType.DATA, SourceType.USER_DEFINED, 0);
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let found = client.find_string("suffix").unwrap();
        assert_eq!(found["count"], 2);
        let references = client.string_refs("suffix".into()).unwrap();
        let mut expected = Vec::new();
        for (encoding, (start, suffix_offset, last_offset)) in
            [(0x2000, 3, 9), (0x3000, 4, 17)].into_iter().enumerate()
        {
            let string_address = format!("0x{start:08x}");
            for (source_offset, string_offset) in [
                (0, 0),
                (1, suffix_offset),
                (1, suffix_offset),
                (2, last_offset),
            ] {
                expected.push(json!({
                    "string_address": string_address,
                    "string_value": "é_suffix",
                    "from": format!("0x{:08x}", 0x1000 + encoding * 0x10 + source_offset),
                    "to": format!("0x{:08x}", start + string_offset),
                    "string_offset": string_offset,
                    "ref_type": "DATA",
                    "from_function": null,
                }));
            }
            let interior = client
                .xrefs_to(format!("0x{:x}", start + suffix_offset))
                .unwrap();
            assert_eq!(interior["count"], 2);
        }
        assert_eq!(references["results"], json!(expected));
        assert_eq!(references["count"], expected.len());
        let data = client.send_command("data_list", None).unwrap();
        assert_eq!(data["count"], 2);
        for row in data["items"].as_array().unwrap() {
            assert_eq!(row["incoming_reference_count"], 4);
        }
        let output = ghidra(harness)
            .args(["string", "refs", "suffix", "--limit", "0", "--json"])
            .with_project(test_project(), &name)
            .run();
        output.assert_success();
        assert_eq!(output.data::<Value>(), references["results"]);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn defined_strings_share_lengths_and_page_after_both_predicates() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("strings-{}", uuid::Uuid::new_v4());
    let values = [
        "Password", "日本", "😀", "e\u{301}", "", "plain", "FILE_A", "skip_A", "FILE_B", "file_C",
    ];
    let mut args = vec![name.clone()];
    args.extend(values.iter().map(|s| s.to_string()));
    client
        .script_run_source(
            include_str!("../fixtures/scripts/CreateStringFixture.java"),
            &args,
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let listed = client.list_strings(None, None, None).unwrap();
        let found = client.find_string("").unwrap();
        assert_eq!(listed["strings"], found["results"]);
        let rows = listed["strings"].as_array().unwrap();
        assert_eq!(rows.len(), values.len() * 2);
        assert_eq!(listed["count"], rows.len());
        assert_eq!(found["count"], rows.len());
        for (i, row) in rows.iter().enumerate() {
            let value = values[i % values.len()];
            let terminator = usize::from(value != "plain");
            let byte_length = if i < values.len() {
                value.len() + terminator
            } else {
                (value.encode_utf16().count() + terminator) * 2
            };
            assert_eq!(row["value"], value, "{row}");
            assert_eq!(row["char_length"], value.chars().count(), "{row}");
            assert_eq!(row["byte_length"], byte_length, "{row}");
        }
        // Pattern and filter are independent AND predicates, before offset/limit.
        // skip_A matches the filter but must not consume a matching-row offset.
        for (pattern, filter) in [("file", "_A"), ("FILE", "_"), ("absent", "_"), ("", "")] {
            let matching: Vec<_> = rows
                .iter()
                .filter(|row| {
                    let value = row["value"].as_str().unwrap().to_lowercase();
                    value.contains(&pattern.to_lowercase())
                        && value.contains(&filter.to_lowercase())
                })
                .cloned()
                .collect();
            for (offset, limit) in [(0, 1), (1, 2), (2, 0), (100, 1)] {
                let expected: Vec<_> = matching
                    .iter()
                    .skip(offset)
                    .take(if limit == 0 { usize::MAX } else { limit })
                    .cloned()
                    .collect();
                let page = client
                    .find_string_page(pattern, Some(limit), Some(filter.into()), Some(offset))
                    .unwrap();
                assert_eq!(
                    page["results"],
                    json!(expected),
                    "{pattern:?}, {filter:?}, {offset}, {limit}"
                );
                assert_eq!(page["count"], expected.len());
            }
        }
        let cli = |command: &[&str], flags: &[&str]| -> Value {
            let output = ghidra(harness)
                .args(command.iter().copied())
                .args(flags.iter().copied())
                .arg("--json")
                .with_project(test_project(), &name)
                .run();
            output.assert_success();
            output.data()
        };
        for command in [&["string", "list"][..], &["find", "string", ""][..]] {
            let flags = ["--filter", "char_length=1", "--limit", "0"];
            assert_eq!(cli(command, &flags), json!([rows[2], rows[12]]));
            let flags = ["--filter", "byte_length=7", "--limit", "0"];
            assert_eq!(
                cli(command, &flags),
                json!([rows[1], rows[6], rows[7], rows[8], rows[9]])
            );
            assert_eq!(cli(command, &["--filter", "char_length=1", "--count"]), 2);
        }
        let flags = ["--filter", "value~_A", "--skip", "1", "--limit", "1"];
        assert_eq!(cli(&["find", "string", "file"], &flags), json!([rows[16]]));
        // Projection follows sorting, and counts select the requested page.
        let flags = [
            "--filter",
            "char_length=1",
            "--sort=-byte_length",
            "--fields",
            "value,byte_length",
            "--limit",
            "0",
        ];
        assert_eq!(
            cli(&["find", "string", "😀"], &flags),
            json!([
                {"value":"😀", "byte_length":6}, {"value":"😀", "byte_length":5}
            ])
        );
        assert_eq!(
            cli(
                &["find", "string", "file"],
                &["--filter", "value~_", "--skip", "1", "--limit", "2", "--count"]
            ),
            2
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn defined_strings_and_references_include_nested_structures_and_arrays() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("nested-strings-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/scripts/CreateNestedStringFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let expected: Vec<_> = ["nest_A", "nest_B", "nest_C"]
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                json!({
                    "address": format!("0x{:08x}", 0x2000 + i * 8),
                    "value": value,
                    "char_length": 6,
                    "byte_length": 8,
                })
            })
            .collect();
        assert_eq!(
            client.list_strings(None, None, None).unwrap()["strings"],
            json!(expected)
        );
        assert_eq!(
            client.find_string("NEST").unwrap()["results"],
            json!(expected)
        );
        let page = client
            .find_string_page("nest", Some(1), Some("_".into()), Some(1))
            .unwrap();
        assert_eq!(page["results"], json!([expected[1]]));
        let refs = client.string_refs("nest".into()).unwrap();
        assert_eq!(refs["count"], 3);
        for (i, row) in refs["results"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["string_address"], expected[i]["address"]);
            assert_eq!(row["string_value"], expected[i]["value"]);
            assert_eq!(row["from"], format!("0x{:08x}", 0x1000 + i));
            assert_eq!(row["to"], format!("0x{:08x}", 0x2002 + i * 8));
            assert_eq!(row["string_offset"], 2);
        }
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
