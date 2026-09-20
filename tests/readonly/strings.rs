use super::*;
use serde_json::{json, Value};

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
            assert!(row.get("length").is_none(), "{row}");
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
            output.json()
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
        let flags = ["--filter", "value~_A", "--offset", "1", "--limit", "1"];
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
                &["--filter", "value~_", "--offset", "1", "--limit", "2", "--count"]
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
