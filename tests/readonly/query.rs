use super::*;
use serde_json::{json, Value};

const LOCALE_SCRIPT: &str = r#"
import ghidra.app.script.GhidraScript;
import java.util.Locale;
public class QueryTestLocale extends GhidraScript {
    public void run() {
        writer.println(Locale.getDefault().toLanguageTag());
        Locale.setDefault(Locale.forLanguageTag(getScriptArgs()[0]));
    }
}
"#;

#[test]
#[serial]
fn server_list_pages_match_full_rows_and_rust_string_semantics() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("query-pages-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/scripts/CreateQueryFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let previous = client
        .script_run_source(LOCALE_SCRIPT, &["tr-TR".into()], &[], false)
        .unwrap();
    let previous = previous["stdout"].as_str().unwrap().trim().to_string();
    let checked = std::panic::catch_unwind(|| {
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("config.yaml");
        std::fs::write(&config, "aliases: {}\ndefault_limit: 2\n").unwrap();
        let cli = |command: &[&str], flags: &[&str]| -> Value {
            let result = ghidra(harness)
                .args(command.iter().copied())
                .args(flags.iter().copied())
                .arg("--json")
                .with_project(test_project(), &name)
                .env("GHIDRA_CLI_CONFIG", config.to_string_lossy())
                .run();
            result.assert_success();
            result.json()
        };
        for (command, wire, key, field) in [
            (["function", "list"], "list_functions", "functions", "name"),
            (["symbol", "list"], "symbol_list", "symbols", "name"),
            (["type", "list"], "type_list", "types", "name"),
            (["comment", "list"], "comment_list", "comments", "text"),
            (["strings", "list"], "list_strings", "strings", "value"),
            (
                ["query", "functions"],
                "list_functions",
                "functions",
                "name",
            ),
            (["query", "strings"], "list_strings", "strings", "value"),
            (["dump", "functions"], "list_functions", "functions", "name"),
            (["dump", "strings"], "list_strings", "strings", "value"),
        ] {
            let all = client.send_command(wire, Some(json!({"limit":0}))).unwrap();
            let rows = all[key].as_array().unwrap();
            assert!(rows.len() > 4, "{wire}: {all}");
            assert_eq!(cli(&command, &[]), json!(&rows[..2]), "{command:?}");
            // Both raw bridge pages and CLI pages must equal local slices.
            for (offset, limit) in [(0usize, 2usize), (1, 2), (2, 0), (10000, 1)] {
                let expected: Vec<_> = rows
                    .iter()
                    .skip(offset)
                    .take(if limit == 0 { usize::MAX } else { limit })
                    .cloned()
                    .collect();
                let page = client
                    .send_command(wire, Some(json!({"offset":offset, "limit":limit})))
                    .unwrap();
                assert_eq!(page[key], json!(expected), "{wire}, {offset}, {limit}");
                assert_eq!(page["count"], expected.len());
                assert_eq!(
                    cli(
                        &command,
                        &[
                            "--offset",
                            &offset.to_string(),
                            "--limit",
                            &limit.to_string()
                        ]
                    ),
                    json!(expected)
                );
            }
            // Unicode and Turkish JVM locale must not change Rust's contains semantics.
            for needle in ["i", "FILE", "ä", "İ", "ος", "Σ", "東京", "absent", ""] {
                let matching: Vec<_> = rows
                    .iter()
                    .filter(|row| {
                        row[field]
                            .as_str()
                            .unwrap()
                            .to_lowercase()
                            .contains(&needle.to_lowercase())
                    })
                    .cloned()
                    .collect();
                let filter = format!("{field}~'{needle}'");
                let server = client
                    .send_command(wire, Some(json!({"filter":needle, "offset":1, "limit":2})))
                    .unwrap();
                let expected: Vec<_> = matching.iter().skip(1).take(2).cloned().collect();
                assert_eq!(server[key], json!(expected), "{wire}, {needle:?}");
                assert_eq!(
                    cli(&command, &["--filter", &filter, "--offset", "1"]),
                    json!(expected)
                );
                assert_eq!(
                    cli(&command, &["--filter", &filter, "--limit", "0"]),
                    json!(matching)
                );
                assert_eq!(
                    cli(&command, &["--filter", &filter, "--count"]),
                    json!(matching.len())
                );
                assert_eq!(
                    cli(
                        &command,
                        &["--filter", &filter, "--offset", "1", "--limit", "1", "--count"]
                    ),
                    json!(matching.len().saturating_sub(1).min(1))
                );
            }
            // Values beyond i32 must not wrap into another page or an unlimited limit.
            let beyond = client
                .send_command(wire, Some(json!({"offset":4294967296u64,"limit":1})))
                .unwrap();
            assert_eq!(beyond[key], json!([]));
            let large = client
                .send_command(wire, Some(json!({"limit":4294967296u64})))
                .unwrap();
            assert_eq!(large[key], json!(rows));
            for invalid in [
                json!({"offset":-1}),
                json!({"limit":1.5}),
                json!({"offset":u64::MAX}),
            ] {
                assert!(client.send_command(wire, Some(invalid)).is_err());
            }
        }
        // Tag/untagged predicates precede offset, which may exhaust a match set.
        let all = client
            .list_functions(None, Some("FILE".into()), &["selected".into()], false, None)
            .unwrap();
        let rows = all["functions"].as_array().unwrap();
        assert!(rows.len() >= 2);
        assert_eq!(
            cli(
                &["function", "list"],
                &[
                    "--tag",
                    "selected",
                    "--filter",
                    "name~FILE",
                    "--offset",
                    "1",
                    "--limit",
                    "1"
                ]
            ),
            json!(&rows[1..2])
        );
        assert_eq!(
            cli(
                &["function", "list"],
                &["--tag", "selected", "--filter", "name~i", "--offset", "2", "--limit", "1"]
            ),
            json!([])
        );
        assert_eq!(
            cli(
                &["function", "list"],
                &[
                    "--untagged",
                    "--filter",
                    "name~i",
                    "--offset",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "name"
                ]
            ),
            json!([{"name":"file_C"}])
        );
        let remaining = cli(
            &["function", "list"],
            &[
                "--filter",
                "name~FILE AND size>1",
                "--sort=-size",
                "--fields",
                "name",
                "--limit",
                "1",
            ],
        );
        assert_eq!(remaining, json!([{"name":"file_C"}]));
    });
    client
        .script_run_source(LOCALE_SCRIPT, &[previous], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
