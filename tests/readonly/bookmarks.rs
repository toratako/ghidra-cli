use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

const BOOKMARK_STATE: &str = r#"
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import java.util.TreeMap;
public class ReadBookmarkState extends GhidraScript {
    public void run() {
        var sorted = new TreeMap<Long, JsonObject>();
        var bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (bookmarks.hasNext()) {
            var bookmark = bookmarks.next();
            var row = new JsonObject();
            row.addProperty("id", bookmark.getId());
            row.addProperty("address", bookmark.getAddress().toString());
            row.addProperty("type", bookmark.getTypeString());
            row.addProperty("category", bookmark.getCategory());
            row.addProperty("comment", bookmark.getComment());
            sorted.put(bookmark.getId(), row);
        }
        var rows = new JsonArray();
        sorted.values().forEach(rows::add);
        var result = new JsonObject();
        result.add("bookmarks", rows);
        result.addProperty("modification_number", currentProgram.getModificationNumber());
        writer.println(result);
    }
}
"#;

#[test]
#[serial]
fn bookmarks_preserve_annotations_and_query_exact_addresses() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("bookmark-queries-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreateBookmarkFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        assert!(client
            .send_command("bookmark_get", Some(json!({"address":"bookmark_target"})))
            .is_err());
        let state = || -> Value {
            let result = client
                .script_run_source(BOOKMARK_STATE, &[], &[], false)
                .unwrap();
            serde_json::from_str(result["stdout"].as_str().unwrap().trim()).unwrap()
        };
        let before = state();
        let all = client.send_command("bookmark_list", None).unwrap();
        let rows = all["bookmarks"].as_array().unwrap();
        assert_eq!(all["count"], 6);
        assert_eq!(rows.len(), 6);
        for row in rows {
            assert_eq!(row.as_object().unwrap().len(), 4);
            for field in ["address", "type", "category", "comment"] {
                assert!(row[field].is_string(), "{row}");
            }
        }
        let expected_entry = json!([
            {"address":"0x00001000", "type":"Error", "category":"Disassembler",
                "comment":"Unable to resolve instruction flow"},
            {"address":"0x00001000", "type":"Note", "category":"Disassembler",
                "comment":"User note: inspect the jump table"},
            {"address":"0x00001000", "type":"Note", "category":"Review",
                "comment":"User note: 東京"}
        ]);
        let entry = client
            .send_command("bookmark_get", Some(json!({"address":"0x1000"})))
            .unwrap();
        assert_eq!(entry["count"], 3);
        for expected in expected_entry.as_array().unwrap() {
            assert!(rows.contains(expected), "{all}");
            assert!(entry["bookmarks"].as_array().unwrap().contains(expected));
        }
        // Interior function addresses must not inherit bookmarks from its entry.
        for address in ["0x1001", "0x9020"] {
            assert_eq!(
                client
                    .send_command("bookmark_get", Some(json!({"address":address})))
                    .unwrap(),
                json!({"bookmarks":[], "count":0})
            );
        }
        for category in ["Analysis", "Unmapped", "External"] {
            let expected = rows.iter().find(|row| row["category"] == category).unwrap();
            let found = client
                .send_command("bookmark_get", Some(json!({"address":expected["address"]})))
                .unwrap();
            assert_eq!(found, json!({"bookmarks":[expected], "count":1}));
        }
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config = ghidra_cli::config::Config::load().unwrap();
        config.default_limit = Some(2);
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let run = |args: &[&str]| -> Value {
            let output = ghidra(harness)
                .args(args.iter().copied())
                .with_project(test_project(), &name)
                .env("GHIDRA_CLI_CONFIG", config_path.to_string_lossy())
                .arg("--json")
                .run();
            output.assert_success();
            output.data()
        };
        assert_eq!(run(&["bookmark", "list"]), json!(rows[..2]));
        assert_eq!(run(&["bookmark", "list", "--limit", "0"]), json!(rows));
        assert_eq!(run(&["bookmark", "list", "--count"]), 6);
        assert_eq!(
            run(&["bookmark", "list", "--offset", "3", "--limit", "1"]),
            json!(rows[3..4])
        );
        assert_eq!(
            run(&[
                "bookmark",
                "list",
                "--filter",
                "type=Error",
                "--sort=-address",
                "--fields",
                "address,category",
                "--limit",
                "1"
            ]),
            json!([{"address":"0x00001010", "category":"Analysis"}])
        );
        assert_eq!(
            run(&[
                "bookmark",
                "list",
                "--filter",
                "category=Disassembler",
                "--count"
            ]),
            2
        );
        assert_eq!(
            run(&[
                "bookmark",
                "list",
                "--filter",
                "comment~'東京'",
                "--fields",
                "comment"
            ]),
            json!([{"comment":"User note: 東京"}])
        );
        let get_rows = entry["bookmarks"].as_array().unwrap();
        assert_eq!(run(&["bookmark", "get", "0x1000"]), json!(get_rows[..2]));
        assert_eq!(run(&["bookmark", "get", "0x1000", "--count"]), 3);
        assert_eq!(
            run(&[
                "bookmark",
                "get",
                "0x1000",
                "--filter",
                "type=Note",
                "--sort=category",
                "--offset",
                "1",
                "--limit",
                "1",
                "--fields",
                "category,comment"
            ]),
            json!([{"category":"Review", "comment":"User note: 東京"}])
        );
        assert_eq!(run(&["bookmark", "get", "0x1001"]), json!([]));
        // Querying must preserve bookmark identities and leave the program unchanged.
        assert_eq!(state(), before);
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(client.send_command("bookmark_list", None).unwrap(), all);
        assert_eq!(state()["bookmarks"], before["bookmarks"]);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
