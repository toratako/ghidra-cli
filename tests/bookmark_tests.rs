//! Exact bookmark mutations preserve other annotation identities and saved state.

use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, ghidra, test_project, DaemonTestHarness};

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;
static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start bridge")
    })
}

fn with_fixture(check: impl FnOnce(&DaemonTestHarness, &BridgeClient, &str)) {
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("bookmark-mutations-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("bookmarks/CreateBookmarkMutationFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(harness, &client, &name);
    }));
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn get(client: &BridgeClient, address: &str) -> Value {
    client
        .send_command("bookmark_get", Some(json!({"address": address})))
        .unwrap()
}

fn set(client: &BridgeClient, address: &str, kind: &str, category: &str, text: &str) -> Value {
    client
        .send_command(
            "bookmark_set",
            Some(json!({"address": address, "type": kind, "category": category, "text": text})),
        )
        .unwrap()
}

fn delete(client: &BridgeClient, address: &str, kind: &str, category: &str) -> Value {
    client
        .send_command(
            "bookmark_delete",
            Some(json!({"address": address, "type": kind, "category": category})),
        )
        .unwrap()
}

#[test]
#[serial]
fn bookmark_set_and_delete_select_only_the_exact_triple() {
    require_ghidra!();
    with_fixture(|_, client, _| {
        let before = get(client, "0x1000");
        let retained: Vec<_> = before["bookmarks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["category"] != "Review")
            .cloned()
            .collect();
        assert_eq!(
            set(client, "0x1000", "Note", "Review", "新しい調査\n次の行"),
            json!({"status": "set", "address": "0x00001000", "type": "Note",
                "category": "Review", "comment": "新しい調査\n次の行"})
        );
        assert_eq!(get(client, "0x1000")["count"], 3);

        // Type/category strings are exact, including case and whitespace.
        for (kind, category) in [
            ("note", "Review"),
            ("Note", "review"),
            ("調査 Type", " 確認 "),
        ] {
            set(client, "0x1000", kind, category, "separate annotation");
        }
        let empty = set(client, "0x1000", "Note", "Review", "");
        assert_eq!(empty["comment"], "");
        let current = get(client, "0x1000");
        assert_eq!(current["count"], 6);
        assert!(current["bookmarks"].as_array().unwrap().iter().any(|row| {
            row["type"] == "Note" && row["category"] == "Review" && row["comment"] == ""
        }));
        for row in &retained {
            assert!(current["bookmarks"].as_array().unwrap().contains(row));
        }

        assert_eq!(delete(client, "0x1000", "NOTE", "Review")["deleted"], 0);
        assert_eq!(delete(client, "0x1000", "Note", "REVIEW")["deleted"], 0);
        assert_eq!(get(client, "0x1000"), current);
        assert_eq!(
            delete(client, "0x1000", "Note", "Review"),
            json!({"status": "deleted", "address": "0x00001000", "type": "Note",
                "category": "Review", "deleted": 1})
        );
        assert_eq!(delete(client, "0x1000", "Note", "Review")["deleted"], 0);
        let expected: Vec<_> = current["bookmarks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| !(row["type"] == "Note" && row["category"] == "Review"))
            .cloned()
            .collect();
        assert_eq!(get(client, "0x1000")["bookmarks"], json!(expected));
    });
}

#[test]
#[serial]
fn bookmark_edits_at_interior_unmapped_and_external_addresses_persist() {
    require_ghidra!();
    with_fixture(|_, client, program| {
        let entry = get(client, "0x1000");
        let external = client.symbol_get("bookmark_external").unwrap()["symbols"][0]["address"]
            .as_str()
            .unwrap()
            .to_owned();
        for address in ["0x1001", "0x9000", external.as_str()] {
            let receipt = set(
                client,
                address,
                "ReviewType",
                "Investigation",
                "保存する注釈",
            );
            assert_eq!(
                get(client, address),
                json!({"count": 1, "bookmarks": [{"address": receipt["address"],
                    "type": "ReviewType", "category": "Investigation", "comment": "保存する注釈"}]})
            );
        }
        assert_eq!(get(client, "0x1000"), entry);
        let before = client.send_command("bookmark_list", None).unwrap();
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.send_command("bookmark_list", None).unwrap(), before);

        for address in ["0x1001", "0x9000", external.as_str()] {
            assert_eq!(
                delete(client, address, "ReviewType", "Investigation")["deleted"],
                1
            );
        }
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(program).unwrap();
        assert_eq!(get(client, "0x1000"), entry);
        for address in ["0x1001", "0x9000", external.as_str()] {
            assert_eq!(get(client, address), json!({"bookmarks": [], "count": 0}));
        }
    });
}

#[test]
#[serial]
fn bookmark_cli_preserves_japanese_multiline_stdin_and_file_text() {
    require_ghidra!();
    with_fixture(|harness, client, program| {
        let stdin_text = "調査メモ\n東京の処理を確認 `literal` $text\n";
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "--quiet",
                "bookmark",
                "set",
                "0x1001",
                "--category",
                "入力",
                "--stdin",
                "--project",
                test_project(),
                "--program",
                program,
            ])
            .write_stdin(stdin_text)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(receipt["data"]["comment"], stdin_text);
        assert_eq!(receipt["data"]["type"], "Note");
        assert_eq!(get(client, "0x1001")["bookmarks"][0]["comment"], stdin_text);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("調査.txt");
        let file_text = "ファイルの調査\n二行目\n";
        std::fs::write(&path, file_text).unwrap();
        let output = ghidra(harness)
            .args(["bookmark", "set", "0x1001", "--category", "入力", "--file"])
            .arg(path.to_str().unwrap())
            .with_project(test_project(), program)
            .run();
        output.assert_success();
        assert_eq!(output.data::<Value>()["comment"], file_text);
        assert_eq!(get(client, "0x1001")["bookmarks"][0]["comment"], file_text);

        let output = ghidra(harness)
            .args([
                "bookmark",
                "set",
                "0x1001",
                "--text",
                "",
                "--category",
                "入力",
            ])
            .with_project(test_project(), program)
            .run();
        output.assert_success();
        assert_eq!(get(client, "0x1001")["bookmarks"][0]["comment"], "");
        for expected in [1, 0] {
            let output = ghidra(harness)
                .args(["bookmark", "delete", "0x1001", "--category", "入力"])
                .with_project(test_project(), program)
                .run();
            output.assert_success();
            assert_eq!(output.data::<Value>()["deleted"], expected);
        }
    });
}

#[test]
#[serial]
fn bookmark_wire_rejects_missing_fields_and_non_address_targets_without_mutation() {
    require_ghidra!();
    with_fixture(|_, client, _| {
        let before = client.send_command("bookmark_list", None).unwrap();
        for (command, args, message) in [
            (
                "bookmark_set",
                json!({"address": "0x1000", "text": "overwrite"}),
                "category required",
            ),
            (
                "bookmark_set",
                json!({"address": "0x1000", "category": "Review"}),
                "text required",
            ),
            (
                "bookmark_delete",
                json!({"address": "0x1000"}),
                "category required",
            ),
            (
                "bookmark_set",
                json!({"address": "bookmark_target", "category": "Review", "text": "overwrite"}),
                "Invalid address",
            ),
            (
                "bookmark_delete",
                json!({"address": "bookmark_target", "category": "Review"}),
                "Invalid address",
            ),
        ] {
            let error = client.send_command(command, Some(args)).unwrap_err();
            assert!(error.to_string().contains(message), "{command}: {error}");
            assert_eq!(client.send_command("bookmark_list", None).unwrap(), before);
        }
    });
}
