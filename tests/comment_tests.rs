//! Tests for comment operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_comment_set_and_get() {
    require_ghidra!();
    let harness = harness();

    // Dynamically resolve an address with a code unit
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("comment")
        .arg("set")
        .arg(&addr)
        .arg("test comment from integration test")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get the comment back
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("comment")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test comment"));
}

#[test]
#[serial]
fn test_comment_list() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    let addr = &addrs[0];

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("another comment")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Analysis generates thousands of auto EOL reference comments at low
    // addresses; `comment list` is address-ordered and limited (default 1000),
    // so a user comment at a high function address can fall outside the default
    // window. Pass an explicit large limit so the assertion is deterministic.
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("comment")
        .arg("list")
        .arg("--limit")
        .arg("100000")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("another comment"));
}

#[test]
#[serial]
fn test_comment_delete() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 3);
    let addr = &addrs[addrs.len() - 1];

    for kind in ["EOL", "PRE", "POST", "PLATE"] {
        client
            .comment_set(addr, &format!("to be deleted: {kind}"), Some(kind))
            .unwrap();
    }
    let comments = client.comment_get(addr).unwrap();
    assert_eq!(comments["comments"].as_array().unwrap().len(), 4);

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("comment")
        .arg("delete")
        .arg(addr)
        .arg("--all")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        receipt,
        serde_json::json!([{"status": "deleted", "address": comments["address"]}])
    );

    assert!(client.comment_get(addr).unwrap()["comments"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
#[serial]
fn comment_delete_selected_type_preserves_other_comments() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    for kind in ["EOL", "PRE", "POST", "PLATE"] {
        client
            .comment_set(
                &addr,
                &format!("retain unless selected: {kind}"),
                Some(kind),
            )
            .unwrap();
    }
    let before = client.comment_get(&addr).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "comment",
            "delete",
            &addr,
            "--comment-type",
            "pRe",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .assert()
        .success();
    let expected: Vec<_> = before["comments"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["type"] != "PRE")
        .cloned()
        .collect();
    assert_eq!(
        client.comment_get(&addr).unwrap()["comments"],
        serde_json::json!(expected)
    );
    client.comment_delete(&addr, None, true).unwrap();
}

#[test]
#[serial]
fn comment_wire_rejects_invalid_scope_and_type_without_mutation() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    for kind in ["EOL", "PRE", "POST", "PLATE"] {
        client
            .comment_set(&addr, &format!("must remain: {kind}"), Some(kind))
            .unwrap();
    }
    let before = client.comment_get(&addr).unwrap();
    for (command, args, message) in [
        (
            "comment_delete",
            serde_json::json!({"address": addr}),
            "exactly one",
        ),
        (
            "comment_delete",
            serde_json::json!({"address": addr, "comment_type": "PRE", "all": true}),
            "exactly one",
        ),
        (
            "comment_delete",
            serde_json::json!({"address": addr, "comment_type": "invalid", "all": false}),
            "Invalid comment type",
        ),
        (
            "comment_set",
            serde_json::json!({"address": addr, "comment_type": "invalid", "text": "must not replace EOL"}),
            "Invalid comment type",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(message), "{command}: {error}");
        assert_eq!(client.comment_get(&addr).unwrap(), before, "{command}");
    }
    client.comment_delete(&addr, None, true).unwrap();
}

#[test]
#[serial]
fn comment_delete_applies_fields_and_format_to_receipt() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    for (format_flag, format) in [("--format", "json-compact"), ("-o", "csv")] {
        client
            .comment_set(&addr, "delete receipt projection", Some("EOL"))
            .unwrap();
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "comment",
                "delete",
                &addr,
                "--all",
                "--fields",
                "status",
                format_flag,
                format,
                "--project",
                test_project(),
                "--program",
                TEST_PROGRAM,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        if format == "json-compact" {
            let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(receipt, serde_json::json!([{"status": "deleted"}]));
        } else {
            let receipt = String::from_utf8(output.stdout).unwrap();
            assert_eq!(receipt.trim(), "status\ndeleted");
        }
        assert!(client.comment_get(&addr).unwrap()["comments"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
#[serial]
fn comment_delete_rejects_query_flags_without_mutating_comments() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    for kind in ["EOL", "PRE", "POST", "PLATE"] {
        client
            .comment_set(&addr, &format!("must remain: {kind}"), Some(kind))
            .unwrap();
    }
    let before = client.comment_get(&addr).unwrap();

    for flag in [
        vec!["--filter", "type=EOL"],
        vec!["--sort", "type"],
        vec!["--offset", "1"],
        vec!["--limit", "0"],
        vec!["--count"],
    ] {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "comment",
                "delete",
                &addr,
                "--all",
                "--project",
                test_project(),
                "--program",
                TEST_PROGRAM,
            ])
            .args(&flag)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "{flag:?}: {output:?}"
        );
        assert_eq!(client.comment_get(&addr).unwrap(), before, "{flag:?}");
    }
    client.comment_delete(&addr, None, true).unwrap();
}

#[test]
#[serial]
fn comment_stdin_preserves_multiline_text_without_prompting_pipelines() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let text = "stdin comment\nsecond line with `literal` $text\n";
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "--quiet",
            "comment",
            "set",
            &addr,
            "--stdin",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .write_stdin(text)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "comment",
            "get",
            &addr,
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value
            .to_string()
            .contains("second line with `literal` $text"),
        "{value}"
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn comment_terminal_stdin_explains_eof_even_when_quiet() {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    let mut master = -1;
    let mut slave = -1;
    // File takes ownership of the fresh descriptors from openpty.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
        .args([
            "--quiet",
            "comment",
            "set",
            &addr,
            "--stdin",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(b"terminal comment\n\x04").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("terminal stdin did not finish after EOF");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Enter comment text; finish with EOF (Ctrl-D)."),
        "{stderr}"
    );
}

#[test]
#[serial]
fn test_comments_at_instruction_data_external_and_unmapped_addresses() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("comment-interior-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateInteriorCommentFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("comment fixture");
            try {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var memory = program.getMemory();
                memory.createInitializedBlock("code", start, 16, (byte) 0, monitor, false);
                memory.setBytes(start, new byte[] {0x66, (byte) 0x90, (byte) 0xc3});
                program.getListing().createData(start.add(8), DWordDataType.dataType);
                program.getExternalManager().addExtFunction("comment_library",
                    "comment_external", null, SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let disasm = client.define_code("0x1000", None).unwrap();
        assert_eq!(disasm["landed"], true);
        let external = client.symbol_get("comment_external").unwrap()["symbols"][0]["address"]
            .as_str()
            .unwrap()
            .to_string();
        let addresses = ["0x1001", "0x1009", "0x10", external.as_str()];
        for address in addresses {
            for kind in ["EOL", "PRE", "POST", "PLATE"] {
                let text = format!("interior-{address}-{kind}");
                client.comment_set(address, &text, Some(kind)).unwrap();
                let comments = client.comment_get(address).unwrap();
                assert!(
                    comments["comments"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row["type"] == kind && row["text"] == text),
                    "{comments}"
                );
                let listed = client.comment_list(None, Some(&text), None).unwrap();
                assert_eq!(listed["count"], 1, "{listed}");
                assert_eq!(listed["comments"][0]["text"], text);
            }
            client.comment_delete(address, None, true).unwrap();
            assert!(client.comment_get(address).unwrap()["comments"]
                .as_array()
                .unwrap()
                .is_empty());
        }

        for address in addresses {
            client
                .comment_set(address, &format!("comment-page-{address}"), Some("EOL"))
                .unwrap();
        }
        let all = client
            .comment_list(None, Some("comment-page-"), None)
            .unwrap();
        let rows = all["comments"].as_array().unwrap();
        assert_eq!(rows.len(), addresses.len(), "{all}");
        for (offset, row) in rows.iter().enumerate() {
            let page = client
                .comment_list(Some(1), Some("comment-page-"), Some(offset))
                .unwrap();
            assert_eq!(page["comments"], serde_json::json!([row]), "{page}");
        }
        let output = common::ghidra(harness())
            .args([
                "comment",
                "list",
                "--filter",
                "text~\"comment-page-\"",
                "--count",
            ])
            .with_project(test_project(), &name)
            .run();
        output.assert_success();
        assert_eq!(output.stdout.trim(), "4");
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
