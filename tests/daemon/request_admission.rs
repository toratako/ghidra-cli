use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serde_json::{json, Value};
use serial_test::serial;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

fn request(port: u16, wire: &str) -> Value {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(socket, "{wire}").unwrap();
    let mut response = String::new();
    BufReader::new(socket).read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

#[test]
#[serial]
fn malformed_or_duplicate_members_cannot_admit_mutations_or_shutdown() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = format!("admission-{}", uuid::Uuid::new_v4());
    client
        .send_command("tag_create", Some(json!({"name": name})))
        .unwrap();
    let before = client.tag_get(&name).unwrap();
    let selected = client.program_info().unwrap()["path"].clone();

    for wire in [
        "{command:'shutdown_wait'}".to_owned(),
        r#"{"command":"ping","command":"shutdown_wait"}"#.to_owned(),
        r#"{"command":"ping","comm\u0061nd":"shutdown_wait"}"#.to_owned(),
        r#"{"command":"ping","args":{"nested":[{"all":false,"all":true}]}}"#.to_owned(),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","args":{{"name":"missing","name":"{name}"}}}}"#
        ),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","program":"missing-program","program":{selected},"args":{{"name":"{name}"}}}}"#
        ),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","args":{{"name":"missing"}},"args":{{"name":"{name}"}}}}"#
        ),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","args":{{"name":"{name}","unused":truE}}}}"#
        ),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","args":{{"name":"{name}","unused":"invalid\'escape"}}}}"#
        ),
        format!(
            r#"{{"command":"tag_create","job_id":"ID","args":{{"name":"{name}\ud800"}}}}"#
        ),
        format!(
            r#"{{"command":"tag_delete","job_id":"ID","args":{{"name":"{name}","unused":{{"\udc00":true}}}}}}"#
        ),
        format!(
            "{{\"command\":\"tag_delete\",\"job_id\":\"ID\",\"args\":{{\"name\":\"{name}\",\"unused\":\"raw\tcontrol\"}}}}"
        ),
        format!(
            "\0{{\"command\":\"tag_delete\",\"job_id\":\"ID\",\"args\":{{\"name\":\"{name}\"}}}}\0"
        ),
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let wire = wire.replace("ID", &id);
        let response = request(harness.port(), &wire);
        assert_eq!(response["status"], "error", "{wire}: {response}");
        assert!(response.get("job_id").is_none(), "{wire}: {response}");
        assert_eq!(client.job_status(Some(&id)).unwrap()["found"], false);
        assert_eq!(client.status().unwrap()["bridge_state"], "running");
        assert_eq!(client.program_info().unwrap()["path"], selected);
        assert_eq!(client.tag_get(&name).unwrap(), before);
    }

    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_get(&name).unwrap(), before);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}

#[test]
#[serial]
fn valid_json_accepts_nested_values_and_preserves_escaped_names_and_text() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let name = format!("admission-日本語-😀-{}", uuid::Uuid::new_v4());
    let comment = "quotes: \" slash: \\ controls: \t\r\n";
    let wire = format!(
        " \t{{\"comm\\u0061nd\":\"tag_create\",\"job_id\":\"{id}\",\"args\":{{\"na\\u006de\":{},\"comment\":{},\"unused\":[null,true,false,9007199254740993,-1.25E+3,{{\"name\":\"independent\"}}]}}}} \r",
        json!(name).to_string().replace('😀', "\\ud83d\\ude00"),
        json!(comment)
    );
    let response = request(harness.port(), &wire);
    assert_eq!(response["status"], "success", "{response}");
    assert_eq!(response["job_id"], id);
    let tag = client.tag_get(&name).unwrap();
    assert_eq!(tag["name"], name);
    assert_eq!(tag["comment"], comment);
    let limited = request(
        harness.port(),
        &format!(
            r#"{{"command":"tag_list","job_id":"{}","args":{{"limit":1E0}}}}"#,
            uuid::Uuid::new_v4()
        ),
    );
    assert_eq!(limited["status"], "success", "{limited}");
    assert_eq!(limited["data"]["count"], 1);
    // The upper signed-long limit would overflow if first rounded through double.
    let functions = request(
        harness.port(),
        &format!(
            r#"{{"command":"list_functions","job_id":"{}","args":{{"limit":9223372036854775807}}}}"#,
            uuid::Uuid::new_v4()
        ),
    );
    assert_eq!(functions["status"], "success", "{functions}");
    assert!(!functions["data"]["functions"]
        .as_array()
        .unwrap()
        .is_empty());
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_get(&name).unwrap(), tag);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}
