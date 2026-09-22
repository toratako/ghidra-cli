use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn test_find_bytes_regex_native_matching_and_boundaries() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("byte-regex-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateByteRegexFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("byte regex fixture");
            try {
                var memory = program.getMemory();
                var space = program.getAddressFactory().getDefaultAddressSpace();
                String[] hex = {"90488b000aff8090488b11223344c3",
                    "61616161612050617373776f726420544f4b454e20746f6b656e", "1234", "5678", "1234", "5678"};
                long[] starts = {0x1000, 0x2000, 0x5000, 0x6000, 0x7000, 0x7002};
                for (int i = 0; i < hex.length; i++) {
                    byte[] bytes = java.util.HexFormat.of().parseHex(hex[i]);
                    memory.createInitializedBlock("raw" + i, space.getAddress(starts[i]),
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                }
                memory.createUninitializedBlock("uninitialized", space.getAddress(0x8000), 0x100, false);
                memory.createInitializedBlock("chunk_boundary", space.getAddress(0x10000),
                    0x8000, (byte) 0xee, monitor, false);
                memory.setBytes(space.getAddress(0x13ffe), java.util.HexFormat.of().parseHex("12345678"));
                memory.createInitializedBlock("regex_overlay", space.getAddress(0x1000),
                    new java.io.ByteArrayInputStream(new byte[]{(byte) 0xca, (byte) 0xfe}),
                    2, monitor, true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let search = |pattern: &str| client.find_bytes_regex_with_limit(pattern, None).unwrap();
        let locations = |result: &Value| -> Vec<(u64, u64)> {
            assert_eq!(result["count"], result["results"].as_array().unwrap().len());
            result["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    assert_eq!(row.as_object().unwrap().len(), 2, "{row}");
                    let address = row["address"].as_str().unwrap().strip_prefix("0x").unwrap();
                    (
                        u64::from_str_radix(address, 16).unwrap(),
                        row["byte_length"].as_u64().unwrap(),
                    )
                })
                .collect()
        };
        let pattern = r"\x48\x8b.{4}";
        let found = search(pattern);
        assert_eq!(locations(&found), [(0x1001, 6), (0x1008, 6)]);
        assert_eq!(locations(&search(r"\x00.\xff")), [(0x1003, 3)]);
        assert_eq!(locations(&search(r"\x0a[\x80-\xff]{2}")), [(0x1004, 3)]);
        assert_eq!(
            locations(&search(r"\x12\x34\x56\x78")),
            [(0x7000, 4), (0x13ffe, 4)]
        );
        assert_eq!(locations(&search(r"\x00")), [(0x1003, 1)]);
        assert_eq!(locations(&search("aa")), [(0x2000, 2), (0x2002, 2)]);
        assert_eq!(client.find_bytes("6161").unwrap()["count"], 4);
        assert_eq!(search("Password|TOKEN")["count"], 2);
        assert_eq!(search("password")["count"], 0);
        assert_eq!(search("(?i)token")["count"], 2);
        assert_eq!(
            search("48 8b")["count"],
            0,
            "regex input must not be parsed as hex"
        );
        let overlay = search(r"\xca\xfe");
        assert_eq!(overlay["count"], 1);
        assert!(overlay["results"][0]["address"]
            .as_str()
            .unwrap()
            .starts_with("regex_overlay:0x"));
        assert_eq!(overlay["results"][0]["byte_length"], 2);

        for (pattern, message) in [
            ("", "Non-empty byte regex"),
            ("[", "Invalid byte regex"),
            ("(?=Password)", "zero-length match"),
            ("^", "zero-length match"),
        ] {
            let error = client
                .find_bytes_regex_with_limit(pattern, None)
                .unwrap_err();
            assert!(error.to_string().contains(message), "{pattern}: {error}");
        }
        assert!(client
            .send_command("find_bytes_regex", Some(json!({})))
            .is_err());
        assert_eq!(
            search(pattern),
            found,
            "failed searches must not poison the next request"
        );
        assert_eq!(
            client
                .find_bytes_regex_with_limit(pattern, Some(1))
                .unwrap()["results"],
            json!([found["results"][0]])
        );

        let output = ghidra(harness())
            .args(["find", "bytes", "--regex", pattern, "--json"])
            .with_project(test_project(), &name)
            .run();
        output.assert_success();
        assert_eq!(output.data::<Value>(), found["results"]);
        let invalid = ghidra(harness())
            .args(["find", "bytes", "--regex", "[", "--json"])
            .with_project(test_project(), &name)
            .run();
        invalid.assert_failure();
        let batch_dir = tempfile::tempdir().unwrap();
        let batch_path = batch_dir.path().join("regex.txt");
        std::fs::write(
            &batch_path,
            format!("find bytes --regex '{pattern}' --limit 0\n"),
        )
        .unwrap();
        let batch = ghidra(harness())
            .args(["batch", batch_path.to_str().unwrap(), "--json"])
            .with_project(test_project(), &name)
            .run();
        batch.assert_success();
        assert_eq!(
            batch.data::<Value>()["results"][0]["result"]["data"],
            found["results"]
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
