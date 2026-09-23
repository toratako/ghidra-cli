//! Native Ghidra address-table candidates, scope, paging, cancellation and read-only behavior.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};

#[macro_use]
mod common;

fn fixture(
    language: &str,
    width: usize,
    big_endian: bool,
    check: impl FnOnce(&common::DaemonTestHarness, &str),
) {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-address-tables-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("tables.bin");
    let mut bytes = vec![0xff; 0x100];
    for (offset, targets) in [
        (0, &[0x3000_u64, 0x3010, 0x3020][..]),
        (0x40, &[0x3001, 0x3011, 0x3021][..]),
        (0x80, &[0x3000, 0x3010, 0x3020, 0x3030][..]),
        (0xc0, &[0x3000, 0x5000, 0x3020][..]),
    ] {
        for (i, value) in targets.iter().enumerate() {
            let encoded = if big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            bytes[offset + i * width..offset + (i + 1) * width].copy_from_slice(if big_endian {
                &encoded[8 - width..]
            } else {
                &encoded[..width]
            });
        }
    }
    bytes[width * 3..width * 3 + 3].copy_from_slice(&[0, 1, 2]);
    std::fs::write(&binary, bytes).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_install_dir()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some(language.to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw address tables");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    if width == 4 || width == 8 {
        harness
            .client()
            .unwrap()
            .script_run_source(
                include_str!("fixtures/address_tables/CreateAddressTables.java"),
                &[],
                &[],
                false,
            )
            .expect("create targets and reference boundary");
    }
    check(&harness, &program);
}

fn search(client: &BridgeClient, args: Value) -> Value {
    client
        .send_command("find_address_tables", Some(args))
        .unwrap()
}

fn address(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

fn check_native_layout(language: &str, width: usize, big_endian: bool) {
    fixture(language, width, big_endian, |harness, program| {
        let client = harness.client().unwrap();
        let args = json!({"start":"0x1000", "end":"0x10ff", "alignment":1});
        let found = search(&client, args.clone());
        assert_eq!(found["count"], 2, "{found}");
        assert_eq!(found["detector"], "ghidra-address-table");
        assert_eq!(found["scope"], "candidate-starts");
        assert_eq!(found["pointer_size"], width);
        assert_eq!(found["endian"], if big_endian { "big" } else { "little" });
        assert_eq!(found["pointer_shift"], 0);
        assert_eq!(found["min_entries"], 3);
        assert_eq!(found["scan"], json!({"complete":true}));
        let rows = found["results"].as_array().unwrap();
        assert_eq!(address(&rows[0]["address"]), 0x1000);
        assert_eq!(rows[0]["name"], "aligned_table");
        assert_eq!(rows[0]["entry_count"], 3);
        assert_eq!(rows[0]["byte_length"], width * 3 + 3);
        assert_eq!(address(&rows[0]["end"]), (0x1000 + width * 3 + 2) as u64);
        assert_eq!(
            address(&rows[0]["index_address"]),
            (0x1000 + width * 3) as u64
        );
        assert_eq!(rows[0]["index_length"], 3);
        assert_eq!(address(&rows[1]["address"]), 0x1040);
        assert_eq!(rows[1]["name"], "odd_targets");
        assert_eq!(rows[1]["entry_count"], 3);
        assert!(rows[1].get("index_address").is_none());

        let overlay = search(
            &client,
            json!({"start":"table_overlay:0x1000", "end":"table_overlay:0x1000"}),
        );
        assert_eq!(overlay["count"], 1, "{overlay}");
        assert!(overlay["results"][0]["address"]
            .as_str()
            .unwrap()
            .starts_with("table_overlay:0x"));
        assert_eq!(overlay["results"][0]["entry_count"], 3);
        let unbounded = search(&client, json!({"alignment":1}));
        assert_eq!(unbounded["count"], 3, "{unbounded}");
        for row in rows.iter().chain(overlay["results"].as_array().unwrap()) {
            assert!(unbounded["results"].as_array().unwrap().contains(row));
        }
        assert_eq!(unbounded["scan"], json!({"complete":true}));
        assert!(client
            .send_command(
                "find_address_tables",
                Some(json!({"start":"0x1000", "end":"table_overlay:0x1000"})),
            )
            .is_err());

        // Bounds select candidate starts; native detection may extend beyond end.
        let exact = search(
            &client,
            json!({"start":"aligned_table", "end":"aligned_table"}),
        );
        assert_eq!(exact["results"], json!([rows[0]]));
        assert_eq!(exact["scan"], json!({"complete":true}));
        assert_eq!(address(&exact["ranges"][0]["start"]), 0x1000);
        assert_eq!(address(&exact["ranges"][0]["end"]), 0x1000);
        // Native alignment applies to table starts and all pointer targets.
        let aligned = search(
            &client,
            json!({"start":"0x1000", "end":"0x107f", "alignment":4}),
        );
        assert_eq!(aligned["results"], json!([rows[0]]));
        // Incoming references delimit two adjacent candidates according to getEntry.
        let split = search(
            &client,
            json!({"start":"0x1080", "end":"0x10bf", "min_entries":2}),
        );
        assert_eq!(split["count"], 2, "{split}");
        assert_eq!(split["results"][0]["entry_count"], 2);
        assert_eq!(
            address(&split["results"][1]["address"]),
            (0x1080 + width * 2) as u64
        );
        assert_eq!(
            search(&client, json!({"start":"0x2000", "end":"0x20ff"}))["results"],
            json!([])
        );
        let limited = search(
            &client,
            json!({"start":"0x1000", "end":"0x10ff", "limit":1}),
        );
        assert_eq!(limited["results"], json!([rows[0]]));
        assert_eq!(
            limited["scan"],
            json!({"complete":false,"stop_reason":"limit"})
        );

        let cli = common::ghidra(harness)
            .args([
                "find",
                "address-tables",
                "--start",
                "0x1000",
                "--end",
                "0x10ff",
                "--alignment",
                "1",
                "--filter",
                "entry_count=3",
                "--sort",
                "-address",
                "--limit",
                "1",
            ])
            .json_format()
            .run();
        cli.assert_success();
        assert_eq!(cli.data::<Value>(), json!([rows[1]]));
        for invalid in [
            json!({"alignment":0}),
            json!({"min_entries":1}),
            json!({"start":"0x1080","end":"0x1000"}),
        ] {
            assert!(client
                .send_command("find_address_tables", Some(invalid))
                .is_err());
        }
        client
            .script_run_source(
                include_str!("fixtures/address_tables/CheckAddressTableReadOnly.java"),
                &[],
                &[],
                false,
            )
            .expect("cancel native scan and verify unchanged read-only database");
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(search(&client, args), found);
    });
}

#[test]
fn address_tables_32_bit_little_endian() {
    check_native_layout("x86:LE:32:default", 4, false);
}

#[test]
fn address_tables_64_bit_little_endian() {
    check_native_layout("x86:LE:64:default", 8, false);
}

#[test]
fn address_tables_64_bit_big_endian() {
    check_native_layout("AARCH64:BE:64:v8A", 8, true);
}

#[test]
fn native_address_tables_reject_unsupported_pointer_width() {
    fixture("x86:LE:16:Real Mode", 2, false, |harness, _| {
        let error = harness
            .client()
            .unwrap()
            .send_command("find_address_tables", Some(json!({})))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("4- or 8-byte pointers in byte-addressed memory"),
            "{error}"
        );
    });
}
