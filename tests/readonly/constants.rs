use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

fn addresses(rows: &[Value]) -> Vec<String> {
    let mut addresses: Vec<_> = rows
        .iter()
        .map(|row| row["address"].as_str().unwrap().to_owned())
        .collect();
    addresses.sort();
    addresses
}

#[test]
#[serial]
fn constant_search_matches_operand_scalars_without_numeric_precision_loss() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("constant-search-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreateConstantSearchFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let find = |args: Value| -> Vec<Value> {
            let result = client.send_command("find_constant", Some(args)).unwrap();
            let rows = result["results"].as_array().unwrap();
            assert_eq!(result["count"], rows.len());
            rows.clone()
        };
        let minus_one = find(json!({"value": "-1"}));
        assert_eq!(
            addresses(&minus_one),
            [
                "0x00001000",
                "0x00001010",
                "0x00001020",
                "0x00001030",
                "0x000010c0",
                "constant_overlay:0x00001000",
            ]
        );
        for row in &minus_one {
            assert_eq!(row["signed_value"], "-1");
            assert!(!row["disasm"].as_str().unwrap().is_empty());
            assert_eq!(row["operand_index"], 1);
            if row["address"].as_str().unwrap().starts_with("0x") {
                assert_eq!(row["function"], "constant_cases");
            } else {
                assert!(row.get("function").is_none());
            }
        }
        for (bits, value, address) in [
            (8, "0xff", "0x00001010"),
            (16, "0xffff", "0x00001020"),
            (32, "0xffffffff", "0x00001000"),
            (64, "0xffffffffffffffff", "0x00001030"),
        ] {
            let unsigned = find(json!({"value": value, "bits": bits}));
            assert_eq!(unsigned, find(json!({"value": "-1", "bits": bits})));
            let row = unsigned
                .iter()
                .find(|row| row["address"] == address)
                .unwrap();
            assert_eq!(row["value"], value);
            assert_eq!(row["bits"], bits);
        }
        assert!(find(json!({"value":"0xffffffff", "bits":16})).is_empty());
        for (unsigned, signed, address) in [
            ("2147483648", "-2147483648", "0x00001040"),
            ("9223372036854775808", "-9223372036854775808", "0x00001050"),
            ("18446744073709551615", "-0x1", "0x00001030"),
        ] {
            let found = find(json!({"value": unsigned}));
            assert_eq!(addresses(&found), [address]);
            assert!(find(json!({"value": signed})).contains(&found[0]));
        }
        let low = find(json!({"value":"9007199254740992"}));
        let high = find(json!({"value":"9007199254740993"}));
        assert_eq!(addresses(&low), ["0x00001070"]);
        assert_eq!(addresses(&high), ["0x00001060"]);
        assert_eq!(high[0]["value"], "0x20000000000001");
        assert_eq!(high[0]["signed_value"], "9007199254740993");
        let high_range = find(json!({"min":"9007199254740992", "max":"9007199254740993"}));
        assert_eq!(addresses(&high_range), ["0x00001060", "0x00001070"]);
        assert_eq!(
            find(json!({"min":"0xffffffffffffffff", "max":"18446744073709551615"})),
            find(json!({"value":"18446744073709551615"}))
        );
        let signed_range = find(json!({"min":"-2147483648", "max":"-1"}));
        let mut expected = minus_one.clone();
        expected.extend(find(json!({"value":"2147483648"})));
        assert_eq!(addresses(&signed_range), addresses(&expected));
        assert!(find(json!({"min":"-1", "max":"0", "bits":32}))
            .iter()
            .all(|row| row["signed_value"] == "-1"));

        // Displacements count, including a second Scalar in a scaled-index operand.
        // ENTER's two equal-valued operands remain two separate occurrences.
        let thirty_two = find(json!({"value":"0x20"}));
        assert_eq!(
            addresses(&thirty_two),
            ["0x00001090", "0x000010b0", "0x000010e0"]
        );
        let eight = find(json!({"value":"8"}));
        assert_eq!(addresses(&eight), ["0x000010d0", "0x000010d0"]);
        let enter: Vec<_> = eight
            .iter()
            .filter(|row| row["address"] == "0x000010d0")
            .map(|row| row["operand_index"].as_u64().unwrap())
            .collect();
        assert_eq!(enter, [0, 1]);
        assert_eq!(find(json!({"min":"32", "max":"0x20"})), thirty_two);
        for value in ["0x76543210", "0x2000", "0xefb"] {
            assert!(find(json!({"value":value})).is_empty(), "{value}");
        }
        let bounded =
            find(json!({"min":"16", "max":"48", "start":"range_start", "end":"range_end"}));
        assert_eq!(
            addresses(&bounded),
            ["0x00001080", "0x00001090", "0x000010a0"]
        );
        assert!(find(json!({"value":"0xffffffff", "start":"0x1001", "end":"0x1004"})).is_empty());
        let overlay = find(json!({"value":"0xffffffff", "start":"constant_overlay:0x1000"}));
        assert_eq!(addresses(&overlay), ["constant_overlay:0x00001000"]);
        assert_eq!(
            find(json!({"value":"0xffffffff", "end":overlay[0]["address"]})),
            overlay
        );

        for args in [
            json!({"value":"18446744073709551616"}),
            json!({"value":"-9223372036854775809"}),
            json!({"value":9007199254740993u64}),
            json!({"value":"1.5"}),
            json!({"min":"-1", "max":"9223372036854775808"}),
            json!({"min":"32", "max":"16"}),
            json!({"min":"1"}),
            json!({"value":"1", "min":"0", "max":"2"}),
            json!({"value":"-1", "bits":0}),
            json!({"value":"-1", "bits":65}),
            json!({"value":"-1", "bits":8.5}),
            json!({"value":"-1", "limit":2147483648u64}),
            json!({"value":"-1", "start":"constant_overlay:0x1000", "end":"0x1100"}),
        ] {
            assert!(
                client
                    .send_command("find_constant", Some(args.clone()))
                    .is_err(),
                "accepted invalid query {args}"
            );
        }
        assert_eq!(find(json!({"value":"-1", "limit":1})), minus_one[..1]);
        assert_eq!(find(json!({"value":"-1", "limit":0})), minus_one);

        // The ordinary query pipeline must fetch enough rows before filtering or paging.
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config = ghidra_cli::config::Config::load().unwrap();
        config.default_limit = Some(2);
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let run = |args: &[&str]| -> Value {
            let output = ghidra(harness)
                .args(args.iter().copied())
                .with_project(test_project(), &name)
                .env(
                    "GHIDRA_CLI_CONFIG",
                    config_path.to_string_lossy().into_owned(),
                )
                .arg("--json")
                .run();
            output.assert_success();
            output.data()
        };
        let with = |flags: &[&str]| -> Value {
            let mut args = vec!["find", "constant", "-1"];
            args.extend(flags);
            run(&args)
        };
        assert_eq!(with(&[]), json!(minus_one[..2]));
        assert_eq!(with(&["--limit", "0"]), json!(minus_one));
        assert_eq!(with(&["--count"]), minus_one.len());
        assert_eq!(with(&["--offset", "3"]), json!(minus_one[3..5]));
        assert_eq!(
            with(&["--offset", "3", "--limit", "0"]),
            json!(minus_one[3..])
        );
        assert_eq!(with(&["--count", "--offset", "3", "--limit", "1"]), 1);
        let filter = "address='constant_overlay:0x1000'";
        assert_eq!(with(&["--filter", filter]), json!(overlay));
        assert_eq!(
            with(&["--fields", "value,bits"]).as_array().unwrap().len(),
            2
        );
        let projected = with(&[
            "--filter",
            "bits=32",
            "--offset",
            "1",
            "--limit",
            "1",
            "--fields",
            "address,value,bits",
        ]);
        assert_eq!(projected.as_array().unwrap().len(), 1);
        assert_eq!(projected[0].as_object().unwrap().len(), 3);
        assert_eq!(projected[0]["value"], "0xffffffff");
        assert_eq!(
            run(&[
                "find",
                "constant",
                "--min",
                "16",
                "--max",
                "48",
                "--start",
                "range_start",
                "--end",
                "range_end",
                "--limit",
                "0"
            ]),
            json!(bounded)
        );
        assert_eq!(
            run(&["find", "constant", "-0x8000000000000000"])[0]["address"],
            "0x00001050"
        );
        let batch_path = temp.path().join("constants.txt");
        std::fs::write(&batch_path,
            "find constant -1 --filter bits=32 --offset 1 --limit 1 --fields address,value,bits\nfind constant --min 9007199254740992 --max 9007199254740993 --limit 0\nfind constant -1 --count\n").unwrap();
        let batch = run(&["batch", batch_path.to_str().unwrap()]);
        let results = &batch["results"];
        assert_eq!(results[0]["result"]["data"], projected);
        assert_eq!(results[1]["result"]["data"], json!(high_range));
        assert_eq!(results[2]["result"]["data"], minus_one.len());
        client
            .script_run_source(
                include_str!("CheckConstantCancellation.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
