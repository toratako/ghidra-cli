//! Pointer interpretation and preserved file bytes against small, unanalyzed raw programs.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

#[macro_use]
mod common;

const OUTSIDE_OLD_RANGE: u64 = 0x0709_da30;

#[test]
#[serial]
fn memory_read_32_bit_little_endian() {
    check_pointer_layout("x86:LE:32:default", 4, false, 0xf123_4560);
}

#[test]
#[serial]
fn memory_read_64_bit_big_endian() {
    check_pointer_layout("AARCH64:BE:64:v8A", 8, true, 0xffff_8000_0709_da30);
}

#[test]
#[serial]
fn memory_read_64_bit_little_endian() {
    check_pointer_layout("x86:LE:64:default", 8, false, 0xffff_8000_0709_da30);
}

#[test]
#[serial]
fn memory_read_arm_thumb_function_pointers() {
    check_pointer_layout("ARM:LE:32:v8", 4, false, 0xf123_4560);
}

fn check_pointer_layout(language: &str, pointer_size: usize, big_endian: bool, high: u64) {
    require_ghidra!();
    let thumb = language == "ARM:LE:32:v8";
    let odd_function_entry = language.starts_with("x86:");
    let directory = tempfile::Builder::new()
        .prefix("ghidra-memory-")
        .tempdir()
        .expect("fixture directory");
    let project = directory.path().join("project");
    let binary = directory.path().join("pointers.bin");
    let values = [
        OUTSIDE_OLD_RANGE,
        high,
        0,
        0x0040_1000, // Unmapped, despite falling inside the old code-address range.
        0x1000,      // Mapped data with no function.
        OUTSIDE_OLD_RANGE + 1, // Thumb entry pointer; otherwise a function interior.
        OUTSIDE_OLD_RANGE + 3, // Still an interior after stripping a code-mode bit.
        0x3001,      // A real odd entry on x86 must remain odd.
        if pointer_size == 4 {
            u32::MAX as u64
        } else {
            u64::MAX
        },
        0x5000, // A two-hop thunk must retain its own entry and both destinations.
        0x5010,
        0x6000, // Mapped, uninitialized data is still a valid address interpretation.
    ];
    let mut bytes = Vec::new();
    for value in values {
        let encoded = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        bytes.extend_from_slice(if big_endian {
            &encoded[8 - pointer_size..]
        } else {
            &encoded[..pointer_size]
        });
    }
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // Incomplete final pointer.
    std::fs::write(&binary, &bytes).expect("write pointer table");

    let installation = ghidra_cli::config::Config::load()
        .expect("load configuration")
        .get_ghidra_install_dir()
        .expect("Ghidra installation");
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
    .expect("import raw pointer fixture");
    // The harness stops the JVM before the temporary project directory is removed.
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program)
        .expect("start fixture bridge");
    let client = harness.client().unwrap();
    let mut target_addresses = vec![format!("{OUTSIDE_OLD_RANGE:x}"), format!("{high:x}")];
    if odd_function_entry {
        target_addresses.push("3001".to_owned());
    }
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreatePointerTargets extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String[] names = {"outside_range_target", "high_address_target", "odd_address_target"};
        var namespace = currentProgram.getSymbolTable().createNameSpace(null,
            "pointer_fixture", SourceType.USER_DEFINED);
        for (int i = 0; i < args.length; i++) {
            var address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[i], 16));
            var block = currentProgram.getMemory().createInitializedBlock(names[i],
                address, 4, (byte) 0, monitor, false);
            block.setExecute(true);
            var thumbMode = currentProgram.getRegister("TMode");
            if (thumbMode != null) {
                currentProgram.getProgramContext().setValue(thumbMode, address,
                    address.add(3), java.math.BigInteger.ONE);
            }
            var function = currentProgram.getFunctionManager().createFunction(names[i], address,
                new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
            if (i == 1) function.setParentNamespace(namespace);
        }
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var functions = currentProgram.getFunctionManager();
        var target = functions.getFunctionAt(space.getAddress(Long.parseUnsignedLong(args[1], 16)));
        for (int i = 1; i >= 0; i--) {
            var address = space.getAddress(0x5000 + i * 0x10);
            var name = i == 0 ? "first_thunk" : "second_thunk";
            var block = currentProgram.getMemory().createInitializedBlock(name,
                address, 4, (byte) 0, monitor, false);
            block.setExecute(true);
            var thunk = functions.createFunction(name, namespace, address,
                new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
            thunk.setThunkedFunction(target);
            target = thunk;
        }
        currentProgram.getSymbolTable().createLabel(space.getAddress(0x1000),
            "table_data", namespace, SourceType.USER_DEFINED);
        currentProgram.getMemory().createUninitializedBlock("uninitialized_data",
            space.getAddress(0x6000), 4, false);
        currentProgram.getSymbolTable().createLabel(space.getAddress(0x6000),
            "uninitialized_data", namespace, SourceType.USER_DEFINED);
    }
}
"#,
            &target_addresses,
            &[],
            false,
        )
        .expect("create pointer targets");
    let before = pointer_program_state(&client);

    let output = common::ghidra(&harness)
        .args(["memory", "read", "0x1000", "--size"])
        .arg(bytes.len().to_string())
        .json_format()
        .run();
    output.assert_success();
    let output: Value = output.data();
    let result = &output;
    assert_eq!(result["source"], "memory");
    assert_eq!(result["pointer_size"], pointer_size);
    assert_eq!(result["endian"], if big_endian { "big" } else { "little" });
    assert_eq!(parse_address(&result["address"]), 0x1000);
    assert_eq!(result["size"], bytes.len());
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(result["hex"], hex);
    let pointers = result["pointers"].as_array().expect("pointer entries");
    assert_eq!(pointers.len(), values.len());
    for (i, (pointer, value)) in pointers.iter().zip(values).enumerate() {
        let offset = i * pointer_size;
        assert_eq!(pointer["offset"], offset);
        assert_eq!(parse_address(&pointer["address"]), 0x1000 + offset as u64);
        assert_eq!(
            pointer["value"],
            format!("0x{value:0width$x}", width = pointer_size * 2)
        );
        assert_eq!(parse_address(&pointer["target_address"]), value);
        assert_eq!(
            parse_address(&pointer["code_address"]),
            if thumb { value & !1 } else { value }
        );
        assert_eq!(
            pointer["mapped"],
            matches!(i, 0 | 1 | 4..=6 | 9..=11) || (i == 7 && odd_function_entry)
        );
        let expected_function = match i {
            0 => Some("outside_range_target"),
            1 => Some("pointer_fixture::high_address_target"),
            5 if thumb => Some("outside_range_target"),
            7 if odd_function_entry => Some("odd_address_target"),
            9 => Some("pointer_fixture::first_thunk"),
            10 => Some("pointer_fixture::second_thunk"),
            _ => None,
        };
        if let Some(name) = expected_function {
            assert_eq!(pointer["function"], name);
            assert_eq!(pointer["function_address"], pointer["code_address"]);
        } else {
            assert_eq!(pointer.get("function"), Some(&Value::Null), "{pointer}");
            assert_eq!(pointer.get("function_address"), Some(&Value::Null));
        }
        if matches!(i, 9 | 10) {
            let direct = &pointer["thunk_target"];
            let effective = &pointer["thunk_final_target"];
            assert_eq!(
                parse_address(&direct["address"]),
                if i == 9 { 0x5010 } else { high }
            );
            assert_eq!(
                direct["name"],
                if i == 9 {
                    "pointer_fixture::second_thunk"
                } else {
                    "pointer_fixture::high_address_target"
                }
            );
            assert_eq!(parse_address(&effective["address"]), high);
            assert_eq!(effective["name"], "pointer_fixture::high_address_target");
        } else {
            assert_eq!(pointer.get("thunk_target"), Some(&Value::Null));
            assert_eq!(pointer.get("thunk_final_target"), Some(&Value::Null));
        }
    }
    assert_eq!(
        pointers[1]["symbol"],
        "pointer_fixture::high_address_target"
    );
    assert_eq!(pointers[4]["symbol"], "pointer_fixture::table_data");
    assert_eq!(
        pointers[11]["symbol"],
        "pointer_fixture::uninitialized_data"
    );
    assert_eq!(pointers[3].get("symbol"), Some(&Value::Null));

    // Reading past the initialized block must use bytes actually read, including
    // the raw trailing bytes, without manufacturing another pointer entry.
    let address = result["address"].as_str().unwrap();
    assert_eq!(read_memory(&client, address, bytes.len() + 16), *result);
    let short = read_memory(&client, address, pointer_size - 1);
    assert_eq!(short["size"], pointer_size - 1);
    assert_eq!(short["hex"], &hex[..(pointer_size - 1) * 2]);
    assert_eq!(short["pointers"], json!([]));

    // Function output must remain a valid input even above signed Long.MAX_VALUE.
    let target = client
        .send_command(
            "get_function",
            Some(json!({"address": "high_address_target"})),
        )
        .expect("resolve high-address function");
    assert_eq!(parse_address(&target["address"]), high);
    let target_address = target["address"].as_str().unwrap();
    assert_eq!(
        read_memory(&client, target_address, 4)["address"],
        target["address"]
    );
    assert_eq!(
        client
            .send_command("get_function", Some(json!({"address": target_address})))
            .expect("roundtrip high function address"),
        target
    );
    assert_eq!(pointer_program_state(&client), before);

    if pointer_size == 4 {
        check_overlay_pointers(&client, thumb);
    }
}

fn check_overlay_pointers(client: &BridgeClient, thumb: bool) {
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateOverlayPointerTargets extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var base = space.getAddress(0x2000);
        memory.createInitializedBlock("base_code", base, 4, (byte) 0, monitor, false);
        currentProgram.getFunctionManager().createFunction("base_target", base,
            new AddressSet(base, base.add(3)), SourceType.USER_DEFINED);
        var overlay = memory.createInitializedBlock("overlay", space.getAddress(0x1000),
            0x1004, (byte) 0, monitor, true);
        var start = overlay.getStart();
        var thumbMode = currentProgram.getRegister("TMode");
        byte modeBit = (byte) (thumbMode == null ? 0 : 1);
        memory.setBytes(start, new byte[] {modeBit, 0x20, 0, 0,
            (byte) (0x30 | modeBit), (byte) 0xda, 9, 7});
        var target = start.add(0x1000);
        if (thumbMode != null) {
            currentProgram.getProgramContext().setValue(thumbMode, target,
                target.add(3), java.math.BigInteger.ONE);
            var oddOverlay = memory.createInitializedBlock("odd_overlay", base.add(1),
                4, (byte) 0, monitor, true);
            memory.setBytes(oddOverlay.getStart(), new byte[] {1, 0x20, 0, 0});
        }
        currentProgram.getFunctionManager().createFunction("overlay_target", target,
            new AddressSet(target, target.add(3)), SourceType.USER_DEFINED);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .expect("create overlapping address spaces");
    let result = read_memory(client, "overlay:0x1000", 8);
    let address = result["address"].as_str().unwrap();
    assert!(address.starts_with("overlay:0x"), "{result}");
    assert_eq!(read_memory(client, address, 8), result);
    assert_ne!(read_memory(client, "0x1000", 8)["hex"], result["hex"]);
    for pointer in result["pointers"].as_array().unwrap() {
        let pointer_address = pointer["address"].as_str().unwrap();
        assert!(pointer_address.starts_with("overlay:0x"), "{pointer}");
        assert_eq!(
            read_memory(client, pointer_address, 4)["address"],
            pointer["address"]
        );
    }
    assert_eq!(result["pointers"][0]["function"], "overlay_target");
    assert_eq!(result["pointers"][1]["function"], "outside_range_target");
    assert!(result["pointers"][0]["target_address"]
        .as_str()
        .unwrap()
        .starts_with("overlay:0x"));
    assert!(result["pointers"][0]["code_address"]
        .as_str()
        .unwrap()
        .starts_with("overlay:0x"));
    assert_eq!(result["pointers"][0]["mapped"], true);
    assert_eq!(
        parse_address(&result["pointers"][1]["target_address"]),
        OUTSIDE_OLD_RANGE + u64::from(thumb)
    );
    assert_eq!(
        result["pointers"][0]["value"],
        if thumb { "0x00002001" } else { "0x00002000" }
    );
    if thumb {
        let boundary = read_memory(client, "odd_overlay:0x2001", 4);
        assert_eq!(boundary["pointers"][0]["value"], "0x00002001");
        assert_eq!(boundary["pointers"][0]["mapped"], true);
        assert_eq!(
            boundary["pointers"][0].get("code_address"),
            Some(&Value::Null)
        );
        assert_eq!(
            boundary["pointers"][0].get("function"),
            Some(&Value::Null),
            "normalization must not substitute the physical-space base_target: {boundary}"
        );
    }
}

fn pointer_program_state(client: &BridgeClient) -> String {
    let result = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class ReadPointerProgramState extends GhidraScript {
    public void run() {
        println("program-state=" + currentProgram.getModificationNumber() + ":" + currentProgram.isChanged());
    }
}
"#,
            &[],
            &[],
            false,
        )
        .expect("read pointer fixture state");
    result["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.starts_with("program-state="))
        .unwrap()
        .to_owned()
}

fn read_memory(client: &BridgeClient, address: &str, size: usize) -> Value {
    client
        .send_command("read_memory", Some(json!({"address":address, "size":size})))
        .expect("read fixture memory")
}

fn parse_address(value: &Value) -> u64 {
    let digits = value
        .as_str()
        .expect("hex address")
        .strip_prefix("0x")
        .expect("explicit address prefix");
    u64::from_str_radix(digits, 16).expect("valid address")
}

#[test]
#[serial]
fn memory_sources_preserve_imported_bytes_and_file_mapping_boundaries() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-memory-sources-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("original.bin");
    std::fs::write(&binary, [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_install_dir()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:32:default".to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .unwrap();
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/memory_sources/CreateMemorySources.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client
        .script_run_source(
            include_str!("memory_mappings/CreateFileMappings.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.memory_write("0x1000", "deadbeef").unwrap();
    client
        .memory_write("original_overlay:0x1000", "aabbccdd")
        .unwrap();
    // The stored original bytes must not depend on reopening the host input file.
    std::fs::remove_file(&binary).unwrap();

    check_memory_sources(&client);
    check_file_mappings(&client);
    check_file_mapping_cli(&harness, &client);
    client
        .script_run_source(
            include_str!("memory_mappings/CheckFileMappingCancellation.java"),
            &[],
            &[],
            false,
        )
        .expect("mapping traversal must propagate cancellation");
    let output = common::ghidra(&harness)
        .args([
            "memory", "read", "0x1000", "--size", "8", "--source", "original",
        ])
        .json_format()
        .run();
    output.assert_success();
    assert_eq!(output.data::<Value>(), read_original(&client, "0x1000", 8));
    let output = common::ghidra(&harness)
        .args([
            "memory", "read", "0x1000", "--size", "8", "--source", "memory",
        ])
        .json_format()
        .run();
    output.assert_success();
    assert_eq!(output.data::<Value>(), read_memory(&client, "0x1000", 8));

    drop(harness);
    let reopened = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    check_memory_sources(&reopened.client().unwrap());
    check_file_mappings(&reopened.client().unwrap());
}

fn read_original(client: &BridgeClient, address: &str, size: usize) -> Value {
    client
        .send_command(
            "read_memory",
            Some(json!({"address": address, "size": size, "source": "original"})),
        )
        .unwrap()
}

fn check_memory_sources(client: &BridgeClient) {
    let original = read_original(client, "0x1000", 8);
    assert_eq!(original["source"], "original");
    assert_eq!(original["hex"], "1011121314151617");
    assert_eq!(original["size"], 8);
    assert!(original.get("pointers").is_none(), "{original}");
    assert_eq!(original["mappings"][0]["file_offset"], 0);
    assert_eq!(read_memory(client, "0x1000", 8)["hex"], "deadbeef14151617");
    assert_eq!(
        read_memory(client, "original_overlay:0x1000", 4)["hex"],
        "aabbccdd"
    );
    let overlay = read_original(client, "original_overlay:0x1000", 4);
    assert_eq!(overlay["hex"], "74757677");
    assert_eq!(
        overlay["mappings"][0]["address"],
        "original_overlay:0x00001000"
    );
    assert_eq!(overlay["mappings"][0]["file_offset"], 0x504);

    // A joined block can have noncontiguous file offsets, followed by another file.
    let spanning = read_original(client, "0x2002", 8);
    assert_eq!(spanning["hex"], "4546494a4b4c7172");
    assert_eq!(spanning["size"], 8);
    assert_eq!(
        spanning["mappings"],
        json!([
            {"state": "mapped", "filename": "archive-member", "file_offset": 0x205,
             "file_bytes_offset": 5, "address": "0x00002002", "end": "0x00002003", "size": 2,
             "block_start": "0x00002000", "source_at": "0x00002000",
             "source_file_offset": 0x200, "source_size": 32},
            {"state": "mapped", "filename": "archive-member", "file_offset": 0x209,
             "file_bytes_offset": 9, "address": "0x00002004", "end": "0x00002007", "size": 4,
             "block_start": "0x00002000", "source_at": "0x00002000",
             "source_file_offset": 0x200, "source_size": 32},
            {"state": "mapped", "filename": "second-input", "file_offset": 0x501,
             "file_bytes_offset": 1, "address": "0x00002008", "end": "0x00002009", "size": 2,
             "block_start": "0x00002008", "source_at": "0x00002008",
             "source_file_offset": 0x500, "source_size": 16}
        ])
    );
    let mapped = client.memory_info("0x2002").unwrap();
    assert_eq!(
        mapped["file_mapping"],
        json!({"state": "mapped", "filename": "archive-member",
               "file_offset": 0x205, "file_bytes_offset": 5, "source_at": "0x00002000",
               "source_file_offset": 0x200, "source_size": 32})
    );
    for (address, state, reason) in [
        ("0x3000", "unmapped", "No preserved file bytes"),
        ("0x4000", "unmapped", "No preserved file bytes"),
        ("0x9000", "unmapped", "No memory block at address"),
        ("0x5000", "unsupported", "Indirect bit/byte memory mapping"),
        ("0x6000", "unsupported", "Indirect bit/byte memory mapping"),
    ] {
        assert_eq!(
            client.memory_info(address).unwrap()["file_mapping"],
            json!({"state": state, "reason": reason})
        );
        let error = client
            .send_command(
                "read_memory",
                Some(json!({"address": address, "size": 1, "source": "original"})),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{address}: {error}");
    }
    // Fail the complete original request, even after a valid prefix, rather than
    // returning a truncated range or filling the remainder from current memory.
    let error = client
        .send_command(
            "read_memory",
            Some(json!({"address": "0x200a", "size": 4, "source": "original"})),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("0x0000200c"), "{error}");
    assert_eq!(read_original(client, "0x200a", 2)["hex"], "7374");
}

fn file_mappings(client: &BridgeClient, args: Value) -> Value {
    client
        .send_command("memory_file_mappings", Some(args))
        .expect("direct file mapping query")
}

fn mapping_addresses(result: &Value) -> std::collections::BTreeSet<&str> {
    result["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["address"].as_str().unwrap())
        .collect()
}

fn check_file_mappings(client: &BridgeClient) {
    let all = file_mappings(client, json!({}));
    assert_eq!(all["count"], 8, "{all}");
    let unsupported = json!([
        {"address": "0x00005000", "end": "0x00005003", "block_start": "0x00005000",
         "reason": "Indirect bit/byte memory mapping"},
        {"address": "0x00006000", "end": "0x00006007", "block_start": "0x00006000",
         "reason": "Indirect bit/byte memory mapping"}
    ]);
    assert_eq!(all["unsupported_mappings"], unsupported);
    for row in all["mappings"].as_array().unwrap() {
        assert_eq!(row["state"], "mapped");
        assert!(row["size"].as_u64().unwrap() > 0);
        let address = row["address"].as_str().unwrap();
        let forward = &client.memory_info(address).unwrap()["file_mapping"];
        for field in [
            "filename",
            "file_offset",
            "file_bytes_offset",
            "source_at",
            "source_file_offset",
            "source_size",
        ] {
            assert_eq!(row[field], forward[field], "{field}: {row}");
        }
        let inverse = file_mappings(
            client,
            json!({"file_offset": row["file_offset"].to_string(), "source_at": row["source_at"]}),
        );
        assert!(mapping_addresses(&inverse).contains(address), "{inverse}");
    }

    let matches = file_mappings(client, json!({"file_offset": "0x205"}));
    assert_eq!(matches["count"], 4);
    assert_eq!(
        mapping_addresses(&matches),
        [
            "0x00002002",
            "0x00007002",
            "0x00007102",
            "same_source_overlay:0x00002002"
        ]
        .into_iter()
        .collect()
    );
    for offset in ["517", "0517", "0X205", "+0x205"] {
        assert_eq!(
            matches,
            file_mappings(client, json!({"file_offset": offset}))
        );
    }
    for row in matches["mappings"].as_array().unwrap() {
        assert_eq!(row["address"], row["end"]);
        assert_eq!(row["size"], 1);
        assert_eq!(row["file_offset"], 0x205);
        assert_eq!(row["file_bytes_offset"], 5);
        assert_eq!(row["source_file_offset"], 0x200);
        assert_eq!(row["source_size"], 32);
    }
    let selected = file_mappings(
        client,
        json!({"file_offset": "0x205", "source_at": "same_source_overlay:0x2001"}),
    );
    assert_eq!(selected["count"], 3);
    assert!(!mapping_addresses(&selected).contains("0x00007002"));
    for row in selected["mappings"].as_array().unwrap() {
        assert_eq!(row["source_at"], "0x00002000");
    }
    assert_eq!(
        file_mappings(client, json!({"source_at": "0x2001"}))["count"],
        4
    );
    let duplicate = file_mappings(
        client,
        json!({"file_offset": "0x205", "source_at": "0x7001"}),
    );
    assert_eq!(duplicate["count"], 1);
    assert_eq!(duplicate["mappings"][0]["source_at"], "0x00007000");
    assert_eq!(read_original(client, "0x7002", 1)["hex"], "90");
    assert_eq!(read_original(client, "0x2002", 1)["hex"], "45");
    let second = file_mappings(client, json!({"file_offset": "0x504"}));
    assert_eq!(second["count"], 2);
    assert_eq!(
        mapping_addresses(&second),
        ["0x0000200b", "original_overlay:0x00001000"]
            .into_iter()
            .collect()
    );
    // Includes source gaps, preserved-but-unloaded bytes, and the largest valid offset.
    for offset in ["0x200", "0x207", "0x800", "9223372036854775807"] {
        let empty = file_mappings(client, json!({"file_offset": offset}));
        assert_eq!(empty["count"], 0, "{empty}");
        assert_eq!(empty["mappings"], json!([]));
        assert_eq!(empty["unsupported_mappings"], unsupported);
    }
    for args in [
        json!({"file_offset": -1}),
        json!({"file_offset": "-1"}),
        json!({"file_offset": "0x8000000000000000"}),
        json!({"source_at": "source_label"}),
        json!({"source_at": "0x4000"}),
        json!({"source_at": "0x5000"}),
        json!({"source_at": "0x9000"}),
    ] {
        assert!(
            client
                .send_command("memory_file_mappings", Some(args.clone()))
                .is_err(),
            "invalid selector accepted: {args}"
        );
    }
}

fn check_file_mapping_cli(harness: &common::DaemonTestHarness, client: &BridgeClient) {
    let output = common::ghidra(harness)
        .args(["memory", "file-mappings", "--limit", "0"])
        .json_format()
        .run();
    output.assert_success();
    assert_file_mapping_output(output.json(), file_mappings(client, json!({})));
    let output = common::ghidra(harness)
        .args([
            "memory",
            "file-mappings",
            "--file-offset",
            "0x205",
            "--source-at",
            "0x2001",
            "--limit",
            "0",
        ])
        .json_format()
        .run();
    output.assert_success();
    assert_file_mapping_output(
        output.json(),
        file_mappings(
            client,
            json!({"file_offset": "0x205", "source_at": "0x2001"}),
        ),
    );
    let output = common::ghidra(harness)
        .args([
            "memory",
            "file-mappings",
            "--file-offset",
            "0x800",
            "--limit",
            "0",
        ])
        .json_format()
        .run();
    output.assert_success();
    assert_file_mapping_output(
        output.json(),
        file_mappings(client, json!({"file_offset": "0x800"})),
    );
}

fn assert_file_mapping_output(output: Value, wire: Value) {
    assert_eq!(output["data"], wire["mappings"]);
    assert_eq!(output["meta"]["returned"], wire["count"]);
    for context in ["unsupported_mappings", "file_offset", "source_at"] {
        assert_eq!(output["meta"].get(context), wire.get(context), "{context}");
    }
}
