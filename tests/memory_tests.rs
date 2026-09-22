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
            currentProgram.getFunctionManager().createFunction(names[i], address,
                new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
        }
    }
}
"#,
            &target_addresses,
            &[],
            false,
        )
        .expect("create pointer targets");

    let output = common::ghidra(&harness)
        .args(["memory", "read", "0x1000"])
        .arg(bytes.len().to_string())
        .json_format()
        .run();
    output.assert_success();
    let output: Value = output.data();
    let result = &output;
    assert_eq!(result.as_object().expect("memory result").len(), 5);
    assert_eq!(result["source"], "memory");
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
        let expected_function = match i {
            0 => Some("outside_range_target"),
            1 => Some("high_address_target"),
            5 if thumb => Some("outside_range_target"),
            7 if odd_function_entry => Some("odd_address_target"),
            _ => None,
        };
        if let Some(name) = expected_function {
            assert_eq!(pointer.as_object().unwrap().len(), 4);
            assert_eq!(pointer["function"], name);
        } else {
            assert_eq!(pointer.as_object().unwrap().len(), 3);
            assert!(pointer.get("function").is_none(), "{pointer}");
        }
    }

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
    assert_eq!(
        result["pointers"][0]["value"],
        if thumb { "0x00002001" } else { "0x00002000" }
    );
    if thumb {
        let boundary = read_memory(client, "odd_overlay:0x2001", 4);
        assert_eq!(boundary["pointers"][0]["value"], "0x00002001");
        assert!(
            boundary["pointers"][0].get("function").is_none(),
            "normalization must not substitute the physical-space base_target: {boundary}"
        );
    }
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
    client.memory_write("0x1000", "deadbeef").unwrap();
    client
        .memory_write("original_overlay:0x1000", "aabbccdd")
        .unwrap();
    // The stored original bytes must not depend on reopening the host input file.
    std::fs::remove_file(&binary).unwrap();

    check_memory_sources(&client);
    let output = common::ghidra(&harness)
        .args(["memory", "read", "0x1000", "8", "--source", "original"])
        .json_format()
        .run();
    output.assert_success();
    assert_eq!(output.data::<Value>(), read_original(&client, "0x1000", 8));
    let output = common::ghidra(&harness)
        .args(["memory", "read", "0x1000", "8", "--source", "memory"])
        .json_format()
        .run();
    output.assert_success();
    assert_eq!(output.data::<Value>(), read_memory(&client, "0x1000", 8));

    drop(harness);
    let reopened = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    check_memory_sources(&reopened.client().unwrap());
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
             "file_bytes_offset": 5, "address": "0x00002002", "end": "0x00002003", "size": 2},
            {"state": "mapped", "filename": "archive-member", "file_offset": 0x209,
             "file_bytes_offset": 9, "address": "0x00002004", "end": "0x00002007", "size": 4},
            {"state": "mapped", "filename": "second-input", "file_offset": 0x501,
             "file_bytes_offset": 1, "address": "0x00002008", "end": "0x00002009", "size": 2}
        ])
    );
    let mapped = client.memory_info("0x2002").unwrap();
    assert_eq!(
        mapped["file_mapping"],
        json!({"state": "mapped", "filename": "archive-member",
               "file_offset": 0x205, "file_bytes_offset": 5})
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
