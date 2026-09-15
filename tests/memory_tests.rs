//! Pointer interpretation against small, unanalyzed raw programs.

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

fn check_pointer_layout(language: &str, pointer_size: usize, big_endian: bool, high: u64) {
    require_ghidra!();
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
        OUTSIDE_OLD_RANGE + 1, // A function interior is not an entry point.
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
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreatePointerTargets extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String[] names = {"outside_range_target", "high_address_target"};
        for (int i = 0; i < names.length; i++) {
            var address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[i], 16));
            var block = currentProgram.getMemory().createInitializedBlock(names[i],
                address, 4, (byte) 0, monitor, false);
            block.setExecute(true);
            currentProgram.getFunctionManager().createFunction(names[i], address,
                new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
        }
    }
}
"#,
            &[format!("{OUTSIDE_OLD_RANGE:x}"), format!("{high:x}")],
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
    let output: Value = output.json();
    let result = &output[0];
    assert_eq!(result.as_object().expect("memory result").len(), 4);
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
        if i < 2 {
            assert_eq!(pointer.as_object().unwrap().len(), 4);
            assert_eq!(
                pointer["function"],
                ["outside_range_target", "high_address_target"][i]
            );
        } else {
            assert_eq!(pointer.as_object().unwrap().len(), 3);
            assert!(pointer.get("function").is_none(), "{pointer}");
        }
    }

    // Reading past the initialized block must use bytes actually read, including
    // the raw trailing bytes, without manufacturing another pointer entry.
    assert_eq!(read_memory(&client, "1000", bytes.len() + 16), *result);
    let short = read_memory(&client, "1000", pointer_size - 1);
    assert_eq!(short["size"], pointer_size - 1);
    assert_eq!(short["hex"], &hex[..(pointer_size - 1) * 2]);
    assert_eq!(short["pointers"], json!([]));

    if pointer_size == 4 {
        check_overlay_pointers(&client);
    }
}

fn check_overlay_pointers(client: &BridgeClient) {
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
        memory.setBytes(start, new byte[] {0, 0x20, 0, 0, 0x30, (byte) 0xda, 9, 7});
        var target = start.add(0x1000);
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
    let result = read_memory(client, "overlay:1000", 8);
    assert_eq!(result["pointers"][0]["function"], "overlay_target");
    assert_eq!(result["pointers"][1]["function"], "outside_range_target");
}

fn read_memory(client: &BridgeClient, address: &str, size: usize) -> Value {
    client
        .send_command("read_memory", Some(json!({"address":address, "size":size})))
        .expect("read fixture memory")
}

fn parse_address(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().expect("hex address"), 16).expect("valid address")
}
