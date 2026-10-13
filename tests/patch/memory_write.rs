use super::{harness, TEST_PROGRAM};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::json;
use serial_test::serial;

const FIXTURE: &str = include_str!("../fixtures/patch/MemoryWriteFixture.java");

fn fixture(language: &str, check: impl FnOnce(&BridgeClient)) {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("memory-write-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            FIXTURE,
            &["create".to_owned(), name.clone(), language.to_owned()],
            &[],
            false,
        )
        .unwrap();
    crate::common::with_temporary_program(&client, &name, TEST_PROGRAM, || {
        check(&client);
    });
}

fn verify(client: &BridgeClient, mode: &str) {
    client
        .script_run_source(FIXTURE, &[mode.to_owned()], &[], false)
        .unwrap();
}

fn reopen(client: &BridgeClient) {
    let info = client.send_command("program_info", None).unwrap();
    let name = info["name"].as_str().unwrap();
    client.program_close().unwrap();
    client.open_program(name).unwrap();
}

fn read(client: &BridgeClient, address: &str, size: usize) -> String {
    client
        .send_command("read_memory", Some(json!({"address":address,"size":size})))
        .unwrap()["hex"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn hex(value: u64, width: usize, big: bool) -> String {
    let bytes = if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    let bytes = if big {
        &bytes[8 - width..]
    } else {
        &bytes[..width]
    };
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[serial]
fn memory_write_preserves_data_settings_and_unchanged_instructions() {
    fixture("x86:LE:64:default", |client| {
        client.memory_write("0x1001", "aa").unwrap();
        client.memory_write("0x1008", "0019000000000000").unwrap();
        client.memory_write("0x1380", "aa").unwrap();
        // Only the data byte changes; the two-byte instruction is untouched.
        client.memory_write("0x1100", "669011000000").unwrap();
        client.memory_write("0x1100", "6690").unwrap();
        verify(client, "data");
        reopen(client);
        verify(client, "data");
        // A change inside an instruction clears the whole instruction and its metadata.
        client.memory_write("0x1101", "91").unwrap();
        verify(client, "cleared");
        reopen(client);
        verify(client, "cleared");
    });
}

#[test]
#[serial]
fn memory_write_clears_shortened_instructions_when_their_parsed_tail_changes() {
    fixture("x86:LE:64:default", |client| {
        client
            .send_command(
                "memory_block_create",
                Some(
                    json!({"name": "high_patch", "start": "0xffff800000000000", "size": 4,
                    "fill": 0, "permissions": "rw"}),
                ),
            )
            .unwrap();
        client.memory_write("0xffff800000000000", "01").unwrap();
        verify(client, "shortened-intact");
        // The listing shows one instruction byte and then a dword, but all five
        // bytes still contribute to the instruction's decoded value.
        client.memory_write("0x1122", "22").unwrap();
        verify(client, "shortened-cleared");
        // An intervening instruction can end before an older shortened
        // instruction's parsed tail, so finding only the nearest one is unsafe.
        for address in ["0x1144", "0x1164"] {
            client.memory_write(address, "22").unwrap();
        }
        verify(client, "intervening-preserved");
        reopen(client);
        verify(client, "shortened-cleared");
        verify(client, "intervening-preserved");
    });
}

fn pointers(language: &str, width: usize, big: bool) {
    fixture(language, |client| {
        for slot in 0..=14 {
            let value = match slot {
                6 => 0x1904,
                7 => 0x80,
                11 => 0x11800, // Masked bits change, decoded address does not.
                _ => 0x1900,
            };
            let width = if slot == 13 { 2 } else { width };
            client
                .memory_write(
                    &format!("0x{:x}", 0x1200 + 8 * slot),
                    &hex(value, width, big),
                )
                .unwrap();
        }
        verify(client, "pointers");
        reopen(client);
        verify(client, "pointers");
        for value in [0, u64::MAX] {
            client
                .memory_write("0x1200", &hex(value, width, big))
                .unwrap();
            verify(client, "null");
        }
    });
}

#[test]
#[serial]
fn memory_write_pointer_references_64_bit_little_endian() {
    pointers("x86:LE:64:default", 8, false);
}

#[test]
#[serial]
fn memory_write_pointer_references_32_bit_big_endian() {
    pointers("MIPS:BE:32:default", 4, true);
}

#[test]
#[serial]
fn memory_write_pointer_references_64_bit_big_endian() {
    pointers("AARCH64:BE:64:v8A", 8, true);
}

#[test]
#[serial]
fn memory_write_preserves_string_storage_and_rejects_layout_changes() {
    fixture("x86:LE:64:default", |client| {
        for (address, bytes) in [
            ("0x1300", "61006300"),
            ("0x1310", "61006300"),
            ("0x1320", "78797a00"),
            ("0x1331", "78797a"),
            ("0x1340", "780079000000"),
            ("0x1350", "78797a00"),
            ("0x1360", "8101"), // Unsupported Dynamic is harmless when unchanged.
        ] {
            client.memory_write(address, bytes).unwrap();
        }
        verify(client, "strings");
        let before = read(client, "0x1100", 0x280);
        for (address, bytes) in [
            ("0x1321", "00"),
            ("0x1323", "41"),
            ("0x1330", "02"),
            ("0x1330", "04"),
            ("0x1342", "0000"),
            ("0x1344", "4100"),
            ("0x1351", "00"),
            ("0x1360", "8201"),
            ("0x1370", "0200"),
        ] {
            let error = client.memory_write(address, bytes).unwrap_err();
            assert!(error.to_string().contains("Cannot preserve"), "{error}");
            assert_eq!(read(client, "0x1100", 0x280), before);
        }
        // A late invalid data edit must also preserve an earlier instruction.
        let mut patch = before.clone();
        patch.replace_range(0..2, "90");
        patch.replace_range(0x221 * 2..0x222 * 2, "00");
        let error = client.memory_write("0x1100", &patch).unwrap_err();
        assert!(error.to_string().contains("Cannot preserve"), "{error}");
        assert_eq!(read(client, "0x1100", 0x280), before);
        assert!(client.disasm("0x1100", Some(1)).is_ok());
        reopen(client);
        verify(client, "strings");
        assert_eq!(read(client, "0x1100", 0x280), before);
    });
}

#[test]
#[serial]
fn memory_write_rejects_shared_changes_but_allows_noops_and_independent_overlays() {
    fixture("x86:LE:64:default", |client| {
        for address in ["0x1700", "0x3000", "0x4000"] {
            let original = read(client, address, 1);
            client.memory_write(address, &original).unwrap();
            let error = client.memory_write(address, "ff").unwrap_err();
            assert!(
                error.to_string().contains("shared mapped memory"),
                "{error}"
            );
            assert_eq!(read(client, address, 1), original);
        }
        // Including an unchanged shared byte must not reject an independent edit.
        client.memory_write("0x16ff", "aa00").unwrap();
        assert_eq!(read(client, "0x16ff", 2), "aa00");
        client
            .memory_write("overlay:0x1200", "0019000000000000")
            .unwrap();
        client
            .memory_write("overlay:0x1ff8", "0029000000000000")
            .unwrap();
        verify(client, "overlay");
        reopen(client);
        verify(client, "overlay");
    });
}

#[test]
#[serial]
fn memory_write_allows_unchanged_bytes_through_nested_mappings() {
    fixture("x86:LE:64:default", |client| {
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class CreateNestedPatchMapping extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createByteMappedBlock("nested_patch_view",
            toAddr(0x2000), toAddr(0x3000), 16, false);
        memory.createBitMappedBlock("nested_patch_bits",
            toAddr(0x2100), toAddr(0x3001), 8, false);
        memory.createByteMappedBlock("nested_bit_bytes",
            toAddr(0x2200), toAddr(0x2100), 8, false);
        memory.createBitMappedBlock("nested_bits_of_bits",
            toAddr(0x2300), toAddr(0x2103), 8, false);
        memory.createByteMappedBlock("cyclic_patch_view",
            toAddr(0x5000), toAddr(0x5000), 1, false);
        memory.createByteMappedBlock("shifted_patch_view",
            toAddr(0x5100), toAddr(0x5101), 8, false);
        memory.createInitializedBlock("shifted_patch_source",
            toAddr(0x5108), 1, (byte) 0x5a, monitor, false);
        memory.createByteMappedBlock("large_shifted_patch_view",
            toAddr(0x10000), toAddr(0x10001), 16 * 1024, false);
        memory.createInitializedBlock("large_shifted_patch_source",
            toAddr(0x14000), 1, (byte) 0x5a, monitor, false);
        for (int i = 63; i >= 0; i--) {
            memory.createByteMappedBlock("deep_patch_view_" + i, toAddr(0x6000 + 16 * i),
                toAddr(i == 63 ? 0x3001 : 0x6000 + 16 * (i + 1)), 1, false);
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let original = read(client, "0x2000", 8);
        client.memory_write("0x2000", &original).unwrap();
        for (address, expected) in [
            ("0x2100", "0000000101000000"),
            ("0x2200", "0000000101000000"),
            ("0x2300", "0100000000000000"),
            ("0x5100", "5a5a5a5a5a5a5a5a"),
            ("0x6000", "18"),
        ] {
            client.memory_write(address, expected).unwrap();
        }
        client
            .memory_write("0x10000", &"5a".repeat(16 * 1024))
            .unwrap();
        for (address, hex) in [("0x2008", "00"), ("0x5000", "00")] {
            let error = client.memory_write(address, hex).unwrap_err();
            assert!(
                error.to_string().contains("fully mapped and initialized"),
                "{error}"
            );
        }
        let error = client.memory_write("0x2000", "ff").unwrap_err();
        assert!(
            error.to_string().contains("shared mapped memory"),
            "{error}"
        );
        assert_eq!(read(client, "0x2000", 8), original);
        assert_eq!(read(client, "0x3000", 8), original);
        assert_eq!(read(client, "0x1700", 8), original);
        // Native program-open byte probes recurse on cyclic/deep self mappings.
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class RemoveRecursivePatchMappings extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        for (long address : new long[]{0x5000, 0x10000, 0x14000}) {
            memory.removeBlock(memory.getBlock(toAddr(address)), monitor);
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        reopen(client);
        client.memory_write("0x2000", &original).unwrap();
        assert_eq!(read(client, "0x2000", 8), original);
    });
}

#[test]
#[serial]
fn memory_write_rejects_shared_file_bytes_and_preserves_alias_metadata() {
    fixture("x86:LE:64:default", |client| {
        client
            .script_run_source(FIXTURE, &["create-file-aliases".to_owned()], &[], false)
            .unwrap();
        let aliases = [
            "0x5008",
            "0x6000",
            "file_overlay:0x5000",
            "0x8000",
            "0x8008",
        ];
        for address in aliases {
            let original = read(client, address, 8);
            client.memory_write(address, &original).unwrap();
            let error = client
                .memory_write(address, "0019000000000000")
                .unwrap_err();
            assert!(error.to_string().contains("shared file bytes"), "{error}");
            for alias in aliases {
                assert_eq!(read(client, alias, 8), original);
            }
        }
        // Unchanged shared bytes can accompany an edit to an unshared file offset.
        let mut bytes = read(client, "0x5000", 16);
        bytes.replace_range(0..2, "aa");
        client.memory_write("0x5000", &bytes).unwrap();
        client.memory_write("0x9008", "0019000000000000").unwrap();
        verify(client, "file-aliases");
        reopen(client);
        verify(client, "file-aliases");
    });
}

#[test]
#[serial]
fn memory_write_clears_the_ghidra_delay_slot_unit() {
    fixture("MIPS:BE:32:default", |client| {
        client.memory_write("0x1107", "02").unwrap();
        verify(client, "delay");
        reopen(client);
        verify(client, "delay");
    });
}
