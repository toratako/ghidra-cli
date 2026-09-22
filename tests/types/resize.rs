//! Tail resizing preserves definitions and validates native propagation before saving.

use super::common::helpers::GhidraResult;
use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn success(result: GhidraResult) -> Value {
    result.assert_success();
    result.data()
}

fn definition(program: &str, name: &str) -> Value {
    success(type_command(program, &["get", name]))
}

fn field<'a>(definition: &'a Value, name: &str) -> &'a Value {
    definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("Missing field {name}: {definition}"))
}

fn resize(program: &str, name: &str, size: u32) -> Value {
    success(type_command(program, &["resize", name, &size.to_string()]))
}

fn rejected(program: &str, name: &str, size: u32) {
    let result = type_command(program, &["resize", name, &size.to_string()]);
    result.assert_failure();
    let error: Value = serde_json::from_str(&result.stderr).unwrap();
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert!(error["detail"].get("partial_changes_saved").is_none());
}

#[test]
#[serial]
fn resize_preserves_explicit_fields_bitfields_zero_length_boundaries_and_settings() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateResizeFields extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var tail = new StructureDataType(CategoryPath.ROOT, "Tail", 16, dtm);
        tail.setDescription("recovered header");
        tail.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "saved value");
        tail.replaceAtOffset(4, Undefined4DataType.dataType, 4, "unknown", "explicit undefined");
        tail.insertAtOffset(12, new ArrayDataType(ByteDataType.dataType, 0, 1), 0, "boundary", "zero length");
        var saved = (Structure) dtm.addDataType(tail, null);
        FormatSettingsDefinition.DEF.setChoice(saved.getComponentAt(0).getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(saved.getComponentAt(0).getDefaultSettings(), EndianSettingsDefinition.BIG);
        var flags = new StructureDataType(CategoryPath.ROOT, "Flags", 12, dtm);
        flags.insertBitFieldAt(6, 2, 4, UnsignedShortDataType.dataType, 8, "bits", "spans bytes");
        dtm.addDataType(flags, null);
        var packed = new StructureDataType(CategoryPath.ROOT, "Packed", 0, dtm);
        packed.setPackingEnabled(true);
        packed.add(DWordDataType.dataType, "value", null);
        dtm.addDataType(packed, null);
    }
}
"#, &[], &[], false).unwrap();
    let before = definition(&program, "Tail");
    let resized = resize(&program, "/Tail", 12);
    assert_eq!(resized["status"], "resized");
    assert_eq!(resized["changed"], true);
    assert_eq!(resized["path"], "/Tail");
    assert_eq!(resized["size_before"], 16);
    assert_eq!(resized["size_after"], 12);
    let trimmed = definition(&program, "Tail");
    for name in ["value", "unknown", "boundary"] {
        assert_eq!(field(&trimmed, name), field(&before, name));
    }
    assert_eq!(field(&trimmed, "boundary")["offset"], 12);
    assert_eq!(field(&trimmed, "boundary")["size"], 0);
    let noop = resize(&program, "Tail", 12);
    assert_eq!(noop["status"], "unchanged");
    assert_eq!(noop["changed"], false);
    rejected(&program, "Tail", 11);
    rejected(&program, "Tail", 7);
    assert_eq!(definition(&program, "Tail"), trimmed);
    resize(&program, "Tail", 24);
    let expanded = definition(&program, "Tail");
    for name in ["value", "unknown", "boundary"] {
        assert_eq!(field(&expanded, name), field(&before, name));
    }
    let flags_before = definition(&program, "Flags");
    resize(&program, "Flags", 8);
    assert_eq!(
        field(&definition(&program, "Flags"), "bits"),
        field(&flags_before, "bits")
    );
    rejected(&program, "Flags", 7);
    rejected(&program, "Packed", 16);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "Tail"), expanded);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CheckResizeFieldSettings extends GhidraScript {
    public void run() throws Exception {
        var tail = (Structure) currentProgram.getDataTypeManager().getDataType("/Tail");
        var settings = tail.getComponentAt(0).getDefaultSettings();
        if (FormatSettingsDefinition.DEF.getChoice(settings) != FormatSettingsDefinition.DECIMAL
                || EndianSettingsDefinition.DEF.getChoice(settings) != EndianSettingsDefinition.BIG)
            throw new IllegalStateException("Field settings were lost");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_zero_is_logical_and_wire_sizes_are_checked_before_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    success(type_command(&program, &["create", "struct", "Empty"]));
    let client = harness().client().unwrap();
    let noop = resize(&program, "Empty", 0);
    assert_eq!(noop["size_before"], 0);
    assert_eq!(noop["size_after"], 0);
    assert_eq!(noop["changed"], false);
    resize(&program, "Empty", 9);
    resize(&program, "Empty", 0);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "Empty")["size"], 0);
    let listed = success(type_command(&program, &["list", "--filter", "name=Empty"]));
    assert_eq!(listed[0]["size"], 0);
    let before = definition(&program, "Empty");
    for size in [json!(-1), json!(1.5), json!(2147483648_u64), json!("8")] {
        client
            .send_command(
                "type_resize",
                Some(json!({"type_name": "/Empty", "size": size})),
            )
            .expect_err("Invalid wire size reached resize");
        assert_eq!(definition(&program, "Empty"), before);
    }
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateResizeComponentOverflow extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var bits = new StructureDataType(CategoryPath.ROOT, "BitCount", 1, dtm);
        bits.insertBitFieldAt(0, 1, 0, ByteDataType.dataType, 2, "low", null);
        bits.insertBitFieldAt(0, 1, 2, ByteDataType.dataType, 2, "high", null);
        dtm.addDataType(bits, null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = definition(&program, "BitCount");
    rejected(&program, "BitCount", i32::MAX as u32);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "BitCount"), before);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_propagates_complete_layouts_through_parents_typedefs_arrays_and_listing() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateResizePropagation extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var child = new StructureDataType(CategoryPath.ROOT, "Child", 4, dtm);
        child.replaceAtOffset(0, WordDataType.dataType, 2, "value", "keep");
        var saved = dtm.addDataType(child, null);
        var alias = dtm.addDataType(new TypedefDataType("ChildAlias", saved), null);
        var array = dtm.addDataType(new ArrayDataType(alias, 3, 4), null);
        var holder = new StructureDataType(CategoryPath.ROOT, "Holder", 40, dtm);
        holder.replaceAtOffset(0, alias, 4, "child", null);
        holder.replaceAtOffset(8, array, 12, "array", null);
        holder.replaceAtOffset(36, DWordDataType.dataType, 4, "tail", "keep tail");
        var registeredHolder = dtm.addDataType(holder, null);
        var packed = new StructureDataType(CategoryPath.ROOT, "PackedHolder", 0, dtm);
        packed.setPackingEnabled(true);
        packed.add(saved, "child", null);
        packed.add(ByteDataType.dataType, "tag", "moves with packing");
        var registeredPacked = dtm.addDataType(packed, null);
        var union = new UnionDataType("UnionHolder");
        union.add(saved, "child", null);
        union.add(QWordDataType.dataType, "wide", null);
        dtm.addDataType(union, null);
        var nested = dtm.addDataType(new ArrayDataType(new ArrayDataType(alias, 2, 4), 2, 8), null);
        var address = toAddr(0x1000);
        currentProgram.getMemory().createInitializedBlock("data", address, 512, (byte) 0, monitor, false);
        var listing = currentProgram.getListing();
        listing.createData(address, registeredHolder);
        listing.createData(toAddr(0x1080), registeredPacked);
        listing.createData(toAddr(0x1100), nested);
        listing.createData(toAddr(0x1180), alias);
        FormatSettingsDefinition.DEF.setChoice(listing.getDefinedDataAt(toAddr(0x1180)).getComponent(0), FormatSettingsDefinition.DECIMAL);
        FormatSettingsDefinition.DEF.setChoice(((Structure) registeredHolder).getComponentAt(36).getDefaultSettings(), FormatSettingsDefinition.BINARY);
        var aligned = new StructureDataType(CategoryPath.ROOT, "Aligned", 4, dtm);
        aligned.setExplicitMinimumAlignment(8);
        aligned.replaceAtOffset(0, WordDataType.dataType, 2, "value", null);
        var registeredAligned = dtm.addDataType(aligned, null);
        dtm.addDataType(new TypedefDataType("AlignedArray", new ArrayDataType(registeredAligned, 2, 8)), null);
    }
}
"#, &[], &[], false).unwrap();
    for size in [8, 2] {
        resize(&program, "Child", size);
        assert_eq!(
            field(&definition(&program, "Holder"), "child")["size"],
            size
        );
        assert_eq!(
            field(&definition(&program, "Holder"), "array")["size"],
            size * 3
        );
        assert_eq!(field(&definition(&program, "Holder"), "tail")["offset"], 36);
        assert_eq!(
            field(&definition(&program, "PackedHolder"), "tag")["offset"],
            size
        );
        assert_eq!(
            field(&definition(&program, "UnionHolder"), "child")["size"],
            size
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CheckResizePropagation extends GhidraScript {
    public void run() throws Exception {
        int size = Integer.parseInt(getScriptArgs()[0]);
        var listing = currentProgram.getListing();
        int[] addresses = { 0x1000, 0x1080, 0x1100, 0x1180 };
        int[] lengths = { 40, size + 1, size * 4, size };
        for (int i = 0; i < addresses.length; i++) {
            var data = listing.getDefinedDataAt(toAddr(addresses[i]));
            if (data == null || data.getLength() != lengths[i] || data.getNumComponents() < 0)
                throw new IllegalStateException("Incomplete data at " + addresses[i]);
        }
        var nested = listing.getDefinedDataAt(toAddr(0x1100));
        if (nested.getComponent(1).getComponent(1).getMinAddress().getOffset() != 0x1100 + 3 * size)
            throw new IllegalStateException("Nested array stride did not propagate");
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        if (FormatSettingsDefinition.DEF.getChoice(holder.getComponentAt(36).getDefaultSettings()) != FormatSettingsDefinition.BINARY)
            throw new IllegalStateException("Parent field settings were lost");
        if (FormatSettingsDefinition.DEF.getChoice(listing.getDefinedDataAt(toAddr(0x1180)).getComponent(0)) != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Applied component settings were lost");
    }
}
"#, &[size.to_string()], &[], false).unwrap();
    }
    resize(&program, "Aligned", 12);
    // Ghidra uses the nonpacked structure's exact length as its array stride,
    // even with explicit minimum alignment; getAlignedLength() remains 12.
    assert_eq!(definition(&program, "AlignedArray")["size"], 24);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_rejects_incomplete_embeddings_and_applications_with_durable_rollback() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateResizeConflicts extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (String name : new String[] { "Embedded", "MemoryEdge", "DataNeighbor", "InstructionNeighbor", "Overflow", "AppliedEmpty", "AppliedSettings", "ArraySettings" }) {
            var child = new StructureDataType(CategoryPath.ROOT, name, 4, dtm);
            if (name.equals("ArraySettings")) child.replaceAtOffset(0, WordDataType.dataType, 2, "value", null);
            var saved = dtm.addDataType(child, null);
            if (name.equals("Embedded")) {
                var parent = new StructureDataType(CategoryPath.ROOT, "ConstrainedHolder", 8, dtm);
                parent.replaceAtOffset(0, saved, 4, "child", null);
                parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", "do not consume");
                dtm.addDataType(parent, null);
            } else if (name.equals("Overflow")) {
                dtm.addDataType(new ArrayDataType(saved, 536870911, 4), null);
            } else {
                int address = name.equals("MemoryEdge") ? 0x1000 : name.equals("DataNeighbor") ? 0x2000
                    : name.equals("InstructionNeighbor") ? 0x3000 : name.equals("AppliedSettings") ? 0x5000
                    : name.equals("ArraySettings") ? 0x6000 : 0x4000;
                currentProgram.getMemory().createInitializedBlock(name, toAddr(address), name.equals("MemoryEdge") ? 6 : 32, (byte) 0x90, monitor, false);
                var listing = currentProgram.getListing();
                if (name.equals("AppliedSettings")) {
                    var packed = new StructureDataType(CategoryPath.ROOT, "SettingsHolder", 0, dtm);
                    packed.setPackingEnabled(true);
                    packed.add(saved, "child", null);
                    packed.add(ByteDataType.dataType, "tag", null);
                    var data = listing.createData(toAddr(address), dtm.addDataType(packed, null));
                    FormatSettingsDefinition.DEF.setChoice(data.getComponent(1), FormatSettingsDefinition.BINARY);
                } else if (name.equals("ArraySettings")) {
                    var data = listing.createData(toAddr(address), new ArrayDataType(saved, 2, 4));
                    FormatSettingsDefinition.DEF.setChoice(data.getComponent(1).getComponent(0), FormatSettingsDefinition.DECIMAL);
                } else {
                    listing.createData(toAddr(address), saved);
                }
                if (name.equals("DataNeighbor"))
                    currentProgram.getListing().createData(toAddr(address + 6), Undefined4DataType.dataType);
                if (name.equals("InstructionNeighbor")) disassemble(toAddr(address + 6));
            }
        }
    }
}
"#, &[], &[], false).unwrap();
    let before = success(type_command(&program, &["list", "--limit", "0"]));
    let holder = definition(&program, "ConstrainedHolder");
    for (name, size) in [
        ("Embedded", 8),
        ("MemoryEdge", 8),
        ("DataNeighbor", 8),
        ("InstructionNeighbor", 8),
        ("Overflow", 8),
        ("AppliedEmpty", 0),
        ("AppliedSettings", 8),
        ("ArraySettings", 8),
    ] {
        rejected(&program, name, size);
        client.program_close().unwrap();
        assert_eq!(
            success(type_command(&program, &["list", "--limit", "0"])),
            before
        );
        assert_eq!(definition(&program, "ConstrainedHolder"), holder);
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckResizeConflictRollback extends GhidraScript {
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        for (int address : new int[] { 0x1000, 0x2000, 0x3000, 0x4000 }) {
            var data = listing.getDefinedDataAt(toAddr(address));
            if (data == null || data.getLength() != 4 || data.getDataType().getLength() != 4)
                throw new IllegalStateException("Applied data changed after rollback at " + address);
        }
        var neighbor = listing.getDefinedDataAt(toAddr(0x2006));
        if (neighbor == null || neighbor.getLength() != 4)
            throw new IllegalStateException("Following defined data was lost");
        if (listing.getInstructionAt(toAddr(0x3006)) == null)
            throw new IllegalStateException("Following instruction was lost");
        var packed = listing.getDefinedDataAt(toAddr(0x5000));
        if (packed.getLength() != 5 || FormatSettingsDefinition.DEF.getChoice(packed.getComponent(1)) != FormatSettingsDefinition.BINARY)
            throw new IllegalStateException("Packed applied component settings changed");
        var array = listing.getDefinedDataAt(toAddr(0x6000));
        if (array.getLength() != 8 || FormatSettingsDefinition.DEF.getChoice(array.getComponent(1).getComponent(0)) != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Array component settings changed");
    }
}
"#, &[], &[], false).unwrap();
    }
    client.open_program(TEST_PROGRAM).unwrap();
}
