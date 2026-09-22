//! Component metadata retains native ordinals and bit storage across byte orders.

use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn definition(program: &str, name: &str) -> Value {
    let result = type_command(program, &["get", name]);
    result.assert_success();
    result.data::<Value>()
}

fn field<'a>(definition: &'a Value, name: &str) -> &'a Value {
    definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == name)
        .unwrap_or_else(|| panic!("Missing field {name}: {definition}"))
}

fn assert_ordinary(component: &Value) {
    assert_eq!(component["is_bitfield"], false, "{component}");
    for key in ["bit_offset", "bit_size", "base_type", "base_type_path"] {
        assert_eq!(component.get(key), Some(&Value::Null), "{key}: {component}");
    }
}

fn assert_ordinals(definition: &Value) {
    for (ordinal, component) in definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(component["ordinal"], ordinal, "{definition}");
    }
}

#[test]
#[serial]
fn ordinary_component_ordinals_include_struct_padding_and_overlapping_union_members() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateOrdinaryComponentMetadata extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Layout");
        var structure = new StructureDataType(path, "OrdinaryStruct", 10, dtm);
        structure.replaceAtOffset(0, DWordDataType.dataType, 4, "word", "word comment");
        structure.replaceAtOffset(8, ByteDataType.dataType, 1, null, "anonymous byte");
        dtm.addDataType(structure, null);
        var union = new UnionDataType(path, "OrdinaryUnion", dtm);
        union.add(DWordDataType.dataType, "word", "word comment");
        union.add(ByteDataType.dataType, null, "anonymous byte");
        dtm.addDataType(union, null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    let structure = definition(&program, "/Layout/OrdinaryStruct");
    let union = definition(&program, "/Layout/OrdinaryUnion");
    assert_eq!(structure["size"], 10);
    assert_eq!(structure["components"].as_array().unwrap().len(), 7);
    assert_eq!(union["size"], 4);
    assert_eq!(union["components"].as_array().unwrap().len(), 2);
    for definition in [&structure, &union] {
        assert_ordinals(definition);
        for component in definition["components"].as_array().unwrap() {
            assert_ordinary(component);
        }
        let word = field(definition, "word");
        assert_eq!(word["ordinal"], 0);
        assert_eq!(word["offset"], 0);
        assert_eq!(word["size"], 4);
        assert_eq!(word["type"], "dword");
        assert_eq!(word["type_path"], "/dword");
        assert_eq!(word["display_name"], "word");
        assert_eq!(word["comment"], "word comment");
    }
    let anonymous = &structure["components"][5];
    assert_eq!(anonymous["ordinal"], 5);
    assert_eq!(anonymous["offset"], 8);
    assert_eq!(anonymous["name"], Value::Null);
    assert!(!anonymous["display_name"].as_str().unwrap().is_empty());
    assert_eq!(anonymous["comment"], "anonymous byte");
    assert_eq!(union["components"][1]["offset"], 0);
    assert_eq!(union["components"][1]["name"], Value::Null);

    // Field projection keeps every nested component intact.
    let projected = type_command(
        &program,
        &[
            "get",
            "/Layout/OrdinaryStruct",
            "--fields",
            "name,components",
        ],
    );
    projected.assert_success();
    assert_eq!(
        projected.data::<Value>(),
        json!({"name": "OrdinaryStruct", "components": structure["components"]})
    );
    client.program_close().unwrap();
    assert_eq!(definition(&program, "/Layout/OrdinaryStruct"), structure);
    assert_eq!(definition(&program, "/Layout/OrdinaryUnion"), union);
    client.open_program(TEST_PROGRAM).unwrap();
}

fn bit_value(component: &Value, bytes: &[u8], big_endian: bool) -> u64 {
    let offset = component["offset"].as_u64().unwrap() as usize;
    let size = component["size"].as_u64().unwrap() as usize;
    let storage = &bytes[offset..offset + size];
    let value = if big_endian {
        storage
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
    } else {
        storage
            .iter()
            .rev()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
    };
    (value >> component["bit_offset"].as_u64().unwrap())
        & ((1 << component["bit_size"].as_u64().unwrap()) - 1)
}

#[test]
#[serial]
fn bitfield_components_describe_native_storage_for_both_byte_orders() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, big_endian) in [
        ("x86:LE:32:default", false),
        ("PowerPC:BE:32:default", true),
    ] {
        let program = create_type_edit_program(language);
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateBitfieldComponentMetadata extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Layout");
        var word = dtm.addDataType(new TypedefDataType(path, "Word",
            UnsignedIntegerDataType.dataType, dtm), null);
        var structure = new StructureDataType(path, "BitLayout", 4, dtm);
        structure.insertBitFieldAt(0, 4, 0, word, 3, "low", "low three bits");
        structure.insertBitFieldAt(0, 4, 3, word, 10, "cross", "crosses a byte");
        structure.insertBitFieldAt(0, 4, 13, word, 3, null, "unnamed bits");
        dtm.addDataType(structure, null);
        var union = new UnionDataType(path, "BitUnion", dtm);
        union.addBitField(word, 3, "flags", "union flags");
        union.add(word, "raw", null);
        dtm.addDataType(union, null);
        var zero = new StructureDataType(path, "ZeroWidth", 0, dtm);
        zero.setPackingEnabled(true);
        zero.addBitField(word, 3, "before", null);
        zero.addBitField(word, 0, null, "alignment boundary");
        zero.addBitField(word, 4, "after", null);
        dtm.addDataType(zero, null);
        var clipped = new StructureDataType(path, "Clipped", 0, dtm);
        clipped.insertBitFieldAt(0, 1, 0, UnsignedCharDataType.dataType, 12, "clipped", null);
        dtm.addDataType(clipped, null);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let structure = definition(&program, "/Layout/BitLayout");
        assert_eq!(structure["size"], 4);
        assert_eq!(structure["packing_enabled"], false);
        assert_ordinals(&structure);
        let bits: Vec<_> = structure["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|component| component["is_bitfield"] == true)
            .collect();
        assert_eq!(bits.len(), 3, "{language}: {structure}");
        for bit in bits {
            assert_eq!(bit["base_type"], "Word");
            assert_eq!(bit["base_type_path"], "/Layout/Word");
        }
        let low = field(&structure, "low");
        let cross = field(&structure, "cross");
        assert_eq!(low["offset"], if big_endian { 3 } else { 0 });
        assert_eq!(low["size"], 1);
        assert_eq!(low["bit_offset"], 0);
        assert_eq!(low["bit_size"], 3);
        assert_eq!(low["type"], "Word:3");
        assert_eq!(low["comment"], "low three bits");
        assert_eq!(cross["offset"], if big_endian { 2 } else { 0 });
        assert_eq!(cross["size"], 2);
        assert_eq!(cross["bit_offset"], 3);
        assert_eq!(cross["bit_size"], 10);
        let unnamed = structure["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["comment"] == "unnamed bits")
            .unwrap();
        assert_eq!(unnamed["name"], Value::Null);
        assert!(!unnamed["display_name"].as_str().unwrap().is_empty());
        assert_eq!(unnamed["bit_offset"], 5);
        assert_eq!(unnamed["bit_size"], 3);
        let bytes = if big_endian {
            [0xde, 0xad, 0xb6, 0xd5]
        } else {
            [0xd5, 0xb6, 0xad, 0xde]
        };
        assert_eq!(bit_value(low, &bytes, big_endian), 5);
        assert_eq!(bit_value(cross, &bytes, big_endian), 730);
        assert_eq!(bit_value(unnamed, &bytes, big_endian), 5);

        let union = definition(&program, "/Layout/BitUnion");
        assert_ordinals(&union);
        let flags = field(&union, "flags");
        assert_eq!(flags["is_bitfield"], true);
        assert_eq!(flags["offset"], 0);
        assert_eq!(flags["size"], 1);
        assert_eq!(flags["bit_size"], 3);
        assert_eq!(flags["bit_offset"], if big_endian { 5 } else { 0 });
        assert_eq!(flags["base_type_path"], "/Layout/Word");
        assert_ordinary(field(&union, "raw"));

        let zero = definition(&program, "/Layout/ZeroWidth");
        assert_ordinals(&zero);
        let boundary = &zero["components"][1];
        assert_eq!(boundary["is_bitfield"], true, "{zero}");
        assert_eq!(boundary["bit_size"], 0);
        assert_eq!(boundary["size"], 0);
        assert_eq!(boundary["name"], Value::Null);
        assert_eq!(boundary["display_name"], Value::Null);
        assert_eq!(boundary["comment"], "alignment boundary");
        assert_eq!(boundary["base_type_path"], "/Layout/Word");
        let clipped = definition(&program, "/Layout/Clipped");
        assert_eq!(field(&clipped, "clipped")["bit_size"], 8);
        assert_eq!(field(&clipped, "clipped")["size"], 1);

        client.program_close().unwrap();
        for saved in [&structure, &union, &zero, &clipped] {
            assert_eq!(
                definition(&program, saved["path"].as_str().unwrap()),
                *saved
            );
        }
    }
    client.open_program(TEST_PROGRAM).unwrap();
}
