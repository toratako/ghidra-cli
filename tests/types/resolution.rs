//! Array expressions, target data organization, and unambiguous type lookup.

use super::common::helpers::GhidraResult;
use super::{ghidra, harness, test_project, unique_suffix, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn type_command(program: &str, args: &[&str]) -> GhidraResult {
    program_command(program, &[&["type"], args].concat())
}

fn program_command(program: &str, args: &[&str]) -> GhidraResult {
    ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn get_type(program: &str, name: &str) -> Value {
    let result = type_command(program, &["get", name]);
    result.assert_success();
    let result: Value = result.data();
    result.clone()
}

fn create_program(bits: u32) -> String {
    create_language_program(&format!("x86:LE:{bits}:default"))
}

fn create_language_program(language: &str) -> String {
    let program = format!("type-resolution-{}", unique_suffix());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateTypeResolutionProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("type resolution fixture");
            try {
                var dtm = program.getDataTypeManager();
                var hook = new FunctionDefinitionDataType(new CategoryPath("/Recovered"), "Hook", dtm);
                hook.setReturnType(VoidDataType.dataType);
                dtm.addDataType(hook, null);
                dtm.addDataType(new StructureDataType(CategoryPath.ROOT, "Holder", 0, dtm), null);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            &[program.clone(), language.to_string()],
            &[],
            false,
        )
        .unwrap();
    program
}

#[test]
#[serial]
fn arrays_and_pointers_use_the_selected_program_width() {
    require_ghidra!();
    for bits in [32, 64] {
        let program = create_program(bits);
        let pointer_size = bits / 8;
        for (expression, size, kind) in [
            ("byte[16]", 16, "array"),
            ("uint32_t[3]", 12, "array"),
            ("unsigned short [ 2 ]", 4, "array"),
            ("byte[2][3]", 6, "array"),
            ("void *", pointer_size, "pointer"),
            ("uint32_t **", pointer_size, "pointer"),
            ("pointer[3]", pointer_size * 3, "array"),
            ("Hook *[8]", pointer_size * 8, "array"),
            ("/Recovered/Hook *[8]", pointer_size * 8, "array"),
        ] {
            let resolved = get_type(&program, expression);
            assert_eq!(
                resolved["size"], size,
                "{bits}-bit {expression}: {resolved}"
            );
            assert_eq!(resolved["kind"], kind, "{resolved}");
        }
        assert_eq!(get_type(&program, "byte[2][3]")["name"], "byte[2][3]");

        for (name, expression) in [("hooks", "/Recovered/Hook *[8]"), ("matrix", "byte[2][3]")] {
            type_command(
                &program,
                &[
                    "field", "append", "Holder", "--name", name, "--type", expression,
                ],
            )
            .assert_success();
        }
        let holder = get_type(&program, "Holder");
        assert_eq!(holder["size"], pointer_size * 8 + 6, "{holder}");
        assert_eq!(holder["components"][0]["size"], pointer_size * 8);
        assert_eq!(holder["components"][1]["offset"], pointer_size * 8);
        assert_eq!(holder["components"][1]["type"], "byte[2][3]");

        // Inspect the actual stored dimension order, then close/reopen to
        // verify that the resolved arrays survive the request save boundary.
        let client = harness().client().unwrap();
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
public class CheckArrayDimensions extends GhidraScript {
    public void run() throws Exception {
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        var outer = (Array) holder.getComponent(1).getDataType();
        var inner = (Array) outer.getDataType();
        if (outer.getNumElements() != 2 || inner.getNumElements() != 3)
            throw new IllegalStateException("Array dimensions were reversed");
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        client.program_close().unwrap();
        let saved = get_type(&program, "Holder");
        client.open_program(TEST_PROGRAM).unwrap();
        assert_eq!(saved, holder);
    }
}

#[test]
#[serial]
fn invalid_arrays_fail_before_registering_types_or_growing_structures() {
    require_ghidra!();
    let program = create_program(64);
    type_command(
        &program,
        &[
            "field", "append", "Holder", "--name", "anchor", "--type", "byte",
        ],
    )
    .assert_success();
    let before = get_type(&program, "Holder");
    let listed = type_command(&program, &["list"]);
    listed.assert_success();
    let types_before: Value = listed.data();

    for expression in [
        "byte[0]",
        "byte[-1]",
        "byte[]",
        "byte[1x]",
        "byte[1",
        "byte]",
        "byte[2] trailing",
        "byte[2147483648]",
        "byte[999999999999999999999999]",
        "uint64_t[2147483647]",
        "byte[65536][65536]",
        "void[2]",
    ] {
        let failed = type_command(
            &program,
            &[
                "field", "set", "Holder", "--name", "invalid", "--type", expression, "--offset",
                "4096",
            ],
        );
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("Invalid array type"),
            "{expression}: {error}"
        );
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
        assert_eq!(get_type(&program, "Holder"), before, "{expression}");
    }

    // The representable boundary remains a valid detached type expression.
    assert_eq!(get_type(&program, "byte[2147483647]")["size"], i32::MAX);
    let listed = type_command(&program, &["list"]);
    listed.assert_success();
    let types_after: Value = listed.data();
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
    assert_eq!(types_after, types_before);
}

#[test]
#[serial]
fn ambiguous_short_names_report_sorted_paths_and_exact_paths_remain_usable() {
    require_ghidra!();
    let program = create_program(64);
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
public class CreateAmbiguousTypes extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        String[] paths = { "/zeta", "/", "/alpha" };
        for (int i = 0; i < paths.length; i++)
            dtm.addDataType(new StructureDataType(new CategoryPath(paths[i]), "Shared", i + 1, dtm), null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    let before = get_type(&program, "Holder");
    for args in [
        vec!["type", "get", "Shared"],
        vec!["type", "get", "Shared *[2]"],
        vec![
            "type", "field", "append", "Holder", "--name", "bad", "--type", "Shared",
        ],
        vec![
            "type",
            "create",
            "typedef",
            "AmbiguousAlias",
            "--type",
            "Shared",
        ],
        vec!["type", "rename", "Shared", "Renamed"],
        vec!["type", "delete", "Shared"],
        vec!["type", "field", "delete", "Shared", "--field", "missing"],
        vec![
            "listing",
            "define-data",
            "0x1000",
            "--type",
            "Shared",
            "--force",
        ],
    ] {
        let failed = program_command(&program, &args);
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("Ambiguous type name"),
            "{args:?}: {error}"
        );
        assert_eq!(
            error["detail"]["candidates"],
            json!(["/Shared", "/alpha/Shared", "/zeta/Shared"]),
            "{args:?}: {error}"
        );
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
    }
    assert_eq!(get_type(&program, "Holder"), before);
    for (path, size) in [("/Shared", 2), ("/alpha/Shared", 3), ("/zeta/Shared", 1)] {
        let resolved = get_type(&program, path);
        assert_eq!(resolved["path"], path);
        assert_eq!(resolved["size"], size);
    }
    for path in ["/missing/Shared", "/missing/byte"] {
        type_command(&program, &["get", path])
            .assert_failure()
            .assert_stderr_contains("Type not found");
    }
    type_command(
        &program,
        &[
            "field",
            "append",
            "Holder",
            "--name",
            "chosen",
            "--type",
            "/alpha/Shared",
        ],
    )
    .assert_success();
    let holder = get_type(&program, "Holder");
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(holder["components"][0]["size"], 3);
}

#[test]
#[serial]
fn program_types_take_precedence_over_builtins_and_alias_spellings() {
    require_ghidra!();
    let program = create_program(32);
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
public class CreateBuiltinShadows extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var category = new CategoryPath("/Shadows");
        dtm.addDataType(new StructureDataType(category, "uint32_t", 7, dtm), null);
        dtm.addDataType(new StructureDataType(category, "byte", 3, dtm), null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    assert_eq!(get_type(&program, "uint32_t")["path"], "/Shadows/uint32_t");
    assert_eq!(get_type(&program, "uint32_t[2]")["size"], 14);
    assert_eq!(get_type(&program, "byte")["path"], "/Shadows/byte");
    assert_eq!(get_type(&program, "byte[2]")["size"], 6);
    assert_eq!(get_type(&program, "u8")["size"], 1);
    assert_eq!(get_type(&program, "u32")["size"], 4);
    assert_eq!(get_type(&program, "/byte")["size"], 1);
    assert_eq!(get_type(&program, "/byte[2]")["size"], 2);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn fixed_width_aliases_preserve_width_and_signedness_on_a_16_bit_abi() {
    require_ghidra!();
    let program = create_language_program("TI_MSP430:LE:16:default");
    assert_eq!(get_type(&program, "int")["size"], 2);
    for (width, unsigned, signed) in [
        (1, "byte", "sbyte"),
        (2, "word", "sword"),
        (4, "dword", "sdword"),
        (8, "qword", "sqword"),
    ] {
        let bits = width * 8;
        for (alias, expected) in [
            (format!("uint{bits}_t"), unsigned),
            (format!("u{bits}"), unsigned),
            (format!("int{bits}_t"), signed),
            (format!("s{bits}"), signed),
        ] {
            let resolved = get_type(&program, &alias);
            assert_eq!(resolved["size"], width, "{alias}: {resolved}");
            assert_eq!(resolved["name"], expected, "{alias}: {resolved}");
            assert_eq!(
                get_type(&program, &format!("{alias}[3]"))["size"],
                width * 3
            );
        }
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn rejected_force_define_data_preserves_instructions_and_data() {
    require_ghidra!();
    let program = create_program(32);
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DWordDataType;
public class PrepareDefineDataMemory extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createInitializedBlock("first", toAddr(0x1000), 8, (byte) 0xc3, monitor, false);
        memory.createInitializedBlock("after_gap", toAddr(0x1010), 8, (byte) 0, monitor, false);
        memory.createInitializedBlock("last", toAddr(0xfffffff0L), 16, (byte) 0, monitor, false);
        disassemble(toAddr(0x1000));
        createData(toAddr(0x1004), DWordDataType.dataType);
        createData(toAddr(0xfffffffcL), DWordDataType.dataType);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    for (address, ty) in [
        ("0x1000", "void"),
        ("0x1004", "void"),
        ("0x1000", "Holder"),
        ("0x1004", "byte[20]"),
        ("0x1004", "byte[2147483647]"),
        ("0xfffffffc", "byte[8]"),
    ] {
        let failed = program_command(
            &program,
            &["listing", "define-data", address, "--type", ty, "--force"],
        );
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class CheckDefineDataPreservation extends GhidraScript {
    public void run() throws Exception {
        if (getInstructionAt(toAddr(0x1000)) == null)
            throw new IllegalStateException("Rejected apply removed instruction");
        for (long address : new long[] { 0x1004, 0xfffffffcL }) {
            var data = getDataAt(toAddr(address));
            if (data == null || !data.isDefined() || data.getLength() != 4
                    || !data.getDataType().getName().equals("dword"))
                throw new IllegalStateException("Rejected apply removed data");
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
    }
    // Valid forced replacement still succeeds after all rejected requests.
    program_command(
        &program,
        &[
            "listing",
            "define-data",
            "0x1004",
            "--type",
            "byte[4]",
            "--force",
        ],
    )
    .assert_success();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_creation_reports_the_registered_conflict_name_and_path() {
    require_ghidra!();
    let program = create_program(64);
    for (name, args, kind) in [
        (
            "EnumCollision",
            vec!["create", "enum", "EnumCollision", "--member", "ONE", "1"],
            "enum",
        ),
        (
            "TypedefCollision",
            vec!["create", "typedef", "TypedefCollision", "--type", "byte"],
            "typedef",
        ),
        (
            "UnionCollision",
            vec!["create", "union", "UnionCollision"],
            "union",
        ),
        (
            "StructCollision",
            vec!["create", "struct", "StructCollision"],
            "struct",
        ),
    ] {
        // Different kinds force Ghidra to retain both definitions under unique names.
        let initial = if kind == "struct" {
            vec!["create", "typedef", name, "--type", "byte"]
        } else {
            vec!["create", "struct", name]
        };
        type_command(&program, &initial).assert_success();
        let result = type_command(&program, &args);
        result.assert_success();
        let created: Value = result.data();
        let created = &created;
        let registered_name = created["name"].as_str().unwrap();
        let path = created["path"].as_str().unwrap();
        assert_ne!(registered_name, name, "{created}");
        let resolved = get_type(&program, path);
        assert_eq!(resolved["name"], registered_name);
        assert_eq!(resolved["path"], path);
        assert_eq!(resolved["kind"], kind);
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn append_field_size_is_honored_or_rejected_before_changing_the_structure() {
    require_ghidra!();
    let program = create_program(64);
    type_command(
        &program,
        &[
            "field", "append", "Holder", "--name", "anchor", "--type", "byte",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.docking.settings.FormatSettingsDefinition;
public class SetAnchorFormat extends GhidraScript {
    public void run() throws Exception {
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        FormatSettingsDefinition.DEF.setChoice(holder.getComponent(0).getDefaultSettings(),
            FormatSettingsDefinition.DECIMAL);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    type_command(
        &program,
        &[
            "field", "append", "Holder", "--name", "sized", "--type", "string", "--size", "8",
        ],
    )
    .assert_success();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckAnchorFormat extends GhidraScript {
    public void run() throws Exception {
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        if (FormatSettingsDefinition.DEF.getChoice(holder.getComponent(0).getDefaultSettings())
                != FormatSettingsDefinition.DECIMAL)
            throw new IllegalStateException("Append discarded an existing field's format setting");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = get_type(&program, "Holder");
    assert_eq!(before["components"][1]["size"], 8);
    assert_eq!(before["size"], 9);
    for (size, message) in [
        ("0", "Field size must be positive"),
        ("8", "Ghidra cannot honor --size"),
    ] {
        type_command(
            &program,
            &[
                "field", "append", "Holder", "--name", "invalid", "--type", "byte", "--size", size,
            ],
        )
        .assert_failure()
        .assert_stderr_contains(message);
        assert_eq!(get_type(&program, "Holder"), before);
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
