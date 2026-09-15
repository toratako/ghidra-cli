//! Array expressions, target data organization, and unambiguous type lookup.

use super::common::helpers::GhidraResult;
use super::{ghidra, harness, test_project, unique_suffix, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn type_command(program: &str, args: &[&str]) -> GhidraResult {
    ghidra(harness())
        .arg("type")
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn get_type(program: &str, name: &str) -> Value {
    let result = type_command(program, &["get", name]);
    result.assert_success();
    let result: Value = result.json();
    result[0].clone()
}

fn create_program(bits: u32) -> String {
    let program = format!("type-resolution-{bits}-{}", unique_suffix());
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
            &[program.clone(), format!("x86:LE:{bits}:default")],
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
                &["add-field", "Holder", "--name", name, "--type", expression],
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
        &["add-field", "Holder", "--name", "anchor", "--type", "byte"],
    )
    .assert_success();
    let before = get_type(&program, "Holder");
    let listed = type_command(&program, &["list"]);
    listed.assert_success();
    let types_before: Value = listed.json();

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
                "add-field",
                "Holder",
                "--name",
                "invalid",
                "--type",
                expression,
                "--offset",
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
    let types_after: Value = listed.json();
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
        vec!["get", "Shared"],
        vec!["get", "Shared *[2]"],
        vec!["add-field", "Holder", "--name", "bad", "--type", "Shared"],
        vec!["typedef", "AmbiguousAlias", "Shared"],
        vec!["rename", "Shared", "Renamed"],
        vec!["delete", "Shared"],
        vec!["del-field", "Shared", "--name", "missing"],
        vec!["apply", "1000", "Shared", "--force"],
    ] {
        let failed = type_command(&program, &args);
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
            "add-field",
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
    assert_eq!(get_type(&program, "u8")["path"], "/Shadows/byte");
    assert_eq!(get_type(&program, "u32")["size"], 4);
    assert_eq!(get_type(&program, "/byte")["size"], 1);
    assert_eq!(get_type(&program, "/byte[2]")["size"], 2);
    client.open_program(TEST_PROGRAM).unwrap();
}
