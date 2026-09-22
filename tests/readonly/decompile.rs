//! Decompiler diagnostics and the attributes of the selected function entry.

use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

fn fixture() -> &'static str {
    static PROGRAM: OnceLock<String> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let name = format!("decompile-details-{}", uuid::Uuid::new_v4());
        harness().client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateDecompileDetails extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("decompile details fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var code = program.getMemory().createInitializedBlock("code", space.getAddress(0x1000), 0x100, (byte)0xc3, monitor, false);
                code.setRead(true); code.setWrite(false); code.setExecute(true);
                var data = program.getMemory().createInitializedBlock("data", space.getAddress(0x2000), 0x100, (byte)0xc3, monitor, false);
                data.setRead(true); data.setWrite(true); data.setExecute(false);
                program.getMemory().createInitializedBlock("bad", space.getAddress(0x2100), 1, (byte)0x0f, monitor, false);
                var fm = program.getFunctionManager();
                var source = SourceType.USER_DEFINED;
                int[] entries = {0x1000, 0x1040, 0x1080, 0x2000, 0x2100, 0x9000};
                String[] names = {"clean", "warned", "thunk", "nonexec", "bad", "unmapped"};
                for (int i = 0; i < entries.length; i++) {
                    var address = space.getAddress(entries[i]);
                    var function = fm.createFunction(names[i], address, new AddressSet(address, address), source);
                    if (entries[i] < 0x2100) {
                        if (!new DisassembleCommand(address, new AddressSet(address, address), false).applyTo(program, monitor))
                            throw new IllegalStateException("Failed to disassemble fixture");
                        function.setCallingConvention("__cdecl");
                        function.setReturnType(VoidDataType.dataType, source);
                    }
                }
                // Entry attributes must not describe all disjoint body ranges.
                var clean = fm.getFunctionAt(space.getAddress(0x1000));
                var body = new AddressSet(clean.getBody());
                body.add(space.getAddress(0x2020));
                clean.setBody(body);
                var warned = fm.getFunctionAt(space.getAddress(0x1040));
                warned.setCallingConvention("unknown");
                warned.setReturnType(IntegerDataType.dataType, source);
                warned.setComment("WARNING: user-supplied note\ncontinued line 日本語");
                var external = program.getExternalManager().addExtFunction("library", "outside", null, source).getFunction();
                fm.getFunctionAt(space.getAddress(0x1080)).setThunkedFunction(external);
                // A WARNING in a string literal is not a comment diagnostic.
                var stringAddr = space.getAddress(0x3000);
                var text = "WARNING: string literal".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                program.getMemory().createInitializedBlock("strings", stringAddr, text.length + 1, (byte)0, monitor, false);
                program.getMemory().setBytes(stringAddr, text);
                program.getListing().createData(stringAddr, TerminatedStringDataType.dataType, text.length + 1);
                var literalAddr = space.getAddress(0x1060);
                byte[] bytes = {(byte)0xb8, 0, 0x30, 0, 0, (byte)0xc3};
                program.getMemory().setBytes(literalAddr, bytes);
                new DisassembleCommand(literalAddr, new AddressSet(literalAddr, literalAddr.add(5)), false).applyTo(program, monitor);
                var literal = fm.createFunction("literal", literalAddr, new AddressSet(literalAddr, literalAddr.add(5)), source);
                literal.setCallingConvention("__cdecl");
                literal.setReturnType(new PointerDataType(CharDataType.dataType, program.getDataTypeManager()), source);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
        name
    })
}

fn command(args: &[&str]) -> crate::common::helpers::GhidraResult {
    ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), fixture())
        .arg("--json")
        .run()
}

fn row(args: &[&str]) -> Value {
    let result = command(args);
    result.assert_success();
    result.data::<Value>()
}

#[test]
#[serial]
fn function_entry_attributes_match_memory_map_and_preserve_list_membership() {
    require_ghidra!();
    let listed = command(&["function", "list", "--limit", "0"]);
    listed.assert_success();
    let listed: Value = listed.data();
    // Ghidra's existing memory-function iterator excludes external and unmapped entries.
    assert_eq!(listed.as_array().unwrap().len(), 6, "{listed}");
    assert!(!listed
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["name"] == "outside"));
    let memory = command(&["memory", "map", "--limit", "0"]);
    memory.assert_success();
    let memory: Value = memory.data();
    for (name, block) in [
        ("clean", "code"),
        ("warned", "code"),
        ("nonexec", "data"),
        ("thunk", "code"),
    ] {
        let expected = memory
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == block)
            .unwrap();
        let expected = json!({"name": block, "permissions": expected["permissions"]});
        let mut got = row(&["function", "get", name]);
        assert_eq!(got["is_external"], false);
        assert_eq!(got["entry_memory"], expected);
        let from_list = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap();
        assert!(got.as_object_mut().unwrap().remove("body_ranges").is_some());
        assert_eq!(from_list, &got);
    }
    assert_eq!(
        row(&["function", "get", "clean"])["entry_memory"]["permissions"],
        "rx"
    );
    assert_eq!(
        row(&["function", "get", "nonexec"])["entry_memory"]["permissions"],
        "rw"
    );
    for (name, external) in [("outside", true), ("unmapped", false)] {
        let got = row(&["function", "get", name]);
        assert_eq!(got["is_external"], external, "{got}");
        assert!(got.get("entry_memory").unwrap().is_null(), "{got}");
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn completed_decompiles_retain_comment_warnings_and_failures_stay_errors() {
    require_ghidra!();
    for name in ["clean", "nonexec", "literal"] {
        let got = row(&["decompile", name]);
        assert_eq!(got["warnings"], json!([]), "{got}");
        assert_eq!(got["is_external"], false);
        assert_eq!(
            got["entry_memory"],
            row(&["function", "get", name])["entry_memory"]
        );
        if name == "literal" {
            assert!(
                got["code"]
                    .as_str()
                    .unwrap()
                    .contains("\"WARNING: string literal\""),
                "{got}"
            );
        }
    }
    let warned = row(&["decompile", "warned"]);
    let warnings = warned["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2, "{warned}");
    assert!(
        warnings.iter().any(|w| w["message"]
            .as_str()
            .unwrap()
            .contains("Unknown calling convention")),
        "{warned}"
    );
    assert!(
        warnings.iter().any(|w| w["message"]
            .as_str()
            .unwrap()
            .contains("continued line 日本語")),
        "{warned}"
    );
    for warning in warnings {
        assert_eq!(warning["source"], "c_comment");
        assert_eq!(warning["address"], warned["address"]);
    }
    let c = command(&["decompile", "warned", "--format", "c"]);
    c.assert_success();
    assert_eq!(c.stdout, warned["code"].as_str().unwrap());
    assert!(c.stderr.is_empty(), "{}", c.stderr);
    for format in ["compact", "full"] {
        let output = command(&["decompile", "warned", "--format", format]);
        output
            .assert_success()
            .assert_stdout_contains("Warnings:")
            .assert_stdout_contains("Entry memory: code (rx)");
    }
    let bad = command(&["decompile", "bad"]);
    bad.assert_success();
    let got: Value = bad.data();
    assert!(
        got["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["message"].as_str().unwrap().contains("bad instruction")),
        "{got}"
    );
    assert!(bad.stderr.is_empty(), "{}", bad.stderr);
    let failure = command(&["decompile", "outside"]);
    failure.assert_failure();
    let failure: Value = serde_json::from_str(&failure.stderr).unwrap();
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["detail"]["is_external"], true, "{failure}");
    assert!(failure["detail"].get("entry_memory").unwrap().is_null());
    // A failed decompile must not poison the next request or retain old warnings.
    assert_eq!(row(&["decompile", "clean"])["warnings"], json!([]));
    // Exercise the independent API-message channel alongside real comment
    // markup. Native warning messages are not reliably triggerable on demand.
    harness().client().unwrap().script_run_source(r#"
import com.google.gson.JsonArray;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
public class CheckApiDecompileWarning extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getName().equals("ghidracli.ScriptCommands"))
                .findFirst().orElseThrow());
        var collect = caller.getClassLoader().loadClass("ghidracli.DecompileWarnings")
            .getDeclaredMethod("collect", DecompileResults.class);
        collect.setAccessible(true);
        var engine = new DecompInterface();
        try {
            if (!engine.openProgram(currentProgram)) throw new IllegalStateException(engine.getLastMessage());
            var result = engine.decompileFunction(getFunctionAt(toAddr(0x1040)), 30, monitor);
            if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
            var message = DecompileResults.class.getDeclaredField("errMsg");
            message.setAccessible(true);
            message.set(result, "  API-only diagnostic\nsecond line  ");
            var warnings = (JsonArray) collect.invoke(null, result);
            if (warnings.size() != 3) throw new IllegalStateException(warnings.toString());
            var diagnostic = warnings.get(0).getAsJsonObject();
            if (!"decompiler".equals(diagnostic.get("source").getAsString())
                    || !"API-only diagnostic\nsecond line".equals(diagnostic.get("message").getAsString())
                    || !diagnostic.get("address").isJsonNull())
                throw new IllegalStateException(diagnostic.toString());
        } finally { engine.closeProgram(); engine.dispose(); }
    }
}
"#, &[], &[], false).unwrap();
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
