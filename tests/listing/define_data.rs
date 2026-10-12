use super::{ghidra, harness, test_project, DaemonTestHarness, TEST_PROGRAM};
use crate::common::get_function_address;
use serial_test::serial;

#[test]
#[serial]
fn test_define_data() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("listing")
        .arg("define-data")
        .arg(&addr)
        .arg("--type")
        .arg("int")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Applying a type at a code address may conflict with existing instructions
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Conflicting instruction")
            || stderr.contains("conflict"),
        "Expected success or instruction conflict, got: {}",
        stderr
    );
}

/// Add bytes to a hex address while preserving its width, for the instruction
/// window restored by this suite's type-application test.
fn hex_addr_plus(addr: &str, delta: u64) -> String {
    let hex = addr.strip_prefix("0x").expect("prefixed hex address");
    let val = u64::from_str_radix(hex, 16).expect("hex address");
    format!("0x{:0width$x}", val + delta, width = hex.len())
}

/// Force-clear+redisassemble a small window at `addr` back to instructions,
/// via the same `listing undefine --disassemble-at` path a caller would use to recover from
/// this (ghidra-bug.md's own suggested workaround) -- used both to armor this
/// test against `main` having been left mid-disassembled by another test
/// sharing the fixture, and to restore it afterward.
fn restore_disassembly(harness: &DaemonTestHarness, addr: &str) {
    ghidra(harness)
        .args(["listing", "undefine", addr, "--end"])
        .arg(hex_addr_plus(addr, 15))
        .arg("--disassemble-at")
        .arg(addr)
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();
}

#[test]
#[serial]
// This suite owns its project, so clearing main cannot affect another suite.
fn test_define_data_force_on_function_entry_warns() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    // Earlier type tests in this suite can clear instructions. Start from a
    // defined function entry so this test exercises the intended conflict.
    restore_disassembly(harness, &addr);

    // --force on a function's own entry point clears its code (not a
    // conflicting data unit) -- the response must flag that distinctly so a
    // caller doesn't mistake it for a normal conflict-clear (ghidra-bug.md).
    let result = ghidra(harness)
        .arg("listing")
        .arg("define-data")
        .arg(&addr)
        .arg("--type")
        .arg("int")
        .arg("--force")
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    // Restore `main`'s disassembly for the many other tests sharing this
    // fixture regardless of what the assertions below find.
    restore_disassembly(harness, &addr);

    result.assert_success();
    // The CLI wraps single-address results in a JSON array.
    let json: serde_json::Value = result.data();
    let entry = &json;
    assert_eq!(entry["cleared_conflicting"], true);
    assert_eq!(
        entry["is_function_entry"], true,
        "expected is_function_entry:true when --force clears a function's own entry, got: {}",
        entry
    );
    assert!(
        entry["warning"]
            .as_str()
            .is_some_and(|w| w.contains("main")),
        "expected a warning naming the cleared function, got: {}",
        entry
    );
}

#[test]
#[serial]
fn define_data_reports_the_overlapping_unit_when_the_start_is_undefined() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-data-conflicts-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateDataConflictFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("data conflicts");
            try {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("storage", start, 32, (byte) 0, monitor, false);
                program.getListing().createData(start.add(2), WordDataType.dataType);
                program.getMemory().setBytes(start.add(0x12), new byte[]{0x66, (byte) 0x90});
                if (!new DisassembleCommand(start.add(0x12), null, false).applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble fixture");
                }
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}

"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let before = client.send_command("data_list", None).unwrap();
        for (target, kind, start, end, type_name) in [
            ("0x1000", "data", "0x00001002", "0x00001003", "uint32_t"),
            ("0x1003", "data", "0x00001002", "0x00001003", "uint16_t"),
            (
                "0x1010",
                "instruction",
                "0x00001012",
                "0x00001013",
                "uint32_t",
            ),
        ] {
            let result = ghidra(harness)
                .args([
                    "--json",
                    "listing",
                    "define-data",
                    target,
                    "--type",
                    type_name,
                ])
                .with_project(test_project(), &name)
                .run();
            result.assert_failure();
            let error: serde_json::Value = serde_json::from_str(&result.stderr).unwrap();
            let detail = &error["detail"];
            assert_eq!(detail["conflicting_start"], start, "{error}");
            assert_eq!(detail["conflicting_end"], end, "{error}");
            assert_eq!(detail["conflicting_length"], 2, "{error}");
            assert_eq!(detail["conflicting_kind"], kind, "{error}");
            assert_eq!(detail["rolled_back"], true);
            if kind == "data" {
                assert_eq!(detail["conflicting_defined"], true);
                assert_eq!(detail["conflicting_type"], "word");
            }
        }
        assert_eq!(client.send_command("data_list", None).unwrap(), before);
        assert_eq!(
            client.disasm("0x1012", Some(1)).unwrap()["instructions"][0]["bytes"],
            "6690"
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

const DEFINE_DATA_FAILURE_PROBE: &str = r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class DefineDataFailureProbe extends GhidraScript {
    private Program real;
    private Program selected;
    private Address start;
    private String fault;
    private boolean nativeClear;
    private boolean observed;
    private int createCalls;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true) {
        @Override public synchronized boolean isCancelled() {
            if (nativeClear && fault.equals("cancel")) {
                check(real.getReferenceManager().getReferencesFrom(start).length == 0,
                    "Cancellation preceded native reference removal");
                observed = true;
                cancel();
            }
            return super.isCancelled();
        }
    };
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    private void checkPreserved(Program program) {
        Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        var data = program.getListing().getDefinedDataAt(address);
        check(data != null && data.getLength() == 8 && data.getDataType().getName().equals("qword"),
            "Failed definition did not restore the original data");
        check(program.getReferenceManager().getReference(address, address.add(16), 0) != null,
            "Failed definition did not restore the original reference");
        check(program.getEquateTable().getEquate("kept_equate") != null,
            "Failed definition did not restore the original equate");
    }
    public void run() throws Exception {
        String name = getScriptArgs()[0];
        fault = getScriptArgs()[1];
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        real = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
        Object session = null;
        DomainFile file = null;
        try {
            start = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            int tx = real.startTransaction("definition rollback fixture");
            try {
                real.getMemory().createInitializedBlock("storage", start, 32, (byte) 0, monitor, false);
                real.getListing().createData(start, QWordDataType.dataType);
                real.getReferenceManager().addMemoryReference(start, start.add(16),
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                real.getEquateTable().createEquate("kept_equate", 0).addReference(start, 0);
            } finally { real.endTransaction(tx, true); }
            file = state.getProject().getProjectData().getRootFolder().createFile(name, real, monitor);

            Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(type -> type.getSimpleName().equals("ScriptCommands")
                        && type.getPackageName().equals("ghidracli.script")).findFirst().orElseThrow());
            var loader = caller.getClassLoader();
            String prefix = caller.getPackageName()
                .substring(0, caller.getPackageName().lastIndexOf('.') + 1);
            Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
                new Class<?>[]{Listing.class}, (proxy, method, args) -> {
                    if (method.getName().equals("createData")) {
                        createCalls++;
                        if (fault.equals("null")) {
                            check(real.getListing().getDefinedDataAt(start) == null
                                && real.getReferenceManager().getReferencesFrom(start).length == 0,
                                "Failure preceded native forced clearing");
                            observed = true;
                            // CodeManager.createCodeUnit can return null after a database error.
                            return null;
                        }
                    }
                    nativeClear = method.getName().equals("clearCodeUnits");
                    try { return method.invoke(real.getListing(), args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                    finally { nativeClear = false; }
                });
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getListing")) return listing;
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                });
            var accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[]{accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected;
                        case "setProgram": selected = (Program) args[0]; return null;
                        case "state": return state;
                        case "monitor": return requestMonitor;
                        case "logError": printerr((String) args[0]); return null;
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            var sessionClass = loader.loadClass(prefix + "session.ProgramSession");
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            var dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
            var constructor = dispatcherClass.getDeclaredConstructor(sessionClass);
            constructor.setAccessible(true);
            Object dispatcher = constructor.newInstance(session);
            var args = new JsonObject();
            args.addProperty("address", "0x1000");
            args.addProperty("type_name", "uint32_t");
            args.addProperty("force", true);
            var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
            execute.setAccessible(true);
            var response = (JsonObject) execute.invoke(dispatcher, "define_data", args);
            check(observed, "Test did not reach native " + fault + " failure: " + response);
            check(response.get("status").getAsString().equals("error"), response.toString());
            var detail = response.getAsJsonObject("detail");
            check(detail.get("rolled_back").getAsBoolean(), response.toString());
            if (fault.equals("cancel")) {
                check(detail.get("cancelled").getAsBoolean(), response.toString());
                check(createCalls == 0, "Data creation continued after cancellation");
            } else {
                check(response.get("message").getAsString().contains("Ghidra did not create data"), response.toString());
                check(createCalls == 1, "Test did not reach failed data creation");
            }
            requestMonitor.clearCancelled();
            checkPreserved(real);
            Object reader = new Object();
            Program saved = (Program) file.getReadOnlyDomainObject(reader,
                DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
            try { checkPreserved(saved); }
            finally { saved.release(reader); }
        } finally {
            requestMonitor.clearCancelled();
            try {
                if (session != null) session.getClass().getMethod("closeProgram").invoke(session);
            } finally {
                real.release(this);
                if (file != null) file.delete();
            }
        }
    }
}
"#;

fn check_define_data_native_failure(mode: &str) {
    require_ghidra!();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            DEFINE_DATA_FAILURE_PROBE,
            &[
                format!("define-data-failure-{}", uuid::Uuid::new_v4()),
                mode.to_owned(),
            ],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn define_data_rolls_back_native_null_after_forced_clearing() {
    check_define_data_native_failure("null");
}

#[test]
#[serial]
fn define_data_cancels_during_native_forced_clearing_and_restores_metadata() {
    check_define_data_native_failure("cancel");
}
