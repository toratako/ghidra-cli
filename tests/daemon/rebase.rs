use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = r#"
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateRebaseFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("rebase fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                var listing = program.getListing();
                // The first block is deliberately below the image base.
                var base = space instanceof ghidra.program.model.address.SegmentedAddressSpace segmented
                    ? segmented.getAddress(0x100, 0) : space.getAddress(0x1000);
                program.setImageBase(base, true);
                memory.createInitializedBlock("low", space.getAddress(0x800),
                    0x10, (byte) 0x17, monitor, false);
                var code = memory.createInitializedBlock("code", space.getAddress(0x2000),
                    0x100, (byte) 0, monitor, false);
                code.setExecute(true);
                memory.createInitializedBlock("data", space.getAddress(0x3000),
                    0x100, (byte) 0x55, monitor, false);
                var mmio = memory.createUninitializedBlock("mmio", space.getAddress(0x5000),
                    0x10, false);
                mmio.setVolatile(true);
                var overlay = memory.createInitializedBlock("rebase_overlay", space.getAddress(0x2000),
                    0x20, (byte) 0x7a, monitor, true);
                listing.setComment(overlay.getStart(), CodeUnit.EOL_COMMENT, "overlay stays");
                if (getScriptArgs()[1].startsWith("avr8")) {
                    memory.createInitializedBlock("other", program.getAddressFactory()
                        .getAddressSpace("mem").getAddress(0x2000), 0x20, (byte) 0x3b, monitor, false);
                }
                if (space instanceof ghidra.program.model.address.SegmentedAddressSpace) {
                    memory.createUninitializedBlock("upper", space.getAddress(0x100000), 0x10, false);
                }
                if (getScriptArgs()[1].equals("x86:LE:64:default")) {
                    memory.setBytes(code.getStart(), new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3});
                    if (!new DisassembleCommand(code.getStart(),
                            new AddressSet(code.getStart(), code.getStart().add(5)), false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture");
                    }
                    program.getFunctionManager().createFunction("rebase_function", code.getStart(),
                        new AddressSet(code.getStart(), code.getStart().add(5)), SourceType.USER_DEFINED);
                    listing.setComment(code.getStart(), CodeUnit.EOL_COMMENT, "manual rebase comment");
                    var pointer = space.getAddress(0x3000);
                    memory.setBytes(pointer, new byte[]{0, 0x20, 0, 0, 0, 0, 0, 0});
                    listing.createData(pointer, new PointerDataType());
                    program.getReferenceManager().addMemoryReference(pointer.add(0x10), code.getStart(),
                        RefType.DATA, SourceType.USER_DEFINED, 0);
                    program.getRelocationTable().add(pointer, Status.APPLIED, 17,
                        new long[]{0x2000}, new byte[]{1, 2, 3, 4}, "fixed_pointer");
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
"#;

const CHECK_FIXTURE: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.address.Address;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.Arrays;

public class CheckRebaseFixture extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    public void run() throws Exception {
        long base = Long.parseUnsignedLong(getScriptArgs()[0], 16);
        long delta = base - 0x1000;
        var p = currentProgram;
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var memory = p.getMemory();
        var listing = p.getListing();
        require(p.getImageBase().getOffset() == base, "Image base differs");
        require(!p.isChanged(), "Successful rebase was not saved");
        require(!GhidraProgramUtilities.isAnalyzed(p), "Rebase ran analysis");
        for (var entry : new Object[][] {{"low", 0x800L}, {"code", 0x2000L},
                {"data", 0x3000L}, {"mmio", 0x5000L}}) {
            var block = memory.getBlock((String) entry[0]);
            require(block.getStart().getOffset() == (long) entry[1] + delta,
                "Block did not preserve its image-base offset: " + entry[0]);
        }
        require(memory.getBlock("mmio").isVolatile(), "MMIO flags changed");
        var overlay = memory.getBlock("rebase_overlay").getStart();
        require(overlay.getOffset() == 0x2000 && memory.getByte(overlay) == (byte) 0x7a,
            "Overlay bytes or address changed");
        require("overlay stays".equals(listing.getComment(CodeUnit.EOL_COMMENT, overlay)),
            "Overlay metadata changed");
        var other = memory.getBlock("other");
        if (other != null) {
            require(other.getStart().getOffset() == 0x2000 && memory.getByte(other.getStart()) == (byte) 0x3b,
                "Other address space moved");
        }
        var upper = memory.getBlock("upper");
        if (upper != null) require(upper.getStart().getOffset() == 0x100000 + delta,
            "Upper segmented memory did not move");
        if (p.getLanguageID().toString().equals("x86:LE:64:default")) {
            var code = space.getAddress(0x2000 + delta);
            var data = space.getAddress(0x3000 + delta);
            byte[] bytes = new byte[6];
            memory.getBytes(code, bytes);
            require(Arrays.equals(bytes, new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3}),
                "Instruction bytes changed");
            require(listing.getInstructionAt(code) != null && listing.getInstructionAt(code.add(0x20)) == null,
                "Instruction definitions changed");
            var function = p.getFunctionManager().getFunctionAt(code);
            require(function != null && function.getName().equals("rebase_function")
                && function.getBody().contains(code.add(5)), "Function metadata did not move");
            require("manual rebase comment".equals(listing.getComment(CodeUnit.EOL_COMMENT, code)),
                "Comment did not move");
            bytes = new byte[8];
            memory.getBytes(data, bytes);
            require(Arrays.equals(bytes, new byte[]{0, 0x20, 0, 0, 0, 0, 0, 0}), "Pointer bytes were fixed up");
            var pointer = listing.getDataAt(data);
            require(pointer != null && pointer.getValue() instanceof Address
                && ((Address) pointer.getValue()).getOffset() == 0x2000, "Applied pointer changed");
            var refs = p.getReferenceManager().getReferencesFrom(data.add(0x10));
            require(refs.length == 1 && refs[0].getToAddress().equals(code)
                && refs[0].getSource() == ghidra.program.model.symbol.SourceType.USER_DEFINED,
                "User xref did not move");
            var relocations = p.getRelocationTable().getRelocations();
            require(relocations.hasNext(), "Relocation disappeared");
            var relocation = relocations.next();
            require(relocation.getAddress().equals(data)
                && relocation.getStatus() == ghidra.program.model.reloc.Relocation.Status.APPLIED
                && Arrays.equals(relocation.getBytes(), new byte[]{1, 2, 3, 4}),
                "Relocation evidence changed");
        }
    }
}
"#;

fn create_fixture(client: &BridgeClient, language: &str) -> String {
    let name = format!("rebase-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, &[name.clone(), language.into()], &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    name
}

fn check_fixture(client: &BridgeClient, byte_base: &str) {
    client
        .script_run_source(CHECK_FIXTURE, &[byte_base.into()], &[], false)
        .unwrap();
}

fn rebase(client: &BridgeClient, base: &str) -> Value {
    client
        .send_command("program_rebase", Some(json!({"base":base})))
        .unwrap()
}

fn reject_rebase(client: &BridgeClient, base: &str, expected: &str) {
    let error = client
        .send_command("program_rebase", Some(json!({"base":base})))
        .unwrap_err();
    assert!(error.to_string().contains(expected), "{error}");
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["rolled_back"], true);
    assert!(detail.get("partial_changes_saved").is_none());
}

#[test]
#[serial]
fn rebase_preserves_native_metadata_and_pointer_bytes_after_reopen() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client, "x86:LE:64:default");
    check_fixture(&client, "1000");
    let result = rebase(&client, "0x5000");
    assert_eq!(result["old_base"], "0x00001000");
    assert_eq!(result["new_base"], "0x00005000");
    assert_eq!(result["delta_bytes"], "16384");
    let moved = result["moved_blocks"].as_array().unwrap();
    assert_eq!(moved.len(), 4);
    assert!(
        moved.contains(&json!({"name":"code", "old_start":"0x00002000",
        "old_end":"0x000020ff", "new_start":"0x00006000", "new_end":"0x000060ff"}))
    );
    assert!(
        moved.contains(&json!({"name":"mmio", "old_start":"0x00005000",
        "old_end":"0x0000500f", "new_start":"0x00009000", "new_end":"0x0000900f"}))
    );
    assert_eq!(
        result["unchanged_blocks"],
        json!([{"name":"rebase_overlay",
        "start":"rebase_overlay:0x00002000", "end":"rebase_overlay:0x0000201f", "reason":"overlay"}])
    );
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "5000");

    let unchanged = rebase(&client, "0x5000");
    assert_eq!(unchanged["delta_bytes"], "0");
    assert_eq!(unchanged["moved_blocks"], json!([]));
    assert_eq!(unchanged["unchanged_blocks"].as_array().unwrap().len(), 5);
    assert_eq!(
        unchanged["unchanged_blocks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|block| block["reason"] == "same_base")
            .count(),
        4
    );
    for (base, message) in [
        ("rebase_function", "explicit address"),
        ("rebase_overlay:0x2000", "default address space"),
        ("0x10000000000000000", "Invalid address"),
        // Both cases can otherwise wrap a block start while leaving its end in range.
        ("0x0", "wrap or exceed"),
        ("0xffffffffffffd000", "wrap or exceed"),
    ] {
        reject_rebase(&client, base, message);
        check_fixture(&client, "5000");
    }

    // These deltas exceed the signed-long range in both directions.
    let high = rebase(&client, "0xf000000000001000");
    assert_eq!(
        high["delta_bytes"],
        (0xf000000000001000_i128 - 0x5000).to_string()
    );
    check_fixture(&client, "f000000000001000");
    let low = rebase(&client, "0x1000");
    assert_eq!(
        low["delta_bytes"],
        (0x1000_i128 - 0xf000000000001000_i128).to_string()
    );
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "1000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
}

#[test]
#[serial]
fn rebase_uses_byte_deltas_for_word_and_segmented_spaces() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let word = create_fixture(&client, "avr8:LE:16:default");
    let result = rebase(&client, "0x1800.1");
    assert_eq!(result["delta_bytes"], "8193");
    assert!(result["new_base"].as_str().unwrap().ends_with("0x1800.1"));
    let other = result["unchanged_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|block| block["name"] == "other")
        .unwrap();
    assert_eq!(other["reason"], "other_address_space");
    assert!(other["start"].as_str().unwrap().ends_with("0x2000"));
    check_fixture(&client, "3001");
    reject_rebase(&client, "0xffff", "wrap or exceed");
    client.program_close().unwrap();
    client.open_program(&word).unwrap();
    check_fixture(&client, "3001");

    let segmented = create_fixture(&client, "x86:LE:16:Real Mode");
    let result = rebase(&client, "ram:0x0200:0x0000");
    assert_eq!(result["old_base"], "ram:0x0100:0x0000");
    assert_eq!(result["new_base"], "ram:0x0200:0x0000");
    assert_eq!(result["delta_bytes"], "4096");
    check_fixture(&client, "2000");
    reject_rebase(&client, "ram:0x0200:0x0001", "zero segment offset");
    reject_rebase(&client, "ram:0xffff:0x0000", "wrap or exceed");
    client.program_close().unwrap();
    client.open_program(&segmented).unwrap();
    check_fixture(&client, "2000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&word).unwrap();
    client.program_delete(&segmented).unwrap();
}

#[test]
#[serial]
fn rebase_rolls_back_native_mutation_on_error_and_cancellation() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = create_fixture(&client, "x86:LE:64:default");
    let folder = format!("rebase-rollback-{}", uuid::Uuid::new_v4());
    // Invoke the real dispatcher with a Program proxy that fails only after
    // native setImageBase has actually changed the separate test database.
    client.script_run_source(r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class RebaseRollbackProbe extends GhidraScript {
    private String fault;
    private Program selected;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        Program real = (Program) file.getDomainObject(owner, true, false, monitor);
        Object session = null;
        try {
            Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(type -> type.getSimpleName().equals("ScriptCommands")
                        && type.getPackageName().equals("ghidracli")).findFirst().orElseThrow());
            var loader = caller.getClassLoader();
            String prefix = caller.getPackageName() + ".";
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                    if (method.getName().equals("setImageBase") && fault != null) {
                        require(real.getImageBase().getOffset() == 0x5000, "Failure preceded native mutation");
                        if (fault.equals("cancel")) requestMonitor.cancel();
                        else throw new IllegalStateException("injected error after native rebase");
                    }
                    return result;
                });
            var accessClass = loader.loadClass(prefix + "ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[]{accessClass}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "program": return selected;
                    case "setProgram": selected = (Program) args[0]; return null;
                    case "state": return state;
                    case "monitor": return requestMonitor;
                    case "logError": printerr((String) args[0]); return null;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
            var sessionClass = loader.loadClass(prefix + "ProgramSession");
            var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
            sessionConstructor.setAccessible(true);
            session = sessionConstructor.newInstance(access);
            var dispatcherClass = loader.loadClass(prefix + "CommandDispatcher");
            var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
            dispatcherConstructor.setAccessible(true);
            Object dispatcher = dispatcherConstructor.newInstance(session);
            var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
            execute.setAccessible(true);
            var args = new JsonObject();
            args.addProperty("base", "0x5000");
            for (String mode : new String[]{"error", "cancel"}) {
                fault = mode;
                var response = (JsonObject) execute.invoke(dispatcher, "program_rebase", args);
                require(response.get("status").getAsString().equals("error"), response.toString());
                var detail = response.getAsJsonObject("detail");
                require(detail.get("rolled_back").getAsBoolean(), response.toString());
                require(!detail.has("partial_changes_saved"), response.toString());
                if (mode.equals("cancel")) require(detail.get("cancelled").getAsBoolean(), response.toString());
                requestMonitor.clearCancelled();
                require(real.getImageBase().getOffset() == 0x1000, "Failed rebase retained image base");
                require(real.getMemory().getBlock("code").getStart().getOffset() == 0x2000,
                    "Failed rebase retained block movement");
                var code = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
                require(real.getFunctionManager().getFunctionAt(code).getName().equals("rebase_function"),
                    "Rollback lost metadata");
                Object reader = new Object();
                Program saved = (Program) file.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
                try { require(saved.getImageBase().getOffset() == 0x1000, "Failed rebase reached saved database"); }
                finally { saved.release(reader); }
            }
            fault = null;
            var response = (JsonObject) execute.invoke(dispatcher, "program_rebase", args);
            require(response.get("status").getAsString().equals("success"), response.toString());
        } finally {
            fault = null;
            requestMonitor.clearCancelled();
            try {
                if (session != null) {
                    var close = session.getClass().getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { real.release(owner); }
        }
    }
}
"#, std::slice::from_ref(&folder), &[], false).unwrap();
    let copied = format!("/{folder}/{name}");
    client.open_program(&copied).unwrap();
    check_fixture(&client, "5000");
    client.open_program(&name).unwrap();
    check_fixture(&client, "1000");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    client.program_delete(&copied).unwrap();
}

#[test]
#[serial]
fn rebase_rejects_wrapping_unmapped_metadata_while_blocks_fit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    const METADATA: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;

public class UnmappedRebaseMetadata extends GhidraScript {
    public void run() throws Exception {
        var p = currentProgram;
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var high = space.getAddress(0xfffffffffffff000L);
        var code = space.getAddress(0x2000);
        if (p.getMemory().contains(high)) throw new IllegalStateException("Expected unmapped address");
        switch (getScriptArgs()[0]) {
            case "symbol":
                p.getSymbolTable().createLabel(high, "unmapped", SourceType.USER_DEFINED); break;
            case "reference source":
                p.getReferenceManager().addMemoryReference(high, code, RefType.DATA, SourceType.USER_DEFINED, 0); break;
            case "reference destination":
                p.getReferenceManager().addMemoryReference(code.add(0x40), high, RefType.DATA, SourceType.USER_DEFINED, 0); break;
            case "comment":
                p.getListing().setComment(high, CodeUnit.EOL_COMMENT, "unmapped comment"); break;
            case "register context":
                var register = p.getProgramContext().getBaseContextRegister();
                p.getProgramContext().setRegisterValue(high, high, new RegisterValue(register, BigInteger.ONE)); break;
            case "bookmark":
                p.getBookmarkManager().setBookmark(high, "Note", "rebase", "unmapped bookmark"); break;
            case "user property":
                p.getUsrPropertyManager().createIntPropertyMap("rebase_property").add(high, 7); break;
            case "relocation":
                p.getRelocationTable().add(high, Status.SKIPPED, 17, new long[]{0x2000},
                    new byte[]{1, 2, 3, 4}, "unmapped relocation"); break;
            case "equate reference":
                p.getEquateTable().createEquate("unmapped_equate", 7).addReference(high, 0); break;
            case "function body":
                var function = p.getFunctionManager().getFunctionAt(code);
                var body = new AddressSet(function.getBody());
                body.add(high);
                function.setBody(body); break;
            case "pinned":
                p.getSymbolTable().createLabel(high, "pinned", SourceType.USER_DEFINED).setPinned(true); break;
            case "check pinned":
                var symbols = p.getSymbolTable().getSymbols(high);
                if (symbols.length != 1 || !symbols[0].getName().equals("pinned") || !symbols[0].isPinned()) {
                    throw new IllegalStateException("Pinned label moved");
                }
                break;
            default: throw new IllegalArgumentException(getScriptArgs()[0]);
        }
    }
}
"#;
    for kind in [
        "symbol",
        "reference source",
        "reference destination",
        "comment",
        "register context",
        "bookmark",
        "user property",
        "relocation",
        "equate reference",
        "function body",
    ] {
        let name = create_fixture(&client, "x86:LE:64:default");
        client
            .script_run_source(METADATA, &[kind.into()], &[], false)
            .unwrap();
        let before = client.memory_map().unwrap();
        if kind == "symbol" {
            assert_eq!(rebase(&client, "0x1000")["moved_blocks"], json!([]));
        }
        reject_rebase(&client, "0x5000", kind);
        assert_eq!(client.memory_map().unwrap(), before);
        assert_eq!(client.program_info().unwrap()["image_base"], "0x00001000");
        client.program_close().unwrap();
        client.open_program(&name).unwrap();
        reject_rebase(&client, "0x5000", kind);
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&name).unwrap();
    }

    let name = create_fixture(&client, "x86:LE:64:default");
    client
        .script_run_source(METADATA, &["pinned".into()], &[], false)
        .unwrap();
    rebase(&client, "0x5000");
    client.program_close().unwrap();
    client.open_program(&name).unwrap();
    check_fixture(&client, "5000");
    client
        .script_run_source(METADATA, &["check pinned".into()], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
}
