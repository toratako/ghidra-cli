use crate::common;
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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;

public class CreateBlockLifecycleFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("block lifecycle fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var code = space.getAddress(0x2000);
                var outside = space.getAddress(0x4000);
                program.setImageBase(space.getAddress(0x1000), true);
                var memory = program.getMemory();
                byte[] original = new byte[0x110];
                java.util.Arrays.fill(original, (byte) 0x55);
                System.arraycopy(new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3},
                    0, original, 8, 6);
                var file = memory.createFileBytes("block-original", 0x200, original.length,
                    new ByteArrayInputStream(original), monitor);
                var block = memory.createInitializedBlock("movable", code, file, 8, 0x100, false);
                block.setExecute(true);
                memory.setByte(code.add(0x50), (byte) 0x7f);
                memory.createInitializedBlock("outside", outside, 0x100, (byte) 0x90, monitor, false);
                if (!new DisassembleCommand(code, new AddressSet(code, code.add(5)), false)
                        .applyTo(program, monitor)) throw new IllegalStateException("Fixture disassembly failed");
                var insideBody = new AddressSet(code, code.add(5));
                insideBody.add(outside.add(0x20), outside.add(0x25));
                program.getFunctionManager().createFunction("inside_entry", code, insideBody,
                    SourceType.USER_DEFINED);
                var outsideBody = new AddressSet(outside, outside.add(5));
                outsideBody.add(code.add(0x20), code.add(0x25));
                program.getFunctionManager().createFunction("outside_entry", outside, outsideBody,
                    SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(code.add(0x30), "moving_label", SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(outside.add(0x30), "outside_label", SourceType.USER_DEFINED);
                var listing = program.getListing();
                listing.setComment(code, CodeUnit.EOL_COMMENT, "moving comment");
                listing.setComment(outside, CodeUnit.EOL_COMMENT, "outside comment");
                memory.setLong(outside.add(0x40), 0x2000);
                listing.createData(outside.add(0x40), new PointerDataType());
                program.getReferenceManager().addMemoryReference(outside.add(0x50), code,
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                program.getReferenceManager().addMemoryReference(outside.add(0x58), space.getAddress(0x6000),
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                program.getReferenceManager().addMemoryReference(code.add(0x60), outside.add(0x30),
                    RefType.DATA, SourceType.USER_DEFINED, 0);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#;

// Shared by the ordinary read-only check and the test-owned dispatcher failure probe.
const CHECK_STATE: &str = r#"
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    private void checkState(ghidra.program.model.listing.Program p, long start, boolean deleted)
            throws Exception {
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var code = space.getAddress(start);
        var outside = space.getAddress(0x4000);
        var memory = p.getMemory();
        var listing = p.getListing();
        require(p.getImageBase().getOffset() == 0x1000, "Block operation changed image base");
        require(!ghidra.program.util.GhidraProgramUtilities.isAnalyzed(p), "Operation ran analysis");
        require(memory.getBlock("outside").getStart().equals(outside), "Other block moved");
        require(memory.getByte(outside) == (byte) 0x90, "Outside byte changed");
        require("outside comment".equals(listing.getComment(
            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, outside)), "Outside comment changed");
        require(p.getSymbolTable().getGlobalSymbol("outside_label", outside.add(0x30)) != null,
            "Outside label changed");
        var pointer = listing.getDataAt(outside.add(0x40));
        require(pointer != null && pointer.getValue() instanceof ghidra.program.model.address.Address
            && ((ghidra.program.model.address.Address) pointer.getValue()).getOffset() == 0x2000,
            "Embedded pointer bytes were rewritten or its definition was removed");
        require(memory.getAllFileBytes().size() == 1, "Stored FileBytes were removed");
        var file = memory.getAllFileBytes().get(0);
        require(file.getFilename().equals("block-original") && file.getFileOffset() == 0x200
            && file.getSize() == 0x110 && file.getOriginalByte(8) == (byte) 0xb8
            && file.getOriginalByte(0x58) == (byte) 0x55, "Stored original changed");
        var functions = p.getFunctionManager();
        var refs = p.getReferenceManager();
        // Native block movement/removal keeps outside reference sources and their
        // absolute destinations, including destinations no longer backed by memory.
        for (long[] entry : new long[][] {{0x50, 0x2000}, {0x58, 0x6000}}) {
            var incoming = refs.getReference(outside.add(entry[0]), space.getAddress(entry[1]), 0);
            require(incoming != null && incoming.getSource()
                == ghidra.program.model.symbol.SourceType.USER_DEFINED,
                "Outside reference destination changed");
        }
        if (deleted) {
            require(memory.getBlock(code) == null, "Deleted memory remains");
            require(listing.getInstructionAt(code) == null, "Deleted instruction remains");
            require(listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, code) == null,
                "Deleted comment remains");
            require(p.getSymbolTable().getSymbols(code.add(0x30)).length == 0, "Deleted label remains");
            require(functions.getFunctionAt(code) == null && functions.getFunctionAt(outside) == null,
                "Functions intersecting the deleted block remain");
            require(refs.getReferencesFrom(code.add(0x60)).length == 0,
                "Reference originating in deleted memory remains");
            return;
        }
        var block = memory.getBlock(code);
        require(block != null && block.getStart().equals(code) && block.getSize() == 0x100,
            "Block range differs");
        require(block.isExecute() && block.isInitialized(), "Block attributes changed");
        require(block.getSourceInfos().get(0).getFileBytesOffset(code) == 8,
            "Moved block lost direct FileBytes mapping");
        byte[] actual = new byte[6];
        memory.getBytes(code, actual);
        require(java.util.Arrays.equals(actual,
            new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3}), "Instruction bytes changed");
        require(memory.getByte(code.add(0x50)) == (byte) 0x7f, "Patched byte was lost");
        require(listing.getInstructionAt(code) != null && listing.getInstructionAt(code.add(5)) != null
            && listing.getInstructionAt(code.add(0x20)) == null, "Instruction definitions changed");
        require("moving comment".equals(listing.getComment(
            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, code)), "Comment did not move");
        require(p.getSymbolTable().getGlobalSymbol("moving_label", code.add(0x30)) != null,
            "Label did not move");
        var insideFunction = functions.getFunctionAt(code);
        require(insideFunction != null && insideFunction.getName().equals("inside_entry")
            && insideFunction.getBody().contains(code.add(5))
            && insideFunction.getBody().contains(outside.add(0x25))
            && insideFunction.getBody().getNumAddresses() == 12, "Inside-entry function body differs");
        var outsideFunction = functions.getFunctionAt(outside);
        require(outsideFunction != null && outsideFunction.getName().equals("outside_entry")
            && outsideFunction.getBody().contains(code.add(0x25))
            && outsideFunction.getBody().contains(outside.add(5))
            && outsideFunction.getBody().getNumAddresses() == 12, "Outside-entry function body differs");
        require(refs.getReference(code.add(0x60), outside.add(0x30), 0) != null,
            "Reference origin did not follow block movement");
        if (start != 0x2000) {
            var old = space.getAddress(0x2000);
            require(memory.getBlock(old) == null && listing.getInstructionAt(old) == null
                && functions.getFunctionAt(old) == null, "Old address retained moved content");
            require(listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, old) == null
                && p.getSymbolTable().getSymbols(old.add(0x30)).length == 0, "Old address retained metadata");
        }
    }
"#;

fn fixture() -> (BridgeClient, String) {
    let client = super::harness().client().unwrap();
    let name = format!("block-lifecycle-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, std::slice::from_ref(&name), &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    (client, name)
}

fn check_state(client: &BridgeClient, start: &str, deleted: bool) {
    let source = format!(
        r#"
import ghidra.app.script.GhidraScript;
public class CheckBlockLifecycleFixture extends GhidraScript {{
    {CHECK_STATE}
    public void run() throws Exception {{
        require(!currentProgram.isChanged(), "Request did not save");
        checkState(currentProgram, Long.parseUnsignedLong(getScriptArgs()[0], 16),
            Boolean.parseBoolean(getScriptArgs()[1]));
    }}
}}
"#
    );
    client
        .script_run_source(&source, &[start.into(), deleted.to_string()], &[], false)
        .unwrap();
}

fn command(client: &BridgeClient, name: &str, args: Value) -> Value {
    client.send_command(name, Some(args)).unwrap()
}

fn reject(client: &BridgeClient, name: &str, args: Value, expected: &str) {
    let error = client.send_command(name, Some(args)).unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains(expected),
        "{error}"
    );
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["rolled_back"], true, "{error}");
    assert!(detail.get("partial_changes_saved").is_none());
}

fn reopen(client: &BridgeClient, name: &str) {
    client.program_close().unwrap();
    client.open_program(name).unwrap();
}

fn cleanup(client: &BridgeClient, name: &str) {
    client.open_program(common::FIXTURE_PROGRAM).unwrap();
    client.program_delete(name).unwrap();
}

#[test]
#[serial]
fn move_and_delete_preserve_native_analysis_effects_and_file_bytes_after_reopen() {
    require_ghidra!();
    let (client, name) = fixture();
    check_state(&client, "2000", false);
    // Exclude the selected block when checking destination collisions. Its own
    // overlapping range must support movement in both directions.
    for (start, destination, expected) in
        [("0x2000", "0x2080", "2080"), ("0x2080", "0x2000", "2000")]
    {
        let moved = command(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":destination}),
        );
        assert_eq!(moved["changed"], true);
        check_state(&client, expected, false);
    }
    let moved = command(
        &client,
        "memory_block_move",
        json!({"block_start":"ram:0x2000", "start":"ram:0x6000"}),
    );
    assert_eq!(moved["changed"], true);
    assert_eq!(moved["before"]["start"], "0x00002000");
    assert_eq!(moved["after"]["start"], "0x00006000");
    assert_eq!(moved["after"]["end"], "0x000060ff");
    let original = command(
        &client,
        "read_memory",
        json!({"address":"0x6050", "size":1, "source":"original"}),
    );
    assert_eq!(original["hex"], "55");
    assert_eq!(original["mappings"][0]["file_offset"], 0x258);
    assert_eq!(original["mappings"][0]["file_bytes_offset"], 0x58);
    let mappings = command(
        &client,
        "memory_file_mappings",
        json!({"file_offset":"0x258"}),
    );
    assert_eq!(mappings["count"], 1);
    assert_eq!(mappings["mappings"][0]["address"], "0x00006050");
    assert_eq!(mappings["mappings"][0]["block_start"], "0x00006000");
    assert_eq!(mappings["mappings"][0]["source_at"], "0x00006000");
    reopen(&client, &name);
    check_state(&client, "6000", false);
    reject(
        &client,
        "memory_block_delete",
        json!({"block_start":"0x2000"}),
        "block",
    );
    let unchanged = command(
        &client,
        "memory_block_move",
        json!({"block_start":moved["after"]["start"], "start":"0x6000"}),
    );
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["before"], unchanged["after"]);
    let removed = command(
        &client,
        "memory_block_delete",
        json!({"block_start":moved["after"]["start"]}),
    );
    assert_eq!(removed["changed"], true);
    assert_eq!(removed["before"], moved["after"]);
    assert!(removed["after"].is_null());
    assert_eq!(removed["overlay_removed"], false);
    reopen(&client, &name);
    check_state(&client, "6000", true);
    let mappings = command(
        &client,
        "memory_file_mappings",
        json!({"file_offset":"0x258"}),
    );
    assert_eq!(mappings["count"], 0);
    assert_eq!(mappings["mappings"], json!([]));
    cleanup(&client, &name);
}

#[test]
#[serial]
fn overlay_move_and_delete_keep_space_until_its_last_block_is_removed() {
    require_ghidra!();
    let (client, name) = fixture();
    command(
        &client,
        "memory_block_create",
        json!({"name":"bank_code", "start":"ram:0x2000", "size":16,
            "uninitialized":false, "fill":171, "permissions":"rx", "volatile":false,
            "overlay":"bank"}),
    );
    command(
        &client,
        "memory_block_create",
        json!({"name":"bank_data", "start":"bank:0x4000", "size":16,
            "uninitialized":true, "permissions":"rw", "volatile":true}),
    );
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
public class MarkMovingOverlay extends GhidraScript {
    public void run() throws Exception {
        var address = currentProgram.getAddressFactory().getAddressSpace("bank")
            .getAddressInThisSpaceOnly(0x2000);
        currentProgram.getListing().setComment(address, CodeUnit.EOL_COMMENT, "overlay comment");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let moved = command(
        &client,
        "memory_block_move",
        json!({"block_start":"bank:0x2000", "start":"bank:0x6000"}),
    );
    assert_eq!(moved["after"]["start"], "bank:0x00006000");
    assert_eq!(moved["after"]["address_space"], "bank");
    assert_eq!(moved["after"]["base_space"], "ram");
    reopen(&client, &name);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
public class CheckMovedOverlay extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getAddressSpace("bank");
        var address = space.getAddressInThisSpaceOnly(0x6000);
        if (currentProgram.getMemory().getByte(address) != (byte) 0xab) {
            throw new IllegalStateException("Overlay bytes did not move");
        }
        if (!"overlay comment".equals(currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, address))) {
            throw new IllegalStateException("Overlay comment did not move");
        }
        // OverlayAddressSpace.getAddress falls back to the physical space at
        // unbacked offsets; inspect the overlay's former address explicitly.
        if (currentProgram.getMemory().getBlock(space.getAddressInThisSpaceOnly(0x2000)) != null) {
            throw new IllegalStateException("Overlay's previous block remains");
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let first = command(
        &client,
        "memory_block_delete",
        json!({"block_start":moved["after"]["start"]}),
    );
    assert_eq!(first["overlay_removed"], false);
    reopen(&client, &name);
    let last = command(
        &client,
        "memory_block_delete",
        json!({"block_start":"bank:0x4000"}),
    );
    assert_eq!(last["overlay_removed"], true);
    reopen(&client, &name);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckRemovedOverlay extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.getAddressFactory().getAddressSpace("bank") != null) {
            throw new IllegalStateException("Last block deletion retained overlay space");
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    check_state(&client, "2000", false);
    cleanup(&client, &name);
}

#[test]
#[serial]
fn block_lifecycle_rejects_conflicts_wrap_space_changes_and_indirect_mapping_damage() {
    require_ghidra!();
    let (client, name) = fixture();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
public class CreateBlockConstraints extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createInitializedBlock("byte_backing", toAddr(0x8000), 0x40, (byte) 0x5a, monitor, false);
        // The latter half maps currently absent backing bytes.
        memory.createByteMappedBlock("byte_view", toAddr(0x9000), toAddr(0x8000), 0x80, false);
        memory.createInitializedBlock("bit_backing", toAddr(0xb000), 0x10, (byte) 0x5a, monitor, false);
        memory.createBitMappedBlock("bit_view", toAddr(0xc000), toAddr(0xb000), 0x80, false);
        memory.createBitMappedBlock("unmapped_bit_view", toAddr(0xe000), toAddr(0xd000), 0x80, false);
        memory.createInitializedBlock("constraint_bank", toAddr(0x2000), 0x10, (byte) 0x33, monitor, true);
        memory.createInitializedBlock("other_bank", AddressSpace.OTHER_SPACE.getAddress(0x2000),
            0x10, (byte) 0x22, monitor, true);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = client.memory_block_list().unwrap();
    for (start, destination, diagnostic) in [
        ("0x2000", "0x4000", "overlap"),
        ("0x2000", "0xffffffffffffff80", "overflow"),
        ("0x2000", "constraint_bank:0x6000", "same address space"),
        ("other_bank:0x2000", "other_bank:0x6000", "nonloaded"),
        ("0x2000", "0x8040", "mapped"),
        ("0x2000", "0xd000", "mapped"),
    ] {
        reject(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":destination}),
            diagnostic,
        );
    }
    for start in ["0x8000", "0x9000", "0xb000", "0xc000"] {
        reject(
            &client,
            "memory_block_move",
            json!({"block_start":start, "start":"0x10000"}),
            "mapped",
        );
        reject(
            &client,
            "memory_block_delete",
            json!({"block_start":start}),
            "mapped",
        );
    }
    assert_eq!(client.memory_block_list().unwrap(), before);
    reopen(&client, &name);
    assert_eq!(client.memory_block_list().unwrap(), before);
    check_state(&client, "2000", false);
    cleanup(&client, &name);
}

const ROLLBACK_PROBE: &str = r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class BlockLifecycleRollbackProbe extends GhidraScript {
    /* CHECK_STATE */
    private String fault;
    private Program selected;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        Program real = (Program) file.getDomainObject(owner, true, false, monitor);
        boolean deleting = getScriptArgs()[1].equals("delete");
        String nativeMethod = deleting ? "removeBlock" : "moveBlock";
        Object session = null;
        try {
            Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(type -> type.getSimpleName().equals("ScriptCommands")
                        && type.getPackageName().equals("ghidracli.script")).findFirst().orElseThrow());
            var loader = caller.getClassLoader();
            String prefix = caller.getPackageName()
                .substring(0, caller.getPackageName().lastIndexOf('.') + 1);

            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[]{Memory.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real.getMemory(), args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                    if (method.getName().equals(nativeMethod) && fault != null && !fault.equals("save")) {
                        require(real.getMemory().getBlock(real.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(0x2000)) == null,
                            "Failure preceded native block mutation");
                        String mode = fault;
                        fault = null;
                        if (mode.equals("cancel")) requestMonitor.cancel();
                        else throw new IllegalStateException("injected error after native block mutation");
                    }
                    return result;
                });
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getMemory")) return memory;
                    if (method.getName().equals("save") && "save".equals(fault)) {
                        fault = null;
                        throw new java.io.IOException("injected block save failure");
                    }
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                });
            var accessClass = loader.loadClass(prefix + "session.ScriptAccess");
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
            var sessionClass = loader.loadClass(prefix + "session.ProgramSession");
            var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
            sessionConstructor.setAccessible(true);
            session = sessionConstructor.newInstance(access);
            var dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
            var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
            dispatcherConstructor.setAccessible(true);
            Object dispatcher = dispatcherConstructor.newInstance(session);
            var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
            execute.setAccessible(true);
            var args = new JsonObject();
            args.addProperty("block_start", "0x2000");
            if (!deleting) args.addProperty("start", "0x6000");
            String command = "memory_block_" + getScriptArgs()[1];
            for (String mode : new String[]{"error", "cancel", "save"}) {
                fault = mode;
                var response = (JsonObject) execute.invoke(dispatcher, command, args);
                require(response.get("status").getAsString().equals("error"), response.toString());
                require(fault == null, "Fault did not follow a real mutation");
                var detail = response.getAsJsonObject("detail");
                require(!detail.has("partial_changes_saved"), response.toString());
                if (mode.equals("save")) {
                    require(detail.get("save_failed").getAsBoolean(), response.toString());
                    require(real.isChanged(), "Save failure lost pending block edits");
                    checkState(real, deleting ? 0x2000 : 0x6000, deleting);
                } else {
                    require(detail.get("rolled_back").getAsBoolean(), response.toString());
                    if (mode.equals("cancel")) require(detail.get("cancelled").getAsBoolean(), response.toString());
                    requestMonitor.clearCancelled();
                    checkState(real, 0x2000, false);
                }
                Object reader = new Object();
                Program saved = (Program) file.getReadOnlyDomainObject(reader,
                    DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
                try { checkState(saved, 0x2000, false); }
                finally { saved.release(reader); }
            }
            var saved = (JsonObject) execute.invoke(dispatcher, "program_save", new JsonObject());
            require(saved.get("status").getAsString().equals("success"), saved.toString());
            require(!real.isChanged(), "Explicit save did not persist pending block mutation");
            checkState(real, deleting ? 0x2000 : 0x6000, deleting);
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
"#;

#[test]
#[serial]
fn move_and_delete_roll_back_after_native_failure_and_cancellation_and_recover_failed_saves() {
    require_ghidra!();
    let (client, name) = fixture();
    let source = ROLLBACK_PROBE.replace("/* CHECK_STATE */", CHECK_STATE);
    for operation in ["move", "delete"] {
        let folder = format!("block-rollback-{}", uuid::Uuid::new_v4());
        client
            .script_run_source(&source, &[folder.clone(), operation.into()], &[], false)
            .unwrap();
        let copied = format!("/{folder}/{name}");
        client.open_program(&copied).unwrap();
        check_state(
            &client,
            if operation == "move" { "6000" } else { "2000" },
            operation == "delete",
        );
        client.open_program(&name).unwrap();
        check_state(&client, "2000", false);
        client.program_delete(&copied).unwrap();
    }
    cleanup(&client, &name);
}
