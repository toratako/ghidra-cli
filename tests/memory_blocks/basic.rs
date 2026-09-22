use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, DaemonTestHarness};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;

const CREATE_FIXTURE: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateBlockBasicsFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("block basics fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("seed", space.getAddress(0x100),
                    16, (byte) 0x17, monitor, false);
                program.getSymbolTable().createLabel(space.getAddress(0x2000),
                    "block_start_symbol", SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#;

fn with_fixture(language: &str, check: impl FnOnce(&DaemonTestHarness, &BridgeClient, &str)) {
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("block-basics-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(CREATE_FIXTURE, &[name.clone(), language.into()], &[], false)
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(harness, &client, &name);
    }));
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn cli(harness: &DaemonTestHarness, program: &str, args: &[&str]) -> Value {
    let result = ghidra(harness)
        .args(["memory", "block"])
        .args(args.iter().copied())
        .with_project(harness.project(), program)
        .json_format()
        .run();
    result.assert_success();
    result.data()
}

fn command(client: &BridgeClient, name: &str, args: Value) -> Value {
    client.send_command(name, Some(args)).unwrap()
}

fn read(client: &BridgeClient, address: &str, size: usize) -> Value {
    command(
        client,
        "read_memory",
        json!({"address": address, "size": size}),
    )
}

fn map_block(client: &BridgeClient, start: &Value) -> Value {
    client.memory_map().unwrap()["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["start"] == *start)
        .unwrap_or_else(|| panic!("No block at {start}"))
        .clone()
}

fn reject(client: &BridgeClient, name: &str, args: Value) {
    let before = client.memory_map().unwrap();
    let error = client
        .send_command(name, Some(args.clone()))
        .expect_err(&format!("Invalid mutation accepted: {name} {args}"));
    let error = error.downcast_ref::<BridgeCommandError>().unwrap();
    assert_eq!(error.detail["rolled_back"], true, "{args}: {error:?}");
    assert_eq!(client.memory_map().unwrap(), before, "{args}");
}

#[test]
#[serial]
fn create_distinguishes_unknown_memory_from_fill_and_persists_block_attributes() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |harness, client, program| {
        let ram = cli(
            harness,
            program,
            &[
                "create",
                ".ram",
                "ram:0x2000",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(ram["status"], "created");
        assert_eq!(ram["changed"], true);
        assert!(ram["before"].is_null());
        assert_eq!(
            ram["after"],
            json!({
                "name": ".ram", "start": "0x00002000", "end": "0x0000200f", "size": 16,
                "permissions": "rw", "initialized": false, "is_loaded": true, "address_space": "ram",
                "overlay": false, "base_space": null, "type": "default", "volatile": false
            })
        );
        let info = client.memory_info("0x2005").unwrap();
        assert_eq!(info["memory"]["initialized"], false);
        assert_eq!(info["file_mapping"]["state"], "unmapped");
        client
            .send_command("read_memory", Some(json!({"address": "0x2000", "size": 4})))
            .expect_err("Uninitialized memory must not read as zero");
        let before = client.memory_map().unwrap();
        client
            .memory_write("0x2000", "01020304")
            .expect_err("memory write must not initialize unknown storage");
        assert_eq!(client.memory_map().unwrap(), before);

        let mmio = cli(
            harness,
            program,
            &[
                "create",
                ".mmio",
                "ram:0x3000",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
                "--volatile",
            ],
        );
        assert_eq!(mmio["after"]["volatile"], true);
        let zero = cli(
            harness,
            program,
            &[
                "create",
                ".zero",
                "ram:0x4000",
                "16",
                "--fill",
                "0x00",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(zero["after"]["initialized"], true);
        assert_eq!(read(client, "0x4000", 16)["hex"], "00".repeat(16));
        let filled = cli(
            harness,
            program,
            &[
                "create",
                ".filled",
                "ram:0x5000",
                "16",
                "--fill",
                "0xff",
                "--permissions",
                "rwx",
            ],
        );
        assert_eq!(read(client, "0x5000", 16)["hex"], "ff".repeat(16));
        assert_eq!(
            client.memory_info("0x5001").unwrap()["file_mapping"]["state"],
            "unmapped"
        );

        let permissions = cli(harness, program, &["set-permissions", "0x5000", "r"]);
        assert_eq!(permissions["status"], "updated");
        assert_eq!(permissions["before"], filled["after"]);
        assert_eq!(permissions["after"]["permissions"], "r");
        assert_eq!(permissions["changed"], true);
        let none = cli(harness, program, &["set-permissions", "0x5000", "none"]);
        assert_eq!(none["before"], permissions["after"]);
        assert_eq!(none["after"]["permissions"], "");
        let unchanged = cli(harness, program, &["set-permissions", "0x5000", "none"]);
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        let cleared = cli(
            harness,
            program,
            &["set-volatile", "0x3000", "--value", "false"],
        );
        assert_eq!(cleared["status"], "updated");
        assert_eq!(cleared["before"], mmio["after"]);
        assert_eq!(cleared["after"]["volatile"], false);
        assert_eq!(cleared["changed"], true);
        let restored = cli(
            harness,
            program,
            &["set-volatile", "0x3000", "--value", "true"],
        );
        assert_eq!(restored["before"], cleared["after"]);
        assert_eq!(restored["after"], mmio["after"]);
        let unchanged = cli(
            harness,
            program,
            &["set-volatile", "0x3000", "--value", "true"],
        );
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        for receipt in [&ram, &mmio, &zero, &none] {
            let block = &receipt["after"];
            let mapped = map_block(client, &block["start"]);
            for field in [
                "name",
                "permissions",
                "address_space",
                "overlay",
                "base_space",
                "type",
                "volatile",
            ] {
                assert_eq!(mapped[field], block[field], "{field}");
            }
            assert_eq!(mapped["is_initialized"], block["initialized"]);
            assert_eq!(mapped["is_loaded"], true);
        }
        // Mapped blocks report initialized=false natively, but still expose the
        // initialized source bytes. Only genuinely unknown storage is unreadable.
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class CreateBlockReadAliases extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var memory = currentProgram.getMemory();
        memory.createByteMappedBlock("byte_alias", space.getAddress(0x6000),
            space.getAddress(0x5000), 16, false);
        memory.createBitMappedBlock("bit_alias", space.getAddress(0x7000),
            space.getAddress(0x5000), 8, false);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        for (start, kind, expected) in [
            ("0x00006000", "byte_mapped", "ffffffffffffffff"),
            ("0x00007000", "bit_mapped", "0101010101010101"),
        ] {
            let mapped = map_block(client, &json!(start));
            assert_eq!(mapped["type"], kind);
            assert_eq!(mapped["is_initialized"], false);
            assert_eq!(read(client, start, 8)["hex"], expected);
        }
        let saved = client.memory_map().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_map().unwrap(), saved);
        assert_eq!(read(client, "0x4000", 16)["hex"], "00".repeat(16));
        assert_eq!(read(client, "0x5000", 16)["hex"], "ff".repeat(16));
        assert_eq!(
            client.memory_info("0x2000").unwrap()["memory"]["initialized"],
            false
        );
    });
}

#[test]
#[serial]
fn overlays_keep_explicit_space_identity_and_edits_require_exact_block_starts() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |harness, client, program| {
        let physical = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "ram:0x2000",
                "16",
                "--fill",
                "0x11",
                "--permissions",
                "rw",
            ],
        );
        let overlay = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "ram:0x2000",
                "16",
                "--overlay",
                "bank1",
                "--fill",
                "0x22",
                "--permissions",
                "rx",
            ],
        );
        assert_eq!(overlay["after"]["name"], physical["after"]["name"]);
        assert_eq!(overlay["after"]["start"], "bank1:0x00002000");
        assert_eq!(overlay["after"]["address_space"], "bank1");
        assert_eq!(overlay["after"]["base_space"], "ram");
        assert_eq!(overlay["after"]["overlay"], true);
        assert_eq!(read(client, "0x2000", 4)["hex"], "11111111");
        assert_eq!(read(client, "bank1:0x2000", 4)["hex"], "22222222");

        let renamed = cli(
            harness,
            program,
            &["rename", "bank1:0x00002000", ".renamed"],
        );
        assert_eq!(renamed["status"], "updated");
        assert_eq!(renamed["before"], overlay["after"]);
        assert_eq!(renamed["changed"], true);
        let mut expected = overlay["after"].clone();
        expected["name"] = json!(".renamed");
        assert_eq!(renamed["after"], expected);
        assert_eq!(
            map_block(client, &physical["after"]["start"])["name"],
            ".shared"
        );
        let unchanged = cli(
            harness,
            program,
            &["rename", "bank1:0x00002000", ".renamed"],
        );
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert_eq!(unchanged["before"], unchanged["after"]);

        let extra = cli(
            harness,
            program,
            &[
                "create",
                ".shared",
                "bank1:0x4000",
                "16",
                "--uninitialized",
                "--permissions",
                "rw",
            ],
        );
        assert_eq!(extra["after"]["address_space"], "bank1");
        assert_eq!(extra["after"]["base_space"], "ram");
        assert_eq!(extra["after"]["overlay"], true);
        assert_eq!(extra["after"]["start"], "bank1:0x00004000");
        let changed = cli(
            harness,
            program,
            &["set-permissions", "bank1:0x00002000", "w"],
        );
        assert_eq!(changed["after"]["permissions"], "w");
        let changed = cli(
            harness,
            program,
            &["set-volatile", "bank1:0x00002000", "--value", "true"],
        );
        assert_eq!(changed["after"]["volatile"], true);
        let untouched = map_block(client, &physical["after"]["start"]);
        assert_eq!(untouched["permissions"], "rw");
        assert_eq!(untouched["volatile"], false);

        // One shared target validator must reject both interiors and real symbols.
        // Other operations use representative targets to guard their dispatch wiring.
        for target in ["0x2001", "block_start_symbol", ".shared", "bank1:0x2001"] {
            reject(
                client,
                "memory_block_rename",
                json!({"block_start": target, "name": ".wrong"}),
            );
        }
        reject(
            client,
            "memory_block_set_permissions",
            json!({"block_start": "0x2001", "permissions": "none"}),
        );
        reject(
            client,
            "memory_block_set_volatile",
            json!({"block_start": "block_start_symbol", "value": true}),
        );
        let saved = client.memory_map().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_map().unwrap(), saved);
        assert_eq!(
            client.memory_info("bank1:0x2003").unwrap()["memory"]["name"],
            ".renamed"
        );
        assert_eq!(read(client, "0x2000", 4)["hex"], "11111111");
        assert_eq!(read(client, "bank1:0x2000", 4)["hex"], "22222222");
    });
}

#[test]
#[serial]
fn creation_validation_and_collisions_leave_memory_and_overlay_spaces_unchanged() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |_, client, program| {
        let valid = json!({"name": ".valid", "start": "ram:0x2000", "size": 16,
            "uninitialized": false, "fill": 0, "permissions": "rw", "volatile": false});
        for (field, replacement) in [
            ("fill", None),
            ("uninitialized", Some(json!(true))),
            ("size", Some(json!(1.5))),
            ("size", Some(json!(0))),
            ("fill", Some(json!(256))),
            ("permissions", None),
            ("permissions", Some(json!("read"))),
            ("volatile", Some(json!("true"))),
        ] {
            let mut invalid = valid.clone();
            if let Some(value) = replacement {
                invalid[field] = value;
            } else {
                invalid.as_object_mut().unwrap().remove(field);
            }
            reject(client, "memory_block_create", invalid);
        }
        let created = command(client, "memory_block_create", valid.clone());
        assert_eq!(created["after"]["name"], ".valid");
        reject(client, "memory_block_create", valid.clone());
        let mut overlay = valid.clone();
        overlay["overlay"] = json!("bank1");
        command(client, "memory_block_create", overlay.clone());
        overlay["start"] = json!("ram:0x3000");
        reject(client, "memory_block_create", overlay.clone());
        overlay["overlay"] = json!("ram");
        reject(client, "memory_block_create", overlay.clone());
        overlay["overlay"] = json!("overflow_bank");
        overlay["start"] = json!("ram:0xffffffffffffffff");
        overlay["size"] = json!(2);
        reject(client, "memory_block_create", overlay);
        reject(
            client,
            "memory_block_set_permissions",
            json!({"block_start": "0x2000", "permissions": "read"}),
        );
        reject(
            client,
            "memory_block_set_volatile",
            json!({"block_start": "0x2000", "value": "false"}),
        );

        // A map comparison alone would miss an empty space leaked on failed creation.
        const CHECK_SPACES: &str = r#"
import ghidra.app.script.GhidraScript;
public class CheckBlockSpaces extends GhidraScript {
    public void run() throws Exception {
        var factory = currentProgram.getAddressFactory();
        int overlays = 0;
        for (var space : factory.getAddressSpaces()) {
            if (space.isOverlaySpace()) {
                overlays++;
                if (!space.getName().equals("bank1"))
                    throw new IllegalStateException("Unexpected overlay: " + space.getName());
            }
        }
        if (overlays != 1 || factory.getAddressSpace("overflow_bank") != null)
            throw new IllegalStateException("Failed creation leaked an address space");
    }
}
"#;
        client
            .script_run_source(CHECK_SPACES, &[], &[], false)
            .unwrap();
        let saved = client.memory_map().unwrap();
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.memory_map().unwrap(), saved);
        client
            .script_run_source(CHECK_SPACES, &[], &[], false)
            .unwrap();
    });
}

#[test]
#[serial]
fn cancelled_creation_rolls_back_a_native_block_and_its_new_overlay_space() {
    require_ghidra!();
    with_fixture("x86:LE:64:default", |_, client, program| {
        let before = client.memory_map().unwrap();
        let folder = format!("block-create-rollback-{}", uuid::Uuid::new_v4());
        // A separate database lets the production dispatcher own the request
        // transaction while the surrounding script retains its own session.
        client
            .script_run_source(
                r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class BlockCreateRollbackProbe extends GhidraScript {
    private Program selected;
    private boolean nativeCreationObserved;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    private void checkAbsent(Program program) throws Exception {
        require(program.getAddressFactory().getAddressSpace("late_bank") == null,
            "Cancelled creation retained its new overlay space");
        require(program.getMemory().getBlocks().length == 1,
            "Cancelled creation retained a block");
        var seed = program.getMemory().getBlock("seed");
        require(seed != null && seed.getSize() == 16
            && program.getMemory().getByte(seed.getStart()) == (byte) 0x17,
            "Cancellation changed existing memory");
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
            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[]{Memory.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real.getMemory(), args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                    if (method.getName().equals("createInitializedBlock")) {
                        var space = real.getAddressFactory().getAddressSpace("late_bank");
                        require(space != null && space.isOverlaySpace(),
                            "Cancellation preceded native overlay creation");
                        var address = space.getAddressInThisSpaceOnly(0x2000);
                        var block = real.getMemory().getBlock(address);
                        require(block != null && block.getSize() == 16
                            && block.getStart().equals(address)
                            && real.getMemory().getByte(address) == (byte) 0x5a,
                            "Cancellation preceded native initialized block creation");
                        nativeCreationObserved = true;
                        requestMonitor.cancel();
                    }
                    return result;
                });
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getMemory")) return memory;
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
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
            args.addProperty("name", ".late_block");
            args.addProperty("start", "ram:0x2000");
            args.addProperty("size", 16);
            args.addProperty("fill", 0x5a);
            args.addProperty("permissions", "rw");
            args.addProperty("overlay", "late_bank");
            var response = (JsonObject) execute.invoke(dispatcher, "memory_block_create", args);
            require(nativeCreationObserved, "Test did not reach native overlay/block creation");
            require(response.get("status").getAsString().equals("error"), response.toString());
            var detail = response.getAsJsonObject("detail");
            require(detail.get("cancelled").getAsBoolean(), response.toString());
            require(detail.get("rolled_back").getAsBoolean(), response.toString());
            require(!detail.has("partial_changes_saved"), response.toString());
            requestMonitor.clearCancelled();
            checkAbsent(real);
            Object reader = new Object();
            Program saved = (Program) file.getReadOnlyDomainObject(reader,
                DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
            try { checkAbsent(saved); }
            finally { saved.release(reader); }
        } finally {
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
"#,
                std::slice::from_ref(&folder),
                &[],
                false,
            )
            .unwrap();
        let copied = format!("/{folder}/{program}");
        client.open_program(&copied).unwrap();
        assert_eq!(client.memory_map().unwrap(), before);
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class CheckReopenedCancelledOverlay extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.getAddressFactory().getAddressSpace("late_bank") != null
                || currentProgram.getMemory().getBlocks().length != 1)
            throw new IllegalStateException("Cancelled overlay/block reappeared after reopen");
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        client.open_program(program).unwrap();
        client.program_delete(&copied).unwrap();
    });
}

#[test]
#[serial]
fn block_sizes_count_bytes_in_word_and_segmented_spaces_and_starts_round_trip() {
    require_ghidra!();
    for (language, start, expected_offset) in [
        ("avr8:LE:16:default", "0x1000.1", "2001"),
        ("x86:LE:16:Real Mode", "ram:0x0200:0x0001", "2001"),
    ] {
        with_fixture(language, |_, client, program| {
            let created = command(
                client,
                "memory_block_create",
                json!({
                    "name": ".odd", "start": start, "size": 3, "uninitialized": false,
                    "fill": 165, "permissions": "rw", "volatile": false
                }),
            );
            assert_eq!(created["after"]["size"], 3);
            let returned_start = created["after"]["start"].as_str().unwrap();
            assert_eq!(read(client, returned_start, 3)["hex"], "a5a5a5");
            let renamed = command(
                client,
                "memory_block_rename",
                json!({
                    "block_start": returned_start, "name": ".renamed_odd"
                }),
            );
            assert_eq!(renamed["before"], created["after"]);
            assert_eq!(renamed["after"]["start"], created["after"]["start"]);
            assert_eq!(renamed["after"]["end"], created["after"]["end"]);
            const CHECK_BYTES: &str = r#"
import ghidra.app.script.GhidraScript;
public class CheckBlockByteSize extends GhidraScript {
    public void run() throws Exception {
        var block = currentProgram.getMemory().getBlock(".renamed_odd");
        long start = Long.parseLong(getScriptArgs()[0], 16);
        if (block == null || block.getStart().getOffset() != start
                || block.getEnd().getOffset() != start + 2 || block.getSize() != 3)
            throw new IllegalStateException("Block creation did not preserve byte offsets and size");
    }
}
"#;
            client
                .script_run_source(CHECK_BYTES, &[expected_offset.into()], &[], false)
                .unwrap();
            let saved = client.memory_map().unwrap();
            client.program_close().unwrap();
            client.open_program(program).unwrap();
            assert_eq!(client.memory_map().unwrap(), saved);
            client
                .script_run_source(CHECK_BYTES, &[expected_offset.into()], &[], false)
                .unwrap();
        });
    }
}
