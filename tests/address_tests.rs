//! Explicit address syntax and name resolution against an isolated raw program.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};

#[macro_use]
mod common;

#[test]
fn explicit_addresses_and_exact_names_preserve_targets() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-address-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("addresses.bin");
    std::fs::write(&binary, vec![0xc3; 0x700]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_installation()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:32:default".into()),
            loader: Some("BinaryLoader".into()),
            loader_options: vec![("baseAddr".into(), "0x1000".into())],
            ..Default::default()
        },
    )
    .expect("import address fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program)
        .expect("start address fixture bridge");
    let client = harness.client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateAddressFixture extends GhidraScript {
    public void run() throws Exception {
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var memory = currentProgram.getMemory();
        var functions = currentProgram.getFunctionManager();
        String[] names = {"add", "dead", "12345", "FUN_00001400", "malformed_target",
            "literal_add", "literal_dead", "literal_digits"};
        long[] offsets = {0x1000, 0x1100, 0x1200, 0x1400, 0x1500, 0xadd, 0xdead, 0x12345};
        for (int i = 0; i < names.length; i++) {
            var address = space.getAddress(offsets[i]);
            if (!memory.contains(address)) {
                memory.createInitializedBlock(names[i], address, 1, (byte) 0xc3, monitor, false);
            }
            memory.getBlock(address).setExecute(true);
            int length = i < 2 ? 6 : 1;
            if (i < 2) {
                // A real x86 CALL to the next named function, followed by RET.
                memory.setBytes(address, new byte[] {(byte) 0xe8, (byte) 0xfb, 0, 0, 0, (byte) 0xc3});
            }
            if (!new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("Disassembly failed for " + names[i]);
            }
            if (i < 2) new DisassembleCommand(address.add(5), null, false).applyTo(currentProgram, monitor);
            functions.createFunction(names[i], address,
                new AddressSet(address, address.add(length - 1)), SourceType.USER_DEFINED);
        }
        var symbols = currentProgram.getSymbolTable();
        symbols.createLabel(space.getAddress(0x1000), "ambiguous", SourceType.USER_DEFINED);
        symbols.createLabel(space.getAddress(0x1100), "ambiguous", SourceType.USER_DEFINED);
        symbols.createLabel(space.getAddress(0x1000), "entry_alias", SourceType.USER_DEFINED);
        symbols.createLabel(space.getAddress(0x1005), "interior_label", SourceType.USER_DEFINED);
        symbols.createLabel(space.getAddress(0x1005), "FUN_00001400", SourceType.USER_DEFINED);
        for (int i = 0; i < 2; i++) {
            var namespace = symbols.createNameSpace(null, "scope" + i, SourceType.USER_DEFINED);
            var address = space.getAddress(0x1300 + i * 0x10);
            functions.createFunction("ambiguous", namespace, address,
                new AddressSet(address, address), SourceType.USER_DEFINED);
        }
        for (String name : new String[] {"0x", "0X", "0xnothex", "0x1000junk"}) {
            symbols.createLabel(space.getAddress(0x1500), name, SourceType.USER_DEFINED);
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .expect("create name and address collisions");

    check_name_and_address_reads(&client);
    check_invalid_targets_do_not_mutate(&client, &harness);
    check_labels_do_not_select_functions(&client, &harness);
    check_address_only_ipc(&client);
    check_mutation_targets(&client, &harness);
    check_address_codec(&client);
    check_import_base_addresses(&client, &binary);
}

fn check_import_base_addresses(client: &BridgeClient, fixture: &std::path::Path) {
    let binary = fixture.with_file_name("base-address.bin");
    std::fs::write(&binary, [0xc3]).unwrap();
    let before = client.send_command("list_programs", None).unwrap();
    for (language, address) in [
        ("x86:LE:32:default", "0xffffffffffffffff"),
        ("x86:LE:32:default", "0x100000000"),
        ("x86:LE:32:default", "unknown:0x1000"),
        ("x86:LE:16:Real Mode", "0x100001000"),
    ] {
        let error = client
            .send_command(
                "import",
                Some(json!({
                    "binary_path": binary,
                    "program": "invalid-base-address",
                    "loader": "BinaryLoader",
                    "language": language,
                    "loader_options": [["baseAddr", address]],
                })),
            )
            .expect_err("out-of-range base address must fail before import");
        let detail = &error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .expect("structured invalid base address error")
            .detail;
        assert_eq!(detail["stage"], "import.options", "{error}");
        assert_eq!(detail["import_status"], "not_started", "{error}");
        assert_eq!(client.send_command("list_programs", None).unwrap(), before);
    }
}

fn get_function(client: &BridgeClient, target: &str) -> Value {
    client
        .send_command("get_function", Some(json!({"address": target})))
        .unwrap_or_else(|error| panic!("get function {target}: {error:#}"))
}

fn check_name_and_address_reads(client: &BridgeClient) {
    for (name, address, literal) in [
        ("add", "0x00001000", "literal_add"),
        ("dead", "0x00001100", "literal_dead"),
        ("12345", "0x00001200", "literal_digits"),
    ] {
        let function = get_function(client, name);
        assert_eq!(function["address"], address, "{name}");
        assert_eq!(function["name"], name);
        assert_eq!(get_function(client, address), function);
        assert_eq!(
            get_function(client, &address.replacen("0x", "0X", 1)),
            function
        );
        assert_eq!(get_function(client, &format!("0x{name}"))["name"], literal);
        assert_eq!(
            client.symbol_get(name).unwrap()["symbols"][0]["address"],
            address
        );
        assert_eq!(
            client
                .decompile(name.into(), false, false, false, false)
                .unwrap()["address"],
            address
        );
        assert_eq!(
            client.function_disasm(name, None).unwrap()["instructions"][0]["address"],
            address
        );
        assert_eq!(
            client.disasm(name, Some(1)).unwrap()["instructions"][0]["address"],
            address
        );
        for function_scope in [false, true] {
            assert_eq!(
                client.xrefs_from(name.to_owned(), function_scope).unwrap(),
                client
                    .xrefs_from(address.to_owned(), function_scope)
                    .unwrap(),
                "xref from name/address equivalence: {name}, function={function_scope}"
            );
        }
        for command in ["graph_callers", "graph_callees"] {
            let by_name = client
                .send_command(command, Some(json!({"function": name})))
                .unwrap();
            let by_address = client
                .send_command(command, Some(json!({"function": address})))
                .unwrap();
            assert_eq!(by_name["calls"], by_address["calls"], "{command}: {name}");
        }
    }
    let incoming = client.graph_callers("dead", None, None).unwrap();
    assert_eq!(incoming["calls"][0]["caller_address"], "0x00001000");
    assert_eq!(incoming["calls"][0]["callee_address"], "0x00001100");
    let outgoing = client.graph_callees("dead", None, None).unwrap();
    assert_eq!(outgoing["calls"][0]["callee_address"], "0x00001200");
    assert_eq!(
        get_function(client, "FUN_00001400")["address"],
        "0x00001400"
    );
    assert_eq!(
        client.function_disasm("FUN_00001400", None).unwrap()["instructions"][0]["address"],
        "0x00001400"
    );
    for (target, address) in [
        ("scope0::ambiguous", "0x00001300"),
        ("scope1::ambiguous", "0x00001310"),
    ] {
        assert_eq!(get_function(client, target)["address"], address);
        client
            .send_command(
                "function_set_noreturn",
                Some(json!({"target":target,"value":true})),
            )
            .unwrap();
        assert_eq!(get_function(client, target)["no_return"], true);
        client
            .send_command(
                "function_set_noreturn",
                Some(json!({"target":target,"value":false})),
            )
            .unwrap();
    }
}

fn target_requests(target: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("get_function", json!({"address": target})),
        ("decompile", json!({"address": target})),
        ("disasm", json!({"address": target, "limit": 1})),
        ("function_disasm", json!({"target": target})),
        ("graph_callers", json!({"function": target})),
        ("graph_callees", json!({"function": target})),
        (
            "rename_function",
            json!({"old_name": target, "new_name": "wrong_target"}),
        ),
        (
            "function_set_signature",
            json!({"target": target, "signature": "int wrong_target(int value)"}),
        ),
        (
            "function_set_noreturn",
            json!({"target": target, "value": true}),
        ),
        ("delete_function", json!({"address": target})),
    ]
}

fn check_invalid_targets_do_not_mutate(client: &BridgeClient, harness: &common::DaemonTestHarness) {
    let before = client.list_functions(None, None, &[], false, None).unwrap();
    // These explicit-looking tokens really exist as labels, but malformed address
    // syntax must never fall back to any of those names.
    for target in [
        "0x",
        "0X",
        "0xnothex",
        "0x1000junk",
        "FUN_00001000",
        "1000",
        "ambiguous",
    ] {
        for (command, args) in target_requests(target) {
            let error = client.send_command(command, Some(args)).unwrap_err();
            if target == "ambiguous" {
                assert!(
                    error.to_string().contains("Ambiguous"),
                    "{command}: {error}"
                );
            }
        }
    }
    for target in ["0xnothex", "FUN_00001000", "ambiguous"] {
        common::ghidra(harness)
            .args(["function", "rename", target, "wrong_target"])
            .run()
            .assert_failure();
    }
    assert_eq!(
        client.list_functions(None, None, &[], false, None).unwrap(),
        before
    );
}

fn check_labels_do_not_select_functions(
    client: &BridgeClient,
    harness: &common::DaemonTestHarness,
) {
    let before = get_function(client, "add");
    for (label, address) in [
        ("entry_alias", "0x00001000"),
        ("interior_label", "0x00001005"),
    ] {
        assert_eq!(
            client.symbol_get(label).unwrap()["symbols"][0]["address"],
            address
        );
        assert_eq!(
            client.disasm(label, Some(1)).unwrap()["instructions"][0]["address"],
            address
        );
        common::ghidra(harness)
            .args(["function", "delete", label])
            .run()
            .assert_failure();
        assert!(client.function_disasm(label, None).is_err());
        assert_eq!(get_function(client, "add"), before);
    }
    // Explicit interior addresses still select the containing function.
    assert_eq!(get_function(client, "0x1005"), before);
    client
        .send_command(
            "function_set_noreturn",
            Some(json!({"target": "0x1005", "value": true})),
        )
        .unwrap();
    assert_eq!(get_function(client, "add")["no_return"], true);
    client
        .send_command(
            "function_set_noreturn",
            Some(json!({"target": "0x1005", "value": false})),
        )
        .unwrap();
    assert_eq!(get_function(client, "add"), before);
}

fn check_address_only_ipc(client: &BridgeClient) {
    client
        .comment_set("0X1600", "preserved comment", None)
        .unwrap();
    let comments = client.comment_get("0x1600").unwrap();
    let memory = client
        .send_command("read_memory", Some(json!({"address": "0x1600", "size": 8})))
        .unwrap();
    let symbols = client.symbol_list(None, None, None).unwrap();
    for address in ["1600", "ram:1600", "0xnothex"] {
        for (command, args) in [
            ("comment_get", json!({"address": address})),
            (
                "comment_set",
                json!({"address": address, "text": "wrong comment"}),
            ),
            ("comment_delete", json!({"address": address, "all": true})),
            (
                "define_data",
                json!({"address": address, "type_name": "int", "force": true}),
            ),
            (
                "symbol_create_label",
                json!({"address": address, "name": "wrong_symbol"}),
            ),
            ("read_memory", json!({"address": address, "size": 8})),
            (
                "memory_write",
                json!({"address": address, "hex": "00000000"}),
            ),
            ("define_code", json!({"target": address})),
            ("clear_range", json!({"start": address, "end": "0x1607"})),
        ] {
            assert!(
                client.send_command(command, Some(args)).is_err(),
                "{command} accepted {address}"
            );
        }
    }
    for (start, end) in [
        ("add", "0x1005"),
        ("0x1000", "dead"),
        ("0x1000", "register:0x1005"),
        ("0x1005", "0x1000"),
    ] {
        assert!(
            client
                .send_command("clear_range", Some(json!({"start": start, "end": end})))
                .is_err(),
            "clear endpoints must form a valid explicit range: {start}:{end}"
        );
    }
    let error = client
        .send_command(
            "rename_function",
            Some(json!({
                "old_name": "add", "new_name": "wrong_target", "address": "1000"
            })),
        )
        .unwrap_err();
    assert!(error.to_string().contains("address"), "{error}");
    assert_eq!(client.comment_get("0x1600").unwrap(), comments);
    assert_eq!(
        client
            .send_command("read_memory", Some(json!({"address": "0x1600", "size": 8})))
            .unwrap(),
        memory
    );
    assert_eq!(client.symbol_list(None, None, None).unwrap(), symbols);
    assert_eq!(
        client.function_disasm("add", None).unwrap()["instructions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Failed define_data must also leave the listing undefined, not just retain bytes.
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class VerifyAddressFailures extends GhidraScript {
    public void run() {
        var address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1600);
        if (currentProgram.getListing().getDefinedDataAt(address) != null
                || currentProgram.getListing().getInstructionAt(address) != null) {
            throw new IllegalStateException("Rejected address changed listing");
        }
    }
}
"#, &[], &[], false).unwrap();
}

fn check_mutation_targets(client: &BridgeClient, harness: &common::DaemonTestHarness) {
    for (name, address, literal_address) in [
        ("add", "0x00001000", "0xadd"),
        ("dead", "0x00001100", "0xdead"),
        ("12345", "0x00001200", "0x12345"),
    ] {
        let decoy = get_function(client, literal_address);
        let renamed = format!("renamed_{name}");
        common::ghidra(harness)
            .args(["function", "rename", name, &renamed])
            .run()
            .assert_success();
        assert_eq!(get_function(client, &renamed)["address"], address);
        assert_eq!(get_function(client, literal_address), decoy);
        client
            .send_command(
                "rename_function",
                Some(json!({"old_name": renamed, "new_name": name})),
            )
            .unwrap();
        let result = client
            .send_command(
                "function_set_signature",
                Some(json!({
                    "target": name, "signature": format!("int signature_{name}(int value)")
                })),
            )
            .unwrap();
        assert_eq!(result["address"], address);
        let signature = get_function(client, address)["signature"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            signature.contains("int") && signature.contains("value"),
            "{signature}"
        );
        assert_eq!(get_function(client, literal_address), decoy);
    }
}

fn check_address_codec(client: &BridgeClient) {
    // Compile the production codec beside this script, avoiding reflective access
    // to the bridge's private OSGi bundle and exercising real Ghidra address types.
    let codec = include_str!("../src/ghidra/scripts/ghidracli/query/AddressCodec.java")
        .replacen("package ghidracli.query;", "", 1)
        .replacen(
            "public final class AddressCodec",
            "final class AddressCodec",
            1,
        );
    let script = format!("{codec}\n{}", CODEC_CHECKS);
    client
        .script_run_source(&script, &[], &[], false)
        .expect("address codec invariants");
}

const CODEC_CHECKS: &str = r#"
public class CheckAddressCodec extends ghidra.app.script.GhidraScript {
    private void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }

    private void roundtrip(ghidra.program.model.address.AddressFactory factory,
            ghidra.program.model.address.Address address) {
        String text = AddressCodec.format(address);
        var parsed = AddressCodec.parseCanonical(factory, text);
        require(address.equals(parsed), "Address roundtrip failed: " + text);
        require(address.getAddressSpace().equals(parsed.getAddressSpace()), "Lost address space: " + text);
        require(address.getOffset() == parsed.getOffset(), "Lost byte offset: " + text);
        require(address.getAddressableWordOffset() == parsed.getAddressableWordOffset(), "Lost word offset: " + text);
    }

    public void run() throws Exception {
        var ram = new ghidra.program.model.address.GenericAddressSpace("ram", 64,
            ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
        var word = new ghidra.program.model.address.GenericAddressSpace("word", 24, 2,
            ghidra.program.model.address.AddressSpace.TYPE_RAM, 1);
        word.setShowSpaceName(true);
        var wide = new ghidra.program.model.address.GenericAddressSpace("wide", 63, 2,
            ghidra.program.model.address.AddressSpace.TYPE_RAM, 3);
        wide.setShowSpaceName(true);
        var signedWord = new ghidra.program.model.address.GenericAddressSpace("signed_word", 63, 2,
            ghidra.program.model.address.AddressSpace.TYPE_CONSTANT, 4);
        var factory = new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {ram, word, wide, signedWord}, ram);
        for (long offset : new long[] {0, 0x401000, Long.MIN_VALUE, -1L}) {
            roundtrip(factory, ram.getAddress(offset));
        }
        for (long offset : new long[] {0x2000, 0x2001, 0x1ffffff}) {
            roundtrip(factory, word.getAddress(offset));
        }
        for (long offset : new long[] {Long.MIN_VALUE, -1L}) roundtrip(factory, wide.getAddress(offset));
        for (long offset : new long[] {Long.MIN_VALUE, -3, -1, 1, Long.MAX_VALUE}) {
            roundtrip(factory, signedWord.getAddress(offset));
        }
        for (String input : new String[] {"signed_word:0x8000000000000000",
                "signed_word:0xbfffffffffffffff.1"}) {
            try {
                AddressCodec.parse(factory, input);
                throw new AssertionError("Signed word overflow silently wrapped: " + input);
            } catch (IllegalArgumentException expected) {
                // Negative word offsets must fit in the signed byte-offset range.
            }
        }
        require(AddressCodec.format(null) == null, "Null address must stay null");
        require(AddressCodec.format(ghidra.program.model.address.Address.NO_ADDRESS) == null,
            "NO_ADDRESS must not become an input address");
        var programFactory = currentProgram.getAddressFactory();
        roundtrip(programFactory, programFactory.getStackSpace().getAddress(-16));
        roundtrip(programFactory, programFactory.getAddressSpace("join").getAddress(1));
        var block = currentProgram.getMemory().createInitializedBlock("codec_overlay",
            programFactory.getDefaultAddressSpace().getAddress(0x1800), 4, (byte) 0, monitor, true);
        roundtrip(programFactory, block.getStart());
        var outsideOverlayBlock = AddressCodec.parse(programFactory, "codec_overlay:0x1000");
        require(outsideOverlayBlock.getAddressSpace().equals(block.getStart().getAddressSpace()),
            "Overlay address must not substitute the physical space outside its block");
        roundtrip(programFactory, outsideOverlayBlock);
        for (String name : new String[] {"0xbank", "0x1234"}) {
            var hexNamedBlock = currentProgram.getMemory().createInitializedBlock(name,
                programFactory.getDefaultAddressSpace().getAddress(0x1900), 4, (byte) 0, monitor, true);
            roundtrip(programFactory, hexNamedBlock.getStart());
        }
        var segmented = new ghidra.program.model.address.SegmentedAddressSpace("segmented", 2);
        var segmentedFactory = new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {segmented}, segmented);
        var address = segmented.getAddress(0x1234, 5);
        String text = AddressCodec.format(address);
        require(text.equals("segmented:0x1234:0x0005"), "Segmented format: " + text);
        roundtrip(segmentedFactory, address);
        try {
            AddressCodec.parseCanonical(segmentedFactory, "0x1234:0x0005");
            throw new AssertionError("Canonical endpoint inferred an unnamed segment");
        } catch (IllegalArgumentException expected) {
            // clear endpoints require the space name even in the default space.
        }
        for (String input : new String[] {text, "0X1234:0X0005", "segmented:0x1234:0x0005"}) {
            var parsed = (ghidra.program.model.address.SegmentedAddress) AddressCodec.parse(segmentedFactory, input);
            require(parsed != null && parsed.getSegment() == 0x1234 && parsed.getSegmentOffset() == 5,
                "Lost original segment/offset: " + input);
        }
        var numericSpace = new ghidra.program.model.address.GenericAddressSpace("0x1234", 32,
            ghidra.program.model.address.AddressSpace.TYPE_RAM, 6);
        var ambiguousFactory = new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {segmented, numericSpace}, segmented);
        roundtrip(ambiguousFactory, address);
        roundtrip(ambiguousFactory, numericSpace.getAddress(5));
        require(AddressCodec.parse(ambiguousFactory, "0x1234:0x0005").getAddressSpace().equals(numericSpace),
            "Registered numeric-looking address space must take precedence over an unnamed segment");
        for (String input : new String[] {"1000", "ram:1000", "FUN_00401000", "0x", "0xxyz",
                "0x10000000000000000", "0x1234:0005", "1234:0x0005", "segmented:1234:0005"}) {
            try {
                require(AddressCodec.parse(segmentedFactory, input) == null,
                    "Accepted invalid explicit address: " + input);
            } catch (IllegalArgumentException expected) {
                // Parsers may report malformed tokens either as null or an input error.
            }
        }
        var narrow = new ghidra.program.model.address.GenericAddressSpace("narrow", 32,
            ghidra.program.model.address.AddressSpace.TYPE_RAM, 5);
        var mixedFactory = new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {narrow, ram}, narrow);
        for (String input : new String[] {"0x100000000", "0xffffffffffffffff"}) {
            try {
                require(AddressCodec.parse(mixedFactory, input) == null,
                    "Address overflow silently changed the default space or recovered its sign: " + input);
            } catch (IllegalArgumentException expected) {
                // A larger secondary space cannot rescue overflow in the default space.
            }
        }
        require(AddressCodec.parse(mixedFactory, "ram:0xffffffffffffffff").getOffset() == -1L,
            "Explicit secondary 64-bit address must remain valid");
    }
}
"#;
