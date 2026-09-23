use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;

fn get(client: &BridgeClient, register: &str, start: &str, end: Option<&str>) -> Value {
    let mut args = json!({"register": register, "start": start});
    if let Some(end) = end {
        args["end"] = json!(end);
    }
    client
        .send_command("program_context_get", Some(args))
        .unwrap()
}

fn set(client: &BridgeClient, register: &str, value: &str, start: &str, end: &str) -> Value {
    client
        .send_command(
            "program_context_set",
            Some(json!({"register": register, "value": value, "start": start, "end": end})),
        )
        .unwrap()
}

fn clear(client: &BridgeClient, register: &str, start: &str, end: &str) -> Value {
    client
        .send_command(
            "program_context_clear",
            Some(json!({"register": register, "start": start, "end": end})),
        )
        .unwrap()
}

fn bits(value: &str, mask: &str) -> Value {
    json!({"value": value, "mask": mask})
}

fn with_fixture(check: impl FnOnce(&BridgeClient, &str) + std::panic::UnwindSafe) {
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let name = format!("processor-context-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateProcessorContextFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("ARM:LE:32:v8"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("processor context fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                // ARM MOV R0,#1; BX LR, and Thumb IT EQ; MOV R0,#1; BX LR.
                byte[] arm = {1, 0, (byte) 0xa0, (byte) 0xe3, 0x1e, (byte) 0xff, 0x2f, (byte) 0xe1};
                byte[] thumb = {8, (byte) 0xbf, 1, 0x20, 0x70, 0x47};
                program.getMemory().createInitializedBlock("arm", space.getAddress(0x1000),
                    new java.io.ByteArrayInputStream(arm), arm.length, monitor, false).setExecute(true);
                program.getMemory().createInitializedBlock("thumb", space.getAddress(0x2000),
                    new java.io.ByteArrayInputStream(thumb), thumb.length, monitor, false).setExecute(true);
                program.getMemory().createInitializedBlock("thumb_prefix", space.getAddress(0x1ff0),
                    0x10, (byte) 0, monitor, false);
                program.getMemory().createInitializedBlock("scratch", space.getAddress(0x3000),
                    0x40, (byte) 0, monitor, false);
                program.getMemory().createInitializedBlock("context_overlay", space.getAddress(0x3000),
                    0x40, (byte) 0, monitor, true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| check(&client, &name));
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn processor_context_masks_ranges_validation_and_persistence() {
    require_ghidra!();
    with_fixture(|client, name| {
        let listed = client.send_command("program_context_list", None).unwrap();
        let registers = listed["registers"].as_array().unwrap();
        assert_eq!(listed["count"], registers.len());
        assert!(registers.contains(&json!({"name":"TMode", "bit_length":1})));
        assert!(registers.contains(&json!({"name":"contextreg", "bit_length":64})));
        assert!(!registers.iter().any(|row| row["name"] == "r0"));

        let initial = get(client, "TMode", "0x3000", Some("0x300f"));
        assert_eq!(initial["ranges"].as_array().unwrap().len(), 1);
        assert_eq!(initial["ranges"][0]["stored"], bits("0x0", "0x0"));
        assert_eq!(initial["ranges"][0]["default"], bits("0x0", "0x1"));
        assert_eq!(initial["ranges"][0]["effective"], bits("0x0", "0x1"));
        let unset = get(client, "REToverride", "0x3000", None);
        assert_eq!(unset["ranges"][0]["default"], bits("0x0", "0x0"));
        assert_eq!(unset["ranges"][0]["effective"], bits("0x0", "0x0"));

        set(client, "LRset", "1", "0x3002", "0x300b");
        let sibling = get(client, "LRset", "0x3000", Some("0x300f"));
        assert_eq!(
            set(client, "TMode", "+0x1", "0x3004", "0x3007")["status"],
            "set"
        );
        set(client, "TMode", "0x0", "0x3008", "0x300b");
        let changed = get(client, "TMode", "0x3000", Some("0x300f"));
        let rows = changed["ranges"].as_array().unwrap();
        assert_eq!(rows.len(), 4, "{changed}");
        assert_eq!(rows[0]["end"], "0x00003003");
        assert_eq!(rows[1]["stored"], bits("0x1", "0x1"));
        // Identical effective zero values still distinguish stored zero from unset.
        assert_eq!(rows[2]["stored"], bits("0x0", "0x1"));
        assert_eq!(rows[3]["stored"], bits("0x0", "0x0"));
        let cleared = clear(client, "TMode", "0x3005", "0x300a");
        assert_eq!(cleared["status"], "cleared");
        assert_eq!(cleared["ranges"][0]["stored"], bits("0x0", "0x0"));
        assert_eq!(cleared["ranges"][0]["effective"], bits("0x0", "0x1"));
        assert_eq!(get(client, "LRset", "0x3000", Some("0x300f")), sibling);
        clear(client, "TMode", "0x3000", "0x300f");
        assert_eq!(get(client, "TMode", "0x3000", Some("0x300f")), initial);
        set(client, "REToverride", "1", "0x3000", "0x3000");
        clear(client, "REToverride", "0x3000", "0x3000");
        assert_eq!(get(client, "REToverride", "0x3000", None), unset);

        // Native context supports unmapped addresses and values beyond JSON integer precision.
        let exact = set(
            client,
            "contextreg",
            "0xfedcba9876543210",
            "0x4000",
            "0x400f",
        );
        assert_eq!(
            exact["ranges"][0]["stored"],
            bits("0xfedcba9876543210", "0xffffffffffffffff")
        );
        let before = get(client, "contextreg", "0x3000", Some("0x400f"));
        for args in [
            json!({"register":"missing", "value":"1", "start":"0x3000", "end":"0x300f"}),
            json!({"register":"r0", "value":"1", "start":"0x3000", "end":"0x300f"}),
            json!({"register":"TMode", "value":"2", "start":"0x3000", "end":"0x300f"}),
            json!({"register":"TMode", "value":"-1", "start":"0x3000", "end":"0x300f"}),
            json!({"register":"TMode", "value":"1", "start":"scratch", "end":"0x300f"}),
            json!({"register":"TMode", "value":"1", "start":"0x3000", "end":"context_overlay:0x300f"}),
            json!({"register":"TMode", "value":"1", "start":"0x300f", "end":"0x3000"}),
            json!({"register":"TMode", "value":"1", "start":"0x3000"}),
        ] {
            let error = client
                .send_command("program_context_set", Some(args))
                .expect_err("invalid context mutation must fail");
            let error = error.downcast_ref::<BridgeCommandError>().unwrap();
            assert_eq!(error.detail["rolled_back"], true);
            assert_eq!(get(client, "contextreg", "0x3000", Some("0x400f")), before);
        }
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(name).unwrap();
        assert_eq!(get(client, "contextreg", "0x3000", Some("0x400f")), before);

        // Test distinct default boundaries even where stored context masks their effect.
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
public class SetContextDefaultBoundaries extends GhidraScript {
    public void run() throws Exception {
        var context = currentProgram.getProgramContext();
        ((DefaultProgramContext) context).setDefaultValue(
            new RegisterValue(currentProgram.getRegister("TMode"), BigInteger.ONE),
            toAddr(0x3004), toAddr(0x3007));
        context.setRegisterValue(toAddr(0x4020), toAddr(0x4020),
            new RegisterValue(context.getBaseContextRegister(),
                new BigInteger("f00000000000000a", 16), new BigInteger("f00000000000000f", 16)));
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        assert_eq!(
            get(client, "contextreg", "0x4020", None)["ranges"][0]["stored"],
            bits("0xf00000000000000a", "0xf00000000000000f")
        );
        for (start, end) in [
            ("0x3000", "0x300f"),
            ("context_overlay:0x3000", "context_overlay:0x300f"),
        ] {
            set(client, "TMode", "1", start, end);
            let observed = get(client, "TMode", start, Some(end));
            let rows = observed["ranges"].as_array().unwrap();
            assert_eq!(rows.len(), 3, "{observed}");
            assert_eq!(rows[0]["default"], bits("0x0", "0x1"));
            assert_eq!(rows[1]["default"], bits("0x1", "0x1"));
            assert_eq!(rows[2]["default"], bits("0x0", "0x1"));
            for row in rows {
                assert_eq!(row["stored"], bits("0x1", "0x1"));
                assert_eq!(row["effective"], bits("0x1", "0x1"));
            }
        }
    });
}

#[test]
#[serial]
fn processor_context_arm_thumb_it_conflicts_and_explicit_redecode() {
    require_ghidra!();
    with_fixture(|client, name| {
        set(client, "TMode", "0", "0x1000", "0x1007");
        set(client, "TMode", "1", "0x2000", "0x2005");
        assert_eq!(
            client.disasm_range("0x1000", "0x2005", None).unwrap()["count"],
            0
        );
        client.define_code("0x1000", Some("0x1007")).unwrap();
        client.define_code("0x2000", Some("0x2005")).unwrap();
        let arm = client.disasm_range("0x1000", "0x1007", None).unwrap();
        let thumb = client.disasm_range("0x2000", "0x2005", None).unwrap();
        assert_eq!(arm["count"], 2, "{arm}");
        assert_eq!(thumb["count"], 3, "{thumb}");
        assert!(
            thumb["instructions"][1]["mnemonic"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("eq"),
            "{thumb}"
        );
        let it = get(client, "condit", "0x2000", Some("0x2005"));
        assert!(
            it["ranges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["stored"]["value"] != "0x0"),
            "{it}"
        );

        // A mapped range beginning before existing instructions must not leave a partial edit.
        let before = get(client, "contextreg", "0x1ff0", Some("0x2005"));
        for command in ["program_context_set", "program_context_clear"] {
            let error = client
                .send_command(
                    command,
                    Some(
                        json!({"register":"TMode", "value":"0", "start":"0x1ff0", "end":"0x2005"}),
                    ),
                )
                .expect_err("existing instructions must reject context changes");
            let error = error.downcast_ref::<BridgeCommandError>().unwrap();
            assert_eq!(error.detail["rolled_back"], true);
            assert_eq!(error.detail["register"], "TMode");
            assert_eq!(error.detail["start"], "0x00001ff0");
            assert_eq!(error.detail["end"], "0x00002005");
            assert!(error.detail["reason"].is_string());
            assert!(error.detail["hint"]
                .as_str()
                .unwrap()
                .contains("listing undefine"));
            assert_eq!(get(client, "contextreg", "0x1ff0", Some("0x2005")), before);
            assert_eq!(
                client.disasm_range("0x2000", "0x2005", None).unwrap(),
                thumb
            );
        }

        client.clear_range("0x2000", "0x2005", None).unwrap();
        clear(client, "TMode", "0x2000", "0x2005");
        let cleared = get(client, "TMode", "0x2000", Some("0x2005"));
        assert_eq!(cleared["ranges"][0]["stored"], bits("0x0", "0x0"));
        assert_eq!(cleared["ranges"][0]["effective"], bits("0x0", "0x1"));
        set(client, "TMode", "1", "0x2000", "0x2005");
        client.define_code("0x2000", Some("0x2005")).unwrap();
        assert_eq!(
            client.disasm_range("0x2000", "0x2005", None).unwrap(),
            thumb
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(name).unwrap();
        assert_eq!(client.disasm_range("0x1000", "0x1007", None).unwrap(), arm);
        assert_eq!(
            client.disasm_range("0x2000", "0x2005", None).unwrap(),
            thumb
        );
        let programs = client.list_programs().unwrap();
        let program = programs["programs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|program| program["name"] == name)
            .unwrap();
        assert_eq!(
            program["analyzed"], false,
            "context and definition must not run analysis"
        );
    });
}
