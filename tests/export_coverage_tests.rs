//! Export receipts describe requested scope and actual artifacts without claiming
//! that decompiled C preserves every function or initialized global.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use serde_json::Value;
use std::path::Path;

#[macro_use]
mod common;

#[test]
fn export_reports_artifacts_and_format_limits() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-export-coverage-")
        .tempdir()
        .expect("export fixture directory");
    let project = directory.path().join("project");
    let binary = directory.path().join("globals.bin");
    let mut bytes = vec![0u8; 24];
    // mov eax, [0x1010]; ret
    bytes[..6].copy_from_slice(&[0xa1, 0x10, 0x10, 0, 0, 0xc3]);
    bytes[16..20].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0x2468_1357u32.to_le_bytes());
    std::fs::write(&binary, &bytes).expect("write raw export fixture");
    let installation = ghidra_cli::config::Config::load()
        .expect("load configuration")
        .get_ghidra_install_dir()
        .expect("Ghidra installation");
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:32:default".to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw export fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program)
        .expect("start export fixture bridge");
    let client = harness.client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;
public class DefineExportCoverageFixture extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getMemory().getBlock(toAddr(0x1000)).setWrite(true);
        createData(toAddr(0x1010), DWordDataType.dataType);
        createLabel(toAddr(0x1010), "referenced_value", true);
        createData(toAddr(0x1014), DWordDataType.dataType);
        createLabel(toAddr(0x1014), "unreferenced_value", true);
        if (!disassemble(toAddr(0x1000))) {
            throw new IllegalStateException("Could not disassemble fixture");
        }
        var function = createFunction(toAddr(0x1000), "read_global");
        function.setReturnType(DWordDataType.dataType, SourceType.USER_DEFINED);
        currentProgram.getMemory().createUninitializedBlock("uninitialized",
            toAddr(0x2000), 32, false);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .expect("define export fixture");

    let c_path = directory.path().join("globals.c");
    // A pre-existing header is not an artifact of the default C export.
    let header = directory.path().join("globals.h");
    std::fs::write(&header, "unrelated header").unwrap();
    let result = common::ghidra(&harness)
        .args(["program", "export", "c", "--output"])
        .arg(c_path.to_str().unwrap())
        .arg("--json")
        .run();
    result.assert_success();
    let result: Value = result.data();
    let c = &result;
    assert_receipt(c, &program, "c", &[&c_path]);
    let c_source = std::fs::read_to_string(&c_path).unwrap();
    assert!(c_source.contains("read_global("), "{c_source}");
    assert!(c_source.contains(" referenced_value;"), "{c_source}");
    assert!(!c_source.contains("unreferenced_value"), "{c_source}");
    assert_eq!(std::fs::read_to_string(header).unwrap(), "unrelated header");
    let limitations = c["limitations"].as_array().unwrap();
    assert!(limitations.iter().any(|item| item
        .as_str()
        .unwrap()
        .contains("do not preserve original data initializers")));
    assert!(limitations.iter().any(|item| item
        .as_str()
        .unwrap()
        .contains("does not verify complete function coverage")));

    let raw_path = directory.path().join("memory.bin");
    let raw = client
        .program_export("binary", Some(raw_path.to_str().unwrap()))
        .expect("export initialized memory");
    assert_receipt(&raw, &program, "binary", &[&raw_path]);
    // Neither the gap nor the uninitialized block is present in raw output.
    assert_eq!(std::fs::read(&raw_path).unwrap(), bytes);
    assert!(raw["limitations"][0]
        .as_str()
        .unwrap()
        .contains("without address gaps"));

    // Exercise both native sidecar naming paths, including a non-.xml filename.
    for name in ["program.xml", "program.dump"] {
        let xml_path = directory.path().join(name);
        let sidecar = directory.path().join(if name.ends_with(".xml") {
            "program.bytes"
        } else {
            "program.dump.bytes"
        });
        std::fs::write(&sidecar, "stale export bytes").unwrap();
        let xml = client
            .program_export("xml", Some(xml_path.to_str().unwrap()))
            .expect("export XML with memory sidecar");
        assert_receipt(&xml, &program, "xml", &[&xml_path, &sidecar]);
        assert_eq!(std::fs::read(&sidecar).unwrap(), bytes);
        let xml_source = std::fs::read_to_string(&xml_path).unwrap();
        assert!(
            xml_source.contains(sidecar.file_name().unwrap().to_str().unwrap()),
            "{xml_source}"
        );
        assert!(xml_source.contains("unreferenced_value"), "{xml_source}");
    }
}

fn assert_receipt(result: &Value, program: &str, format: &str, paths: &[&Path]) {
    assert_eq!(result["status"], "exported");
    assert_eq!(result["format"], format);
    assert_eq!(result["program_path"], format!("/{program}"));
    assert_eq!(result["requested_scope"], "program");
    let artifacts = result["artifacts"].as_array().expect("export artifacts");
    assert_eq!(artifacts.len(), paths.len(), "{result}");
    for (artifact, path) in artifacts.iter().zip(paths) {
        assert_eq!(Path::new(artifact["path"].as_str().unwrap()), *path);
        assert_eq!(artifact["size_bytes"], path.metadata().unwrap().len());
    }
    assert!(result["exporter_messages"].is_array(), "{result}");
    assert!(result["limitations"].is_array(), "{result}");
}
