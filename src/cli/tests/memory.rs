use super::*;

#[test]
fn memory_numeric_inputs_reject_lossy_or_ambiguous_values() {
    for offset in ["0", "0x205", "9223372036854775807", "0X7fffffffffffffff"] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "file-mappings",
            "--file-offset",
            offset,
        ])
        .unwrap();
        let Commands::Memory(MemoryCommands::FileMappings(args)) = cli.command else {
            panic!("expected memory file-mappings");
        };
        assert_eq!(args.file_offset.as_deref(), Some(offset));
    }
    for offset in [
        "-1",
        "9223372036854775808",
        "0x8000000000000000",
        "0x",
        "1.5",
    ] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "file-mappings",
            "--file-offset",
            offset,
        ])
        .is_err());
    }
}
