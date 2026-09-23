use super::*;

fn parse_block_create(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(
        [
            "ghidra-cli",
            "memory",
            "block",
            "create",
            ".ram",
            "--start",
            "ram:0x1000",
            "--size",
        ]
        .into_iter()
        .chain(args.iter().copied()),
    )
}

#[test]
fn block_creation_requires_explicit_initialization_and_permissions() {
    for args in [
        vec!["64", "--permissions", "rw"],
        vec!["64", "--uninitialized"],
        vec![
            "64",
            "--uninitialized",
            "--fill",
            "0",
            "--permissions",
            "rw",
        ],
    ] {
        assert!(parse_block_create(&args).is_err(), "{args:?}");
    }
    for (initialization, uninitialized, fill) in [
        (vec!["--uninitialized"], true, None),
        (vec!["--fill", "0x00"], false, Some(0)),
        (vec!["--fill", "255"], false, Some(255)),
    ] {
        let cli = parse_block_create(
            &["64", "--permissions", "wr"]
                .into_iter()
                .chain(initialization)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let Commands::Memory(MemoryCommands::Block(MemoryBlockCommands::Create(args))) =
            cli.command
        else {
            panic!("expected memory block create");
        };
        assert_eq!(args.size, 64);
        assert_eq!(args.uninitialized, uninitialized);
        assert_eq!(args.fill, fill);
        assert_eq!(args.permissions, "rw");
        assert!(!args.volatile);
        assert!(args.overlay.is_none());
    }
}

#[test]
fn memory_numeric_inputs_reject_lossy_or_ambiguous_values() {
    for size in ["0", "-1", "0x100", "9223372036854775808", "1.5"] {
        assert!(parse_block_create(&[size, "--uninitialized", "--permissions", "rw"]).is_err());
    }
    for fill in ["256", "0x100", "-1", "1.5"] {
        assert!(parse_block_create(&["64", "--fill", fill, "--permissions", "rw"]).is_err());
    }
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

#[test]
fn block_attribute_edits_require_unambiguous_replacement_values() {
    for permissions in ["", "rr", "rwq", "RW", "none+r"] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "block",
            "set-permissions",
            "ram:0x1000",
            "--permissions",
            permissions,
        ])
        .is_err());
    }
    assert!(Cli::try_parse_from([
        "ghidra-cli",
        "memory",
        "block",
        "set-volatile",
        "ram:0x1000",
    ])
    .is_err());
    for value in ["true", "false"] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "block",
            "set-volatile",
            "ram:0x1000",
            "--value",
            value,
        ])
        .unwrap();
        let Commands::Memory(MemoryCommands::Block(MemoryBlockCommands::SetVolatile(args))) =
            cli.command
        else {
            panic!("expected set-volatile");
        };
        assert_eq!(args.value, value == "true");
    }
}
