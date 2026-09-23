use super::*;

#[test]
fn vtable_requires_an_address_point_count_and_explicit_abi() {
    for args in [
        vec!["--entries", "3", "--abi", "itanium"],
        vec!["Widget::vtable", "--abi", "itanium"],
        vec!["Widget::vtable", "--entries", "3"],
    ] {
        let error = Cli::try_parse_from(
            ["ghidra-cli", "memory", "read-vtable"]
                .into_iter()
                .chain(args),
        )
        .err()
        .expect("vtable layout operands must be explicit");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
    for (count, expected) in [("010", 10), ("0x10", 16)] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "read-vtable",
            "bank1:0x4000",
            "--entries",
            count,
            "--abi",
            "msvc",
            "--fields",
            "address,entries",
        ])
        .unwrap();
        let Commands::Memory(MemoryCommands::ReadVtable(args)) = cli.command else {
            panic!("expected memory read-vtable");
        };
        assert_eq!(args.target, "bank1:0x4000");
        assert_eq!(args.entries, expected);
        assert_eq!(args.abi, VtableAbi::Msvc);
        assert_eq!(args.encoding, VtableEncoding::Absolute);
        assert!(args.validate().is_ok());
    }
}

#[test]
fn address_table_search_defaults_and_numeric_operands_are_unambiguous() {
    let cli = Cli::try_parse_from(["ghidra-cli", "find", "address-tables"]).unwrap();
    let Commands::Find(FindCommands::AddressTables(args)) = cli.command else {
        panic!("expected find address-tables");
    };
    assert_eq!(args.min_entries, 3);
    assert_eq!(args.alignment, None);
    assert_eq!(args.start, None);
    assert_eq!(args.end, None);

    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "find",
        "address-tables",
        "--min-entries",
        "010",
        "--alignment",
        "0x8",
        "--start",
        "bank1:0x1000",
        "--end",
        "table_end",
    ])
    .unwrap();
    let Commands::Find(FindCommands::AddressTables(args)) = cli.command else {
        panic!("expected find address-tables");
    };
    assert_eq!(args.min_entries, 10);
    assert_eq!(args.alignment, Some(8));
    assert_eq!(args.start.as_deref(), Some("bank1:0x1000"));
    assert_eq!(args.end.as_deref(), Some("table_end"));
}

#[test]
fn table_read_and_detector_counts_respect_native_bounds() {
    for count in ["0", "0x10001"] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "memory",
            "read-vtable",
            "0x4000",
            "--entries",
            count,
            "--abi",
            "itanium",
        ])
        .is_err());
    }
    for (option, value) in [
        ("--min-entries", "1"),
        ("--min-entries", "0x80000000"),
        ("--alignment", "0"),
        ("--alignment", "9"),
    ] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "find", "address-tables", option, value,]).is_err()
        );
    }
}
