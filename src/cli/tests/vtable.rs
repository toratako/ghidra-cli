use super::*;

#[test]
fn vtable_requires_an_address_point_count_and_explicit_abi() {
    for args in [
        vec!["--entries", "3", "--abi", "itanium"],
        vec!["Widget::vtable", "--abi", "itanium"],
        vec!["Widget::vtable", "--entries", "3"],
    ] {
        let error = Cli::try_parse_from(["ghidra-cli", "vtable", "read"].into_iter().chain(args))
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
            "vtable",
            "read",
            "bank1:0x4000",
            "--entries",
            count,
            "--abi",
            "msvc",
            "--fields",
            "address,entries",
        ])
        .unwrap();
        let Commands::Vtable(VtableCommands::Read(args)) = cli.command else {
            panic!("expected vtable read");
        };
        assert_eq!(args.target, "bank1:0x4000");
        assert_eq!(args.entries, expected);
        assert_eq!(args.abi, VtableAbi::Msvc);
        assert_eq!(args.encoding, VtableEncoding::Absolute);
        assert!(args.validate().is_ok());
    }
}

#[test]
fn table_read_counts_respect_native_bounds() {
    for count in ["0", "0x10001"] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "vtable",
            "read",
            "0x4000",
            "--entries",
            count,
            "--abi",
            "itanium",
        ])
        .is_err());
    }
}
