use super::*;

#[test]
fn equate_values_preserve_all_64_bits_and_reject_truncation() {
    for value in [
        "0",
        "-1",
        "-0x1",
        "+0x1",
        "-0x8000000000000000",
        "+1",
        "-9223372036854775808",
        "9223372036854775807",
        "0xffffffffffffffff",
        "0X8000000000000000",
    ] {
        let cli = Cli::try_parse_from(["ghidra-cli", "equate", "create", "FLAG", value]).unwrap();
        let Commands::Equate(EquateCommands::Create(args)) = cli.command else {
            panic!("expected equate create");
        };
        assert_eq!(args.value, value);
    }
    for value in [
        "9223372036854775808",
        "-9223372036854775809",
        "0x10000000000000000",
        "1.5",
        "0x",
        "-0x8000000000000001",
    ] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "equate", "create", "FLAG", value]).is_err(),
            "{value}"
        );
    }
}

#[test]
fn annotation_mutations_require_one_text_source() {
    for command in [
        vec!["ghidra-cli", "comment", "set", "0x1000"],
        vec![
            "ghidra-cli",
            "bookmark",
            "set",
            "0x1000",
            "--category",
            "Review",
        ],
    ] {
        for source in [
            vec!["--text", ""],
            vec!["--file", "note.txt"],
            vec!["--stdin"],
        ] {
            assert!(Cli::try_parse_from(command.iter().copied().chain(source)).is_ok());
        }
        for sources in [
            vec![],
            vec!["--text", "text", "--stdin"],
            vec!["--stdin", "--file", "note.txt"],
            vec!["--text", "text", "--file", "note.txt"],
        ] {
            assert!(Cli::try_parse_from(command.iter().copied().chain(sources)).is_err());
        }
    }
}

#[test]
fn bookmark_identity_and_namespace_destination_are_required() {
    for args in [
        vec!["bookmark", "delete", "0x1000"],
        vec![
            "symbol",
            "set-namespace",
            "label",
            "--namespace",
            "app",
            "--global",
        ],
        vec!["symbol", "set-namespace", "label"],
    ] {
        assert!(Cli::try_parse_from(["ghidra-cli"].into_iter().chain(args)).is_err());
    }
}
