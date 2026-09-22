use super::*;

#[test]
fn equate_values_preserve_all_64_bits_and_reject_truncation() {
    for value in [
        "0",
        "-1",
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
        "-0x1",
    ] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "equate", "create", "FLAG", value]).is_err(),
            "{value}"
        );
    }
}

#[test]
fn bookmark_inputs_and_namespace_destinations_are_exclusive() {
    for args in [
        vec![
            "bookmark",
            "set",
            "0x1000",
            "text",
            "--stdin",
            "--category",
            "Review",
        ],
        vec![
            "bookmark",
            "set",
            "0x1000",
            "--stdin",
            "--text-file",
            "note.txt",
            "--category",
            "Review",
        ],
        vec![
            "bookmark",
            "set",
            "0x1000",
            "text",
            "--text-file",
            "note.txt",
            "--category",
            "Review",
        ],
        vec!["bookmark", "set", "0x1000", "--category", "Review"],
        vec!["bookmark", "delete", "0x1000"],
        vec!["symbol", "set-namespace", "label", "app", "--global"],
        vec!["symbol", "set-namespace", "label"],
    ] {
        assert!(Cli::try_parse_from(["ghidra-cli"].into_iter().chain(args)).is_err());
    }
}
