use super::*;
use crate::format::OutputFormat;
use clap::ValueEnum;

#[test]
fn instruction_search_accepts_ranges_and_rejects_empty_patterns() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "find",
        "instruction",
        "mov",
        "--start",
        "1000",
        "--end",
        "2000",
        "--case-sensitive",
        "--limit",
        "0",
    ])
    .unwrap();
    let Commands::Find(FindCommands::Instruction(args)) = cli.command else {
        panic!("expected instruction search");
    };
    assert_eq!(args.start.as_deref(), Some("1000"));
    assert_eq!(args.end.as_deref(), Some("2000"));
    assert!(args.case_sensitive);
    assert_eq!(args.options.limit, Some(0));
    assert!(Cli::try_parse_from(["ghidra-cli", "find", "instruction", ""]).is_err());
}

#[test]
fn disasm_end_conflicts_with_instruction_count() {
    for target in [vec!["main"], vec!["--target", "main"]] {
        let mut args = vec!["ghidra-cli", "disasm"];
        args.extend(target);
        args.extend(["--end", "2000"]);
        let cli = Cli::try_parse_from(&args).unwrap();
        let Commands::Disasm(disasm) = cli.command else {
            panic!("expected disasm");
        };
        assert_eq!(disasm.end.as_deref(), Some("2000"));
        for flag in ["-n", "--instructions"] {
            let mut conflict = args.clone();
            conflict.extend([flag, "10"]);
            let error = Cli::try_parse_from(conflict)
                .err()
                .expect("conflicting bounds must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }
}

#[test]
fn query_help_lists_only_routed_types() {
    for help_flag in ["-h", "--help"] {
        let help = Cli::try_parse_from(["ghidra-cli", "query", help_flag])
            .err()
            .expect("expected help");
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(help
            .to_string()
            .contains("[possible values: functions, strings, imports, exports, memory]"));
    }
    for data_type in ["functions", "strings", "imports", "exports", "memory"] {
        Cli::try_parse_from(["ghidra-cli", "query", data_type]).unwrap();
    }
    for unsupported in ["symbols", "xrefs", "sections", "function", "FUNCTIONS"] {
        let error = Cli::try_parse_from(["ghidra-cli", "query", unsupported])
            .err()
            .expect("unsupported query type must fail before bridge startup");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
}

#[test]
fn output_formats_keep_existing_spellings_and_aliases() {
    for (name, expected) in [
        ("full", OutputFormat::Full),
        ("compact", OutputFormat::Compact),
        ("minimal", OutputFormat::Minimal),
        ("json", OutputFormat::Json),
        ("json-compact", OutputFormat::JsonCompact),
        ("json-stream", OutputFormat::JsonStream),
        ("ndjson", OutputFormat::JsonStream),
        ("csv", OutputFormat::Csv),
        ("tsv", OutputFormat::Tsv),
        ("table", OutputFormat::Table),
        ("ids", OutputFormat::Ids),
        ("count", OutputFormat::Count),
        ("tree", OutputFormat::Tree),
        ("hex", OutputFormat::Hex),
        ("asm", OutputFormat::Asm),
        ("c", OutputFormat::C),
    ] {
        for spelling in [name.to_string(), name.to_uppercase()] {
            assert_eq!(OutputFormat::from_str(&spelling).unwrap(), expected);
            for command in [["query", "functions"], ["function", "list"]] {
                for flag in ["-o", "--format"] {
                    let cli = Cli::try_parse_from([
                        "ghidra-cli",
                        command[0],
                        command[1],
                        flag,
                        &spelling,
                    ])
                    .unwrap();
                    let format = match cli.command {
                        Commands::Query(args) => args.format,
                        Commands::Function(FunctionCommands::List(args)) => args.options.format,
                        _ => panic!("unexpected command"),
                    };
                    assert_eq!(format, Some(expected));
                }
            }
        }
    }
}

#[test]
fn shared_format_help_lists_choices_and_legacy_rendering() {
    for command in [["query"].as_slice(), ["memory", "read"].as_slice()] {
        for flag in ["-h", "--help"] {
            let help = Cli::try_parse_from(
                ["ghidra-cli"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain([flag]),
            )
            .err()
            .expect("expected help")
            .to_string();
            for value in OutputFormat::value_variants() {
                let possible = value.to_possible_value().unwrap();
                assert!(help.contains(possible.get_name()), "{help}");
            }
            if flag == "--help" {
                assert!(help.contains("alias: ndjson"), "{help}");
                assert!(help.contains("Currently rendered as JSON"), "{help}");
            }
        }
    }
}

#[test]
fn analyzer_set_parses_explicit_boolean() {
    for (value, expected) in [("true", true), ("false", false)] {
        let cli = Cli::try_parse_from(["ghidra-cli", "analyzer", "set", "ASCII Strings", value])
            .expect("analyzer set should accept an explicit boolean");
        match cli.command {
            Commands::Analyzer(AnalyzerCommands::Set(args)) => {
                assert_eq!(args.name, "ASCII Strings");
                assert_eq!(args.enabled, expected);
            }
            _ => panic!("expected analyzer set command"),
        }
    }
}

#[test]
fn analyzer_set_requires_valid_boolean() {
    let missing = Cli::try_parse_from(["ghidra-cli", "analyzer", "set", "ASCII Strings"])
        .err()
        .expect("expected argument error");
    assert_eq!(
        missing.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    let invalid = Cli::try_parse_from(["ghidra-cli", "analyzer", "set", "ASCII Strings", "maybe"])
        .err()
        .expect("expected argument error");
    assert_eq!(invalid.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn analyzer_set_help_is_available() {
    let help = Cli::try_parse_from(["ghidra-cli", "analyzer", "set", "--help"])
        .err()
        .expect("expected argument error");
    assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    assert!(help.to_string().contains("<ENABLED>"));
}

#[test]
fn parses_decompile_target_flag() {
    let cli = Cli::try_parse_from(["ghidra-cli", "decompile", "--target", "FUN_00401000"])
        .expect("decompile --target should parse");
    match cli.command {
        Commands::Decompile(args) => assert_eq!(args.resolved_target(), "FUN_00401000"),
        _ => panic!("expected decompile command"),
    }
}

#[test]
fn parses_function_get_positional_target() {
    let cli = Cli::try_parse_from(["ghidra-cli", "function", "get", "main"])
        .expect("function get positional target should parse");
    match cli.command {
        Commands::Function(FunctionCommands::Get(args)) => {
            assert_eq!(args.resolved_target(), "main");
        }
        _ => panic!("expected function get command"),
    }
}
