use super::*;
use crate::format::OutputFormat;
use clap::ValueEnum;

#[test]
fn text_search_accepts_encodings_and_rejects_empty_input() {
    for encoding in [None, Some("utf-16le"), Some("shift_jis")] {
        let mut args = vec!["ghidra-cli", "find", "text", "日本"];
        if let Some(encoding) = encoding {
            args.extend(["--encoding", encoding]);
        }
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Find(FindCommands::Text(args)) = cli.command else {
            panic!("expected text search");
        };
        assert_eq!(args.text, "日本");
        assert_eq!(args.encoding, encoding.unwrap_or("utf-8"));
    }
    for args in [
        vec!["ghidra-cli", "find", "text", ""],
        vec!["ghidra-cli", "find", "text", "needle", "--encoding", ""],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

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
fn output_formats_accept_supported_spellings_and_aliases() {
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
        ("asm", OutputFormat::Asm),
        ("c", OutputFormat::C),
    ] {
        for spelling in [name.to_string(), name.to_uppercase()] {
            assert_eq!(OutputFormat::from_str(&spelling).unwrap(), expected);
            for command in [["program", "imports"], ["function", "list"]] {
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
                        Commands::Program(ProgramCommands::Imports(opts)) => opts.format,
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
fn shared_format_help_lists_supported_choices() {
    for command in [
        ["program", "exports"].as_slice(),
        ["memory", "read"].as_slice(),
    ] {
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
                assert!(!help.contains("Currently rendered as JSON"), "{help}");
            }
        }
    }
}

#[test]
fn unsupported_query_formats_do_not_remove_hex_program_export() {
    for format in ["tree", "hex", "TREE", "HEX"] {
        assert!(OutputFormat::from_str(format).is_err());
        assert!(serde_json::from_str::<OutputFormat>(&format!("\"{format}\"")).is_err());
        for command in [["program", "imports"], ["function", "list"]] {
            let error =
                Cli::try_parse_from(["ghidra-cli", command[0], command[1], "--format", format])
                    .err()
                    .expect("unsupported query format must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        }
    }

    let cli = Cli::try_parse_from(["ghidra-cli", "program", "export", "hex"]).unwrap();
    let Commands::Program(ProgramCommands::Export(args)) = cli.command else {
        panic!("expected program export");
    };
    assert_eq!(args.format, "hex");
}

#[test]
fn management_commands_accept_global_options_at_each_command_level() {
    for command in [
        vec!["bridge", "start"],
        vec!["bridge", "stop"],
        vec!["bridge", "restart"],
        vec!["bridge", "status"],
        vec!["bridge", "ping"],
        vec!["job", "list"],
        vec!["job", "get", "42"],
        vec!["job", "cancel"],
        vec!["job", "cancel", "42"],
    ] {
        for position in 0..=command.len() {
            for output_flag in ["--json", "--pretty"] {
                let mut args = vec!["ghidra-cli"];
                args.extend_from_slice(&command[..position]);
                args.extend([
                    "--project",
                    "test-project",
                    "--program",
                    "sample",
                    output_flag,
                ]);
                args.extend_from_slice(&command[position..]);
                let cli =
                    Cli::try_parse_from(&args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
                assert_eq!(cli.json, output_flag == "--json", "{args:?}");
                assert_eq!(cli.pretty, output_flag == "--pretty", "{args:?}");

                let (family, action, job_id, project, program) = match cli.command {
                    Commands::Bridge(BridgeCommands::Start { project, program }) => {
                        ("bridge", "start", None, project, program)
                    }
                    Commands::Bridge(BridgeCommands::Stop { project }) => {
                        ("bridge", "stop", None, project, None)
                    }
                    Commands::Bridge(BridgeCommands::Restart { project, program }) => {
                        ("bridge", "restart", None, project, program)
                    }
                    Commands::Bridge(BridgeCommands::Status { project }) => {
                        ("bridge", "status", None, project, None)
                    }
                    Commands::Bridge(BridgeCommands::Ping { project }) => {
                        ("bridge", "ping", None, project, None)
                    }
                    Commands::Job(JobCommands::List { project }) => {
                        ("job", "list", None, project, None)
                    }
                    Commands::Job(JobCommands::Get { job_id, project }) => {
                        ("job", "get", Some(job_id), project, None)
                    }
                    Commands::Job(JobCommands::Cancel { job_id, project }) => {
                        ("job", "cancel", job_id, project, None)
                    }
                    _ => panic!("unexpected command: {args:?}"),
                };
                assert_eq!((family, action), (command[0], command[1]), "{args:?}");
                assert_eq!(job_id, command.get(2).map(|_| 42), "{args:?}");
                assert_eq!(
                    project.as_deref().or(cli.project.as_deref()),
                    Some("test-project"),
                    "{args:?}"
                );
                assert_eq!(
                    program.as_deref().or(cli.program.as_deref()),
                    Some("sample"),
                    "{args:?}"
                );
            }
        }
    }
}

#[test]
fn management_commands_reject_old_top_level_names_and_missing_job_id() {
    for command in [
        "start", "stop", "restart", "status", "ping", "jobs", "cancel",
    ] {
        let error = Cli::try_parse_from(["ghidra-cli", command])
            .err()
            .expect("old top-level command must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    let error = Cli::try_parse_from(["ghidra-cli", "job", "get"])
        .err()
        .expect("job get requires an ID");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
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
