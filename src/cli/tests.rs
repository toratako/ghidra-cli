use super::*;
use clap::{CommandFactory, ValueEnum};

#[test]
fn byte_search_accepts_regex_without_changing_literal_defaults() {
    for args in [
        vec!["ghidra-cli", "find", "bytes", "--regex", r"\x48\x8b.{4}"],
        vec!["ghidra-cli", "find", "bytes", r"\x48\x8b.{4}", "--regex"],
    ] {
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Find(FindCommands::Bytes(args)) = cli.command else {
            panic!("expected byte search");
        };
        assert!(args.regex);
        assert_eq!(args.hex, r"\x48\x8b.{4}");
    }
    let cli = Cli::try_parse_from(["ghidra-cli", "find", "bytes", "48 8b"]).unwrap();
    assert!(matches!(cli.command, Commands::Find(FindCommands::Bytes(args)) if !args.regex));
    for args in [
        vec!["ghidra-cli", "find", "string", "--regex", "needle"],
        vec!["ghidra-cli", "find", "text", "--regex", "needle"],
        vec![
            "ghidra-cli",
            "find",
            "bytes",
            "--regex",
            ".",
            "--encoding",
            "utf-8",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

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
        "0x1000",
        "--end",
        "0x2000",
        "--case-sensitive",
        "--limit",
        "0",
    ])
    .unwrap();
    let Commands::Find(FindCommands::Instruction(args)) = cli.command else {
        panic!("expected instruction search");
    };
    assert_eq!(args.start.as_deref(), Some("0x1000"));
    assert_eq!(args.end.as_deref(), Some("0x2000"));
    assert!(args.case_sensitive);
    assert_eq!(args.options.limit, Some(0));
    assert!(Cli::try_parse_from(["ghidra-cli", "find", "instruction", ""]).is_err());
}

#[test]
fn disassembly_uses_limit_and_rejects_removed_instruction_counts() {
    for target in [vec!["main"], vec!["--target", "main"]] {
        let mut args = vec!["ghidra-cli", "disassemble"];
        args.extend(target);
        args.extend(["--end", "0x2000", "--limit", "12"]);
        let cli = Cli::try_parse_from(&args).unwrap();
        let Commands::Disasm(disasm) = cli.command else {
            panic!("expected disasm");
        };
        assert_eq!(disasm.end.as_deref(), Some("0x2000"));
        assert_eq!(disasm.options.limit, Some(12));
    }
    for limit in ["0", "12"] {
        let cli =
            Cli::try_parse_from(["ghidra-cli", "disassemble", "0x1000", "--limit", limit]).unwrap();
        assert!(
            matches!(cli.command, Commands::Disasm(args) if args.options.limit == Some(limit.parse().unwrap()))
        );
    }
    for flag in ["-n", "--instructions"] {
        let error = Cli::try_parse_from(["ghidra-cli", "disassemble", "0x1000", flag, "10"])
            .err()
            .expect("removed instruction count must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
    let cli = Cli::try_parse_from(["ghidra-cli", "disassemble", "main", "--count"]).unwrap();
    assert!(matches!(cli.command, Commands::Disasm(args) if args.options.count));
}

#[test]
fn define_code_accepts_positional_targets_and_bounds_without_query_options() {
    for target in ["entry", "0x1000"] {
        for end in [None, Some("0x2000")] {
            let mut args = vec!["ghidra-cli", "define-code", target];
            if let Some(end) = end {
                args.extend(["--end", end]);
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let Commands::DefineCode(args) = cli.command else {
                panic!("expected define-code")
            };
            assert_eq!(args.target, target);
            assert_eq!(args.end.as_deref(), end);
        }
    }
    assert!(Cli::try_parse_from(["ghidra-cli", "disassemble-at", "0x1000"]).is_err());
    for flags in [
        vec!["--limit", "1"],
        vec!["-n", "1"],
        vec!["--instructions", "1"],
        vec!["--count"],
        vec!["--count", "2"],
        vec!["--filter", "mnemonic=RET"],
        vec!["--sort", "address"],
        vec!["--offset", "1"],
        vec!["--fields", "address"],
        vec!["--format", "asm"],
    ] {
        assert!(Cli::try_parse_from(
            ["ghidra-cli", "define-code", "0x1000"]
                .into_iter()
                .chain(flags)
        )
        .is_err());
    }
}

#[test]
fn mutation_targets_require_one_positional_without_target_flag_compatibility() {
    for command in [vec!["function", "delete"], vec!["define-code"]] {
        for target in ["entry", "0x1000"] {
            let cli = Cli::try_parse_from(
                ["ghidra-cli"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain(["--program", "sample", target, "--project", "project"]),
            )
            .unwrap();
            let (actual, program, project) = match cli.command {
                Commands::Function(FunctionCommands::Delete(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::DefineCode(args) => (args.target, args.program, args.project),
                _ => panic!("unexpected command"),
            };
            assert_eq!(actual, target);
            assert_eq!(program.as_deref(), Some("sample"));
            assert_eq!(project.as_deref(), Some("project"));
        }
        let missing =
            Cli::try_parse_from(["ghidra-cli"].into_iter().chain(command.iter().copied()))
                .err()
                .expect("positional target must be required");
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for args in [
            vec!["--target", "entry"],
            vec!["--target=entry"],
            vec!["entry", "--target", "entry"],
            vec!["entry", "--target", "other"],
            vec!["--target", "entry", "other"],
            vec!["entry", "other"],
        ] {
            let error = Cli::try_parse_from(
                ["ghidra-cli"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain(args),
            )
            .err()
            .expect("removed target flag or second target must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
        for flag in ["-h", "--help"] {
            let help = Cli::try_parse_from(
                ["ghidra-cli"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain([flag]),
            )
            .err()
            .expect("expected help");
            assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
            let help = help.to_string();
            assert!(help.contains("<TARGET>"), "{help}");
            assert!(!help.contains("--target"), "{help}");
        }
    }
}

#[test]
fn output_formats_accept_supported_spellings() {
    for (name, expected) in [
        ("full", OutputFormat::Full),
        ("compact", OutputFormat::Compact),
        ("minimal", OutputFormat::Minimal),
        ("json", OutputFormat::Json),
        ("json-compact", OutputFormat::JsonCompact),
        ("ndjson", OutputFormat::JsonStream),
        ("csv", OutputFormat::Csv),
        ("tsv", OutputFormat::Tsv),
        ("table", OutputFormat::Table),
        ("asm", OutputFormat::Asm),
        ("c", OutputFormat::C),
    ] {
        for spelling in [name.to_string(), name.to_uppercase()] {
            assert_eq!(spelling.parse::<OutputFormat>().unwrap(), expected);
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
                assert!(help.contains("ndjson"), "{help}");
                assert!(!help.contains("json-stream"), "{help}");
                assert!(!help.contains("Currently rendered as JSON"), "{help}");
            }
        }
    }
}

#[test]
fn program_export_formats_accept_only_canonical_names() {
    for format in ["json", "cpp", "bin", "ascii"] {
        for spelling in [format.to_string(), format.to_uppercase()] {
            let error = Cli::try_parse_from(["ghidra-cli", "program", "export", &spelling])
                .err()
                .expect("removed export formats must fail");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        }
    }
    for format in ["xml", "c", "binary", "gzf", "asm", "hex", "html"] {
        for spelling in [format.to_string(), format.to_uppercase()] {
            Cli::try_parse_from(["ghidra-cli", "program", "export", &spelling]).unwrap();
        }
    }
}

#[test]
fn unsupported_query_formats_do_not_remove_hex_program_export() {
    for format in ["tree", "hex", "ids", "count", "TREE", "HEX", "IDS", "COUNT"] {
        assert!(format.parse::<OutputFormat>().is_err());
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
fn clear_defaults_to_clear_only_and_rejects_to_data_flag() {
    for disasm_at in [None, Some("0x1000")] {
        let mut command = vec!["ghidra-cli", "clear", "0x1000:0x1010"];
        if let Some(address) = disasm_at {
            command.extend(["--disassemble-at", address]);
        }
        let cli = Cli::try_parse_from(&command).unwrap();
        let Commands::Clear(args) = cli.command else {
            panic!("expected clear");
        };
        assert_eq!(args.range, "0x1000:0x1010");
        assert_eq!(args.disasm_at.as_deref(), disasm_at);

        command.push("--to-data");
        let error = Cli::try_parse_from(command)
            .err()
            .expect("obsolete clear flag must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}

#[test]
fn type_creation_parses_struct_enum_and_typedef_arguments() {
    let cli = Cli::try_parse_from(["ghidra-cli", "type", "create", "struct", "Header"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Type(TypeCommands::Create(TypeCreateCommands::Struct(args)))
            if args.name == "Header"
    ));

    for size in [None, Some("1"), Some("2"), Some("4"), Some("8")] {
        let mut args = vec![
            "ghidra-cli",
            "type",
            "create",
            "enum",
            "Mode",
            "--values",
            "Read=1,Write=2",
        ];
        if let Some(size) = size {
            args.extend(["--size", size]);
        }
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Type(TypeCommands::Create(TypeCreateCommands::Enum(args))) = cli.command
        else {
            panic!("expected enum creation");
        };
        assert_eq!(args.name, "Mode");
        assert_eq!(args.values, "Read=1,Write=2");
        assert_eq!(args.size, size.unwrap_or("4").parse::<i32>().unwrap());
    }

    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "create",
        "typedef",
        "HeaderPointer",
        "Header *",
    ])
    .unwrap();
    let Commands::Type(TypeCommands::Create(TypeCreateCommands::Typedef(args))) = cli.command
    else {
        panic!("expected typedef creation");
    };
    assert_eq!(args.name, "HeaderPointer");
    assert_eq!(args.base_type, "Header *");
}

#[test]
fn type_creation_requires_kind_and_arguments_without_legacy_aliases() {
    assert!(Cli::try_parse_from(["ghidra-cli", "type", "create"]).is_err());
    for args in [
        vec!["struct"],
        vec!["enum"],
        vec!["enum", "Mode"],
        vec!["enum", "--values", "Read=1"],
        vec!["typedef"],
        vec!["typedef", "HeaderAlias"],
    ] {
        let error = Cli::try_parse_from(["ghidra-cli", "type", "create"].into_iter().chain(args))
            .err()
            .expect("type creation requires its operands");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
    for args in [
        vec!["create", "Header"],
        vec!["create-enum", "Mode", "--values", "Read=1"],
        vec!["typedef", "HeaderAlias", "Header"],
    ] {
        let error = Cli::try_parse_from(["ghidra-cli", "type"].into_iter().chain(args))
            .err()
            .expect("legacy type creation syntax must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}

#[test]
fn type_creation_accepts_global_options_at_each_command_level() {
    for command in [
        vec!["type", "create", "struct", "Header"],
        vec!["type", "create", "enum", "Mode", "--values", "Read=1"],
        vec!["type", "create", "typedef", "HeaderAlias", "Header"],
    ] {
        for position in [0, 1, 2, 3, command.len()] {
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
                let (kind, project, program) = match cli.command {
                    Commands::Type(TypeCommands::Create(TypeCreateCommands::Struct(args))) => {
                        ("struct", args.project, args.program)
                    }
                    Commands::Type(TypeCommands::Create(TypeCreateCommands::Enum(args))) => {
                        ("enum", args.project, args.program)
                    }
                    Commands::Type(TypeCommands::Create(TypeCreateCommands::Typedef(args))) => {
                        ("typedef", args.project, args.program)
                    }
                    _ => panic!("unexpected command: {args:?}"),
                };
                assert_eq!(kind, command[2]);
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
fn analyzer_run_is_rejected_without_a_compatibility_alias() {
    for namespace in ["analyzer", "analysis-control"] {
        let error = Cli::try_parse_from(["ghidra-cli", namespace, "run"])
            .err()
            .expect("removed analysis command must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
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

#[test]
fn canonical_commands_parse_without_aliases() {
    for args in [
        vec!["xref", "to", "main"],
        vec!["xref", "from", "main"],
        vec!["string", "list"],
        vec!["string", "refs", "hello"],
        vec!["disassemble", "main"],
        vec!["function", "disassemble", "main"],
        vec!["define-code", "0x1000"],
        vec!["find", "string", "hello"],
        vec!["graph", "callers", "main"],
        vec!["graph", "callees", "main"],
        vec!["type", "import-c", "typedef int Word;"],
        vec!["function", "list"],
        vec!["function", "get", "main"],
        vec!["type", "delete", "Word"],
        vec!["tag", "rename", "old", "new"],
        vec!["analyzer", "list"],
        vec!["analyze"],
        vec!["decompile", "main"],
    ] {
        Cli::try_parse_from(["ghidra-cli"].into_iter().chain(args.iter().copied()))
            .unwrap_or_else(|error| panic!("{args:?}: {error}"));
    }
}

#[test]
fn removed_command_names_are_rejected() {
    for (namespace, removed) in [
        (
            None,
            vec![
                "prog",
                "programs",
                "fn",
                "func",
                "functions",
                "strings",
                "str",
                "sym",
                "symbols",
                "mem",
                "x-ref",
                "xrefs",
                "crossref",
                "crossrefs",
                "types",
                "tags",
                "analysis-control",
                "comments",
                "search",
                "callgraph",
                "cg",
                "decomp",
                "dec",
                "disasm",
                "dis",
                "disasm-at",
                "scripts",
                "analysis",
            ],
        ),
        (Some("program"), vec!["ls"]),
        (
            Some("function"),
            vec!["ls", "show", "detail", "disasm", "dis"],
        ),
        (Some("string"), vec!["ls", "references", "xrefs"]),
        (Some("symbol"), vec!["ls"]),
        (Some("xref"), vec!["list"]),
        (Some("type"), vec!["ls", "import", "parse-c", "rm", "mv"]),
        (Some("tag"), vec!["ls", "show", "rm", "mv"]),
        (Some("analyzer"), vec!["ls"]),
        (Some("comment"), vec!["ls"]),
        (Some("find"), vec!["str", "strings"]),
        (
            Some("graph"),
            vec!["called-by", "incoming", "calls-to", "outgoing"],
        ),
    ] {
        for name in removed {
            let args: Vec<_> = ["ghidra-cli"]
                .into_iter()
                .chain(namespace)
                .chain([name])
                .collect();
            let error = Cli::try_parse_from(&args)
                .err()
                .expect("removed command must fail");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{args:?}: {error}"
            );
        }
    }
}

#[test]
fn canonical_options_parse_and_removed_options_are_rejected() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "import",
        "sample.bin",
        "--language",
        "x86:LE:32:default",
        "--compiler-spec",
        "gcc",
    ])
    .unwrap();
    let Commands::Import(args) = cli.command else {
        panic!("expected import")
    };
    assert_eq!(args.language.as_deref(), Some("x86:LE:32:default"));
    assert_eq!(args.compiler_spec.as_deref(), Some("gcc"));
    let cli =
        Cli::try_parse_from(["ghidra-cli", "type", "apply", "0x1000", "int", "--force"]).unwrap();
    let Commands::Type(TypeCommands::Apply(args)) = cli.command else {
        panic!("expected type apply")
    };
    assert!(args.force);

    for args in [
        vec!["import", "sample.bin", "--processor", "x86:LE:32:default"],
        vec!["import", "sample.bin", "--cspec", "gcc"],
        vec!["type", "apply", "0x1000", "int", "--clear-conflicting"],
        vec!["clear", "0x1000:0x1010", "--disasm-at", "0x1000"],
    ] {
        let error = Cli::try_parse_from(["ghidra-cli"].into_iter().chain(args.iter().copied()))
            .err()
            .expect("removed option must fail");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{args:?}: {error}"
        );
    }
    let help = Cli::try_parse_from(["ghidra-cli", "type", "apply", "--help"])
        .err()
        .unwrap()
        .to_string();
    assert!(help.contains("including instructions"), "{help}");
}

#[test]
fn json_stream_format_is_rejected() {
    for name in ["json-stream", "JSON-STREAM"] {
        assert!(name.parse::<OutputFormat>().is_err());
        assert!(serde_json::from_str::<OutputFormat>(&format!("\"{name}\"")).is_err());
        let error = Cli::try_parse_from(["ghidra-cli", "function", "list", "--format", name])
            .err()
            .expect("old format name must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
}

#[test]
fn command_tree_has_no_command_or_option_aliases() {
    fn check(command: &clap::Command) {
        assert_eq!(
            command.get_all_aliases().count(),
            0,
            "{}",
            command.get_name()
        );
        assert_eq!(
            command.get_all_short_flag_aliases().count(),
            0,
            "{}",
            command.get_name()
        );
        assert_eq!(
            command.get_all_long_flag_aliases().count(),
            0,
            "{}",
            command.get_name()
        );
        for arg in command.get_arguments() {
            assert!(
                arg.get_all_aliases().unwrap_or_default().is_empty(),
                "{}: {}",
                command.get_name(),
                arg.get_id()
            );
            assert!(
                arg.get_all_short_aliases().unwrap_or_default().is_empty(),
                "{}: {}",
                command.get_name(),
                arg.get_id()
            );
        }
        for subcommand in command.get_subcommands() {
            check(subcommand);
        }
    }
    let mut command = Cli::command();
    command.build();
    check(&command);
}
