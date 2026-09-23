use super::*;

const JOB_ID: &str = "2c7a3b91-f960-4b85-87d7-e90cf7bf0625";

#[test]
fn program_export_requires_output_for_every_format() {
    for format in ["xml", "c", "binary", "gzf", "asm", "hex", "html"] {
        let error = Cli::try_parse_from([
            "ghidra-cli",
            "program",
            "export",
            "sample",
            "--export-format",
            format,
        ])
        .err()
        .expect("export destination is required");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--output <OUTPUT>"));
        for flag in ["-o", "--output"] {
            let cli = Cli::try_parse_from([
                "ghidra-cli",
                "program",
                "export",
                "sample",
                "--export-format",
                format,
                flag,
                "exported.file",
            ])
            .unwrap();
            let Commands::Program(ProgramCommands::Export(args)) = cli.command else {
                panic!("expected program export");
            };
            assert_eq!(args.name, "sample");
            assert_eq!(args.format, format);
            assert_eq!(args.output, "exported.file");
        }
    }
}

#[test]
fn program_export_formats_accept_supported_spellings() {
    for format in ["xml", "c", "binary", "gzf", "asm", "hex", "html"] {
        for spelling in [format.to_string(), format.to_uppercase()] {
            Cli::try_parse_from([
                "ghidra-cli",
                "program",
                "export",
                "sample",
                "--export-format",
                &spelling,
                "-o",
                "exported.file",
            ])
            .unwrap();
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
        vec!["job", "get", JOB_ID],
        vec!["job", "cancel"],
        vec!["job", "cancel", JOB_ID],
        vec!["job", "result", JOB_ID],
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
                    Commands::Job(JobCommands::Result { job_id, project }) => {
                        ("job", "result", Some(job_id), project, None)
                    }
                    Commands::Job(JobCommands::Cancel { job_id, project }) => {
                        ("job", "cancel", job_id, project, None)
                    }
                    _ => panic!("unexpected command: {args:?}"),
                };
                assert_eq!((family, action), (command[0], command[1]), "{args:?}");
                assert_eq!(job_id.as_deref(), command.get(2).copied(), "{args:?}");
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
fn job_get_requires_an_id() {
    let error = Cli::try_parse_from(["ghidra-cli", "job", "get"])
        .err()
        .expect("job get requires an ID");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn analysis_option_set_preserves_typed_input_for_bridge_validation() {
    for value in ["false", "-12", "1.25", "FAST", "path with spaces", ""] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "analysis",
            "option",
            "set",
            "Analyzer.Detail",
            value,
        ])
        .expect("option value should reach the bridge unchanged");
        match cli.command {
            Commands::Analysis(AnalysisCommands::Option(AnalysisOptionCommands::Set(args))) => {
                assert_eq!(args.name, "Analyzer.Detail");
                assert_eq!(args.value, value);
            }
            _ => panic!("expected analysis option set"),
        }
    }
}

#[test]
fn project_archives_have_explicit_operands_independent_of_global_selection() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "--project",
        "default",
        "--program",
        "selected",
        "project",
        "archive",
        "work",
        "--output",
        "work.gar",
    ])
    .unwrap();
    assert!(matches!(cli.command, Commands::Project(ProjectArgs {
        command: ProjectCommands::Archive { name, output },
    }) if name == "work" && output == std::path::Path::new("work.gar")));
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "project",
        "restore",
        "work.gar",
        "work-copy",
        "--projects-dir",
        "copies",
    ])
    .unwrap();
    assert!(matches!(cli.command, Commands::Project(ProjectArgs {
        command: ProjectCommands::Restore { archive, name },
    }) if name == "work-copy" && archive == std::path::Path::new("work.gar")));
    assert_eq!(
        cli.projects_dir.as_deref(),
        Some(std::path::Path::new("copies"))
    );
}

#[test]
fn program_target_operands_are_separate_from_global_context() {
    for action in [
        "open",
        "delete",
        "close",
        "save",
        "info",
        "stats",
        "list-relocations",
        "rebase",
        "export",
    ] {
        let mut argv = vec![
            "ghidra-cli",
            "--program",
            "context",
            "program",
            action,
            "target",
        ];
        if action == "rebase" {
            argv.extend(["--base", "0x400000"]);
        }
        if action == "export" {
            argv.extend(["--export-format", "binary", "--output", "sample.bin"]);
        }
        let parsed = Cli::try_parse_from(argv).unwrap();
        assert_eq!(parsed.program.as_deref(), Some("context"));
        let target = match parsed.command {
            Commands::Program(ProgramCommands::Open(args) | ProgramCommands::Delete(args)) => {
                Some(args.name)
            }
            Commands::Program(ProgramCommands::Close(args) | ProgramCommands::Save(args)) => {
                args.name
            }
            Commands::Program(ProgramCommands::Info(args) | ProgramCommands::Stats(args)) => {
                args.name
            }
            Commands::Program(ProgramCommands::ListRelocations(args)) => args.name,
            Commands::Program(ProgramCommands::Rebase(args)) => args.name,
            Commands::Program(ProgramCommands::Export(args)) => Some(args.name),
            _ => unreachable!(),
        };
        assert_eq!(target.as_deref(), Some("target"));
    }
}

#[test]
fn program_context_commands_can_omit_the_target_operand() {
    for action in [
        "close",
        "save",
        "info",
        "stats",
        "list-relocations",
        "rebase",
    ] {
        let mut argv = vec!["ghidra-cli", "program", action];
        if action == "rebase" {
            argv.extend(["--base", "0x400000"]);
        }
        Cli::try_parse_from(argv).unwrap();
    }
}

#[test]
fn processor_context_uses_register_operand_and_named_bounds() {
    for operation in ["get", "set", "clear"] {
        let mut argv = vec![
            "ghidra-cli",
            "program",
            "context",
            operation,
            "--start",
            "overlay:0x1000",
            "TMode",
            "--program",
            "target",
        ];
        if operation != "get" {
            argv.extend(["--end", "overlay:0x100f"]);
        }
        if operation == "set" {
            argv.extend(["--value", "0x1"]);
        }
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.program.as_deref(), Some("target"));
        let Commands::Program(ProgramCommands::Context(command)) = cli.command else {
            panic!("expected processor context command");
        };
        let (register, start, end) = match command {
            ProgramContextCommands::Get(args) => (args.register, args.start, args.end),
            ProgramContextCommands::Set(args) => {
                assert_eq!(args.value, "0x1");
                (args.register, args.start, Some(args.end))
            }
            ProgramContextCommands::Clear(args) => (args.register, args.start, Some(args.end)),
            _ => unreachable!(),
        };
        assert_eq!(register, "TMode");
        assert_eq!(start, "overlay:0x1000");
        assert_eq!(
            end.as_deref(),
            if operation == "get" {
                None
            } else {
                Some("overlay:0x100f")
            }
        );
    }
}

#[test]
fn processor_context_edits_require_explicit_bounds_and_value() {
    for operation in ["set", "clear"] {
        let mut complete = vec![
            "ghidra-cli",
            "program",
            "context",
            operation,
            "TMode",
            "--start",
            "0x1000",
            "--end",
            "0x100f",
        ];
        if operation == "set" {
            complete.extend(["--value", "1"]);
        }
        for required in ["--start", "--end", "--value"] {
            let Some(index) = complete.iter().position(|arg| *arg == required) else {
                continue;
            };
            let mut argv = complete.clone();
            argv.drain(index..index + 2);
            let error = Cli::try_parse_from(argv)
                .err()
                .expect("context mutations require complete bounds and a value for set");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains(required));
        }
    }
}

#[test]
fn loader_options_preserve_pairs_and_literal_delimiters() {
    let parsed = Cli::try_parse_from([
        "ghidra-cli",
        "program",
        "import",
        "sample.bin",
        "--loader-option",
        "first",
        "path=with:delimiters",
        "--loader-option",
        "second",
        "space in value",
        "--loader-option",
        "blockName",
        "-scratch",
    ])
    .unwrap();
    let Commands::Program(ProgramCommands::Import(args)) = parsed.command else {
        unreachable!();
    };
    assert_eq!(
        args.loader_options,
        [
            "first",
            "path=with:delimiters",
            "second",
            "space in value",
            "blockName",
            "-scratch"
        ]
    );
}
