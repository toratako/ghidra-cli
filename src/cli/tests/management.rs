use super::*;

#[test]
fn program_export_requires_output_for_every_format() {
    for format in ["xml", "c", "binary", "gzf", "asm", "hex", "html"] {
        let error = Cli::try_parse_from(["ghidra-cli", "program", "export", format])
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
                format,
                flag,
                "exported.file",
            ])
            .unwrap();
            let Commands::Program(ProgramCommands::Export(args)) = cli.command else {
                panic!("expected program export");
            };
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
