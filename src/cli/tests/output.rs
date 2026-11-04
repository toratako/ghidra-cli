use super::*;

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
            for command in [["symbol", "externals"], ["function", "list"]] {
                let cli = Cli::try_parse_from([
                    "ghidra-cli",
                    command[0],
                    command[1],
                    "--format",
                    &spelling,
                ])
                .unwrap();
                let format = match cli.command {
                    Commands::Symbol(SymbolCommands::Externals(opts)) => opts.format,
                    Commands::Function(FunctionCommands::List(args)) => args.options.format,
                    _ => panic!("unexpected command"),
                };
                assert_eq!(format, Some(expected));
            }
        }
    }
}

#[test]
fn projection_modes_are_mutually_exclusive() {
    for command in [
        ["function", "list"].as_slice(),
        ["program", "info"].as_slice(),
    ] {
        let error = Cli::try_parse_from(
            ["ghidra-cli"]
                .into_iter()
                .chain(command.iter().copied())
                .chain(["--fields", "name", "--exclude-fields", "size"]),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
