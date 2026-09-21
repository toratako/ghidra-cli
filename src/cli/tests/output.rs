use super::*;
use clap::ValueEnum;

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
                        Commands::Symbol(SymbolCommands::Externals(opts)) => opts.format,
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
        ["symbol", "entry-points"].as_slice(),
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
            }
        }
    }
}

#[test]
fn single_object_commands_reject_list_options() {
    for command in [
        ["memory", "read", "0x1000", "64"].as_slice(),
        ["program", "info"].as_slice(),
        ["program", "stats"].as_slice(),
    ] {
        for flags in [
            ["--filter", "size>0"].as_slice(),
            ["-f", "size>0"].as_slice(),
            ["--count"].as_slice(),
            ["--limit", "1"].as_slice(),
            ["--offset", "1"].as_slice(),
            ["--sort", "size"].as_slice(),
        ] {
            let error = Cli::try_parse_from(
                ["ghidra-cli"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain(flags.iter().copied()),
            )
            .err()
            .expect("single objects must reject list options");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
    for command in [
        ["memory", "map"],
        ["symbol", "externals"],
        ["symbol", "entry-points"],
    ] {
        Cli::try_parse_from(["ghidra-cli"].into_iter().chain(command).chain([
            "--filter",
            "name~test",
            "--count",
            "--limit",
            "1",
            "--offset",
            "1",
            "--sort",
            "name",
        ]))
        .unwrap();
    }
}
