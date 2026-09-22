use super::*;

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
fn type_creation_requires_kind_and_arguments() {
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
fn type_category_requires_a_path_and_exposes_queries_only_for_lists() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "category",
        "list",
        "/Protocol",
        "--filter",
        "type_count>0",
        "--sort",
        "name",
        "--fields",
        "path",
    ])
    .unwrap();
    assert!(matches!(cli.command,
        Commands::Type(TypeCommands::Category(TypeCategoryCommands::List(args)))
            if args.path == "/Protocol" && args.options.fields.as_deref() == Some("path")));
    assert!(Cli::try_parse_from(["ghidra-cli", "type", "category", "list"]).is_err());
    for operation in ["create", "delete"] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "type",
            "category",
            operation,
            "/Draft",
            "--filter",
            "name=Draft",
        ])
        .is_err());
    }
}
