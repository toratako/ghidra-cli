use super::*;

#[test]
fn structure_inference_uses_variable_selection_and_explicit_evidence_limits() {
    let args = [
        "ghidra-cli",
        "function",
        "var",
        "infer-struct",
        "process",
        "--var",
        "ctx",
    ];
    let cli = Cli::try_parse_from(args.into_iter().chain([
        "--where",
        "kind=parameter AND ordinal=0",
        "--with-accesses",
        "--max-accesses",
        "0x10",
    ]))
    .unwrap();
    let Commands::Function(FunctionCommands::Var(FunctionVarCommands::InferStruct(parsed))) =
        cli.command
    else {
        panic!("expected structure inference");
    };
    assert_eq!(parsed.selection.target, "process");
    assert_eq!(parsed.selection.var_name, "ctx");
    assert_eq!(parsed.max_accesses, Some(16));
    assert!(parsed.with_accesses);
    assert!(Cli::try_parse_from(args.into_iter().chain(["--max-accesses", "1"])).is_err());
    assert!(Cli::try_parse_from(args.into_iter().chain([
        "--with-accesses",
        "--max-accesses",
        "0"
    ]))
    .is_err());
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
            "--member",
            "Read",
            "1",
            "--member",
            "Write",
            "2",
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
        assert_eq!(
            serde_json::to_value(args.members()).unwrap(),
            serde_json::json!([{"name": "Read", "value": "1"}, {"name": "Write", "value": "2"}])
        );
        assert_eq!(args.size, size.unwrap_or("4").parse::<i32>().unwrap());
    }

    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "create",
        "typedef",
        "HeaderPointer",
        "--type",
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
        vec!["enum", "--member", "Read", "1"],
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
        vec!["type", "create", "enum", "Mode", "--member", "Read", "1"],
        vec![
            "type",
            "create",
            "typedef",
            "HeaderAlias",
            "--type",
            "Header",
        ],
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
fn type_resize_accepts_decimal_and_hex_sizes_with_zero_and_java_int_boundaries() {
    for (input, size) in [
        ("0", 0),
        ("64", 64),
        ("010", 10),
        ("0x40", 64),
        ("0X7fffffff", i32::MAX),
    ] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "type",
            "resize",
            "/Draft/Header",
            "--size",
            input,
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Commands::Type(TypeCommands::Resize(args))
            if args.type_name == "/Draft/Header" && args.size == size)
        );
    }
    for size in ["-1", "2147483648", "0x80000000", "0x", "1.5"] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "type", "resize", "/Header", "--size", size])
                .is_err()
        );
    }
}

#[test]
fn bitfield_creation_parses_explicit_storage_and_optional_attributes() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "field",
        "create-bitfield",
        "/Flags",
        "--offset",
        "0x10",
        "--storage-size",
        "0x4",
        "--bit-offset",
        "0",
        "--bit-size",
        "3",
        "--type",
        "uint32_t",
        "--name",
        "mode",
        "--comment",
        "",
    ])
    .unwrap();
    let Commands::Type(TypeCommands::Field(TypeFieldCommands::CreateBitfield(args))) = cli.command
    else {
        panic!("expected bitfield creation");
    };
    assert_eq!(
        (
            args.offset,
            args.storage_size,
            args.bit_offset,
            args.bit_size
        ),
        (16, 4, 0, 3)
    );
    assert_eq!(args.field_type, "uint32_t");
    assert_eq!(args.name.as_deref(), Some("mode"));
    assert_eq!(args.comment.as_deref(), Some(""));
}

#[test]
fn bitfield_edits_require_positive_width_and_an_exact_component_selector() {
    for selector in [["--field", "mode"], ["--ordinal", "1"]] {
        let cli = Cli::try_parse_from(
            ["ghidra-cli", "type", "field", "set", "/Flags"]
                .into_iter()
                .chain(selector)
                .chain(["--bit-size", "4"]),
        )
        .unwrap();
        assert!(matches!(cli.command,
            Commands::Type(TypeCommands::Field(TypeFieldCommands::Set(args)))
                if args.bit_size == Some(4) && args.field_type.is_none()));
    }
    for flags in [
        vec!["--offset", "0", "--bit-size", "4"],
        vec!["--ordinal", "1", "--bit-size", "0"],
        vec!["--ordinal", "1", "--bit-size", "2147483648"],
        vec![
            "--ordinal",
            "1",
            "--bit-size",
            "4",
            "--type",
            "uint",
            "--size",
            "4",
        ],
    ] {
        assert!(Cli::try_parse_from(
            ["ghidra-cli", "type", "field", "set", "/Flags"]
                .into_iter()
                .chain(flags)
        )
        .is_err());
    }
    for (storage_size, bit_size) in [("0", "1"), ("4", "0"), ("2147483648", "1")] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "type",
            "field",
            "create-bitfield",
            "/Flags",
            "--offset",
            "0",
            "--storage-size",
            storage_size,
            "--bit-offset",
            "0",
            "--bit-size",
            bit_size,
            "--type",
            "uint",
        ])
        .is_err());
    }
}

#[test]
fn field_clear_uses_the_shared_component_selector() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "field",
        "clear",
        "/Flags",
        "--ordinal",
        "1",
    ])
    .unwrap();
    assert!(matches!(cli.command,
        Commands::Type(TypeCommands::Field(TypeFieldCommands::Clear(args)))
            if args.selector.ordinal == Some(1)));
    assert!(Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "field",
        "clear",
        "/Flags",
        "--ordinal",
        "1",
        "--field",
        "mode",
    ])
    .is_err());
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

#[test]
fn enum_members_preserve_signed_and_prefixed_values_as_separate_operands() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "create",
        "enum",
        "State",
        "--member",
        "Unknown",
        "-1",
        "--member",
        "Ready",
        "0x10",
        "--member",
        "Failed",
        "-0x2",
    ])
    .unwrap();
    let Commands::Type(TypeCommands::Create(TypeCreateCommands::Enum(args))) = cli.command else {
        panic!("expected enum creation");
    };
    assert_eq!(
        serde_json::to_value(args.members()).unwrap(),
        serde_json::json!([
            {"name": "Unknown", "value": "-1"}, {"name": "Ready", "value": "0x10"},
            {"name": "Failed", "value": "-0x2"}
        ])
    );
    assert!(Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "create",
        "enum",
        "State",
        "--member",
        "Unknown",
    ])
    .is_err());
}

#[test]
fn import_c_requires_one_explicit_source() {
    for source in [
        vec!["--code", "typedef int Id;"],
        vec!["--file", "types.h"],
        vec!["--stdin"],
    ] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "type", "import-c"].into_iter().chain(source))
                .is_ok()
        );
    }
    for source in [
        vec![],
        vec!["--code", "typedef int Id;", "--stdin"],
        vec!["--file", "types.h", "--stdin"],
    ] {
        assert!(
            Cli::try_parse_from(["ghidra-cli", "type", "import-c"].into_iter().chain(source))
                .is_err()
        );
    }
}

#[test]
fn field_sizes_and_ordinals_accept_hexadecimal_literals() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "field",
        "append",
        "/Header",
        "--name",
        "value",
        "--type",
        "int",
        "--size",
        "0x4",
    ])
    .unwrap();
    assert!(matches!(cli.command,
        Commands::Type(TypeCommands::Field(TypeFieldCommands::Append(args)))
            if args.size == Some(4)));
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "field",
        "set",
        "/Header",
        "--ordinal",
        "0x10",
        "--type",
        "int",
        "--size",
        "-0x1",
    ])
    .unwrap();
    assert!(matches!(cli.command,
        Commands::Type(TypeCommands::Field(TypeFieldCommands::Set(args)))
            if args.selector.ordinal == Some(16) && args.size == Some(-1)));
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "create",
        "enum",
        "Mode",
        "--member",
        "Read",
        "1",
        "--size",
        "0x4",
    ])
    .unwrap();
    assert!(matches!(cli.command,
        Commands::Type(TypeCommands::Create(TypeCreateCommands::Enum(args)))
            if args.size == 4));
}
