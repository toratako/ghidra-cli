use super::*;

#[test]
fn virtual_callers_separates_callee_vtable_and_optional_caller_scope() {
    for (abi, expected_abi) in [("itanium", VtableAbi::Itanium), ("msvc", VtableAbi::Msvc)] {
        for within in [None, Some("dispatch")] {
            let mut argv = vec![
                "ghidra-cli",
                "find",
                "virtual-callers",
                "Widget::draw",
                "--vtable",
                "overlay:0x401020",
                "--entries",
                "010",
                "--abi",
                abi,
                "--project",
                "selected",
                "--program",
                "sample",
                "--limit",
                "0",
            ];
            if let Some(within) = within {
                argv.extend(["--within", within]);
            }
            let cli = Cli::try_parse_from(argv).unwrap();
            let Commands::Find(FindCommands::VirtualCallers(args)) = cli.command else {
                panic!("expected virtual callers");
            };
            assert_eq!(args.function, "Widget::draw");
            assert_eq!(args.vtable, "overlay:0x401020");
            assert_eq!(args.entries, 10);
            assert_eq!(args.abi, expected_abi);
            assert_eq!(args.within.as_deref(), within);
            assert_eq!(args.options.project.as_deref(), Some("selected"));
            assert_eq!(args.options.program.as_deref(), Some("sample"));
            assert_eq!(args.options.limit, Some(0));
            args.validate().unwrap();
        }
    }
}

#[test]
fn virtual_callers_requires_complete_table_interpretation_and_bounded_entries() {
    let required = [
        "Widget::draw",
        "--vtable",
        "0x401020",
        "--entries",
        "2",
        "--abi",
        "itanium",
    ];
    for omitted in [0..1, 1..3, 3..5, 5..7] {
        let argv = ["ghidra-cli", "find", "virtual-callers"].into_iter().chain(
            required
                .iter()
                .enumerate()
                .filter_map(|(i, &value)| (!omitted.contains(&i)).then_some(value)),
        );
        assert!(Cli::try_parse_from(argv).is_err(), "omitted {omitted:?}");
    }
    for (entries, expected) in [("1", 1), ("0x10", 16), ("0x10000", 65536)] {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "find",
            "virtual-callers",
            "0x2000",
            "--vtable",
            "vtable_symbol",
            "--entries",
            entries,
            "--abi",
            "msvc",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Commands::Find(FindCommands::VirtualCallers(args)) if args.entries == expected)
        );
    }
    for entries in ["0", "65537", "-1"] {
        assert!(Cli::try_parse_from([
            "ghidra-cli",
            "find",
            "virtual-callers",
            "draw",
            "--vtable",
            "0x2000",
            "--entries",
            entries,
            "--abi",
            "itanium",
        ])
        .is_err());
    }
}

#[test]
fn cfg_and_high_pcode_accept_bounded_results_without_row_queries() {
    for (command, high) in [
        (vec!["ghidra-cli", "graph", "cfg", "main"], false),
        (
            vec!["ghidra-cli", "pcode", "function", "main", "--high"],
            true,
        ),
    ] {
        let parsed = Cli::try_parse_from(&command).unwrap();
        match parsed.command {
            Commands::Graph(GraphCommands::Cfg(args)) => {
                assert_eq!(args.function, "main");
                assert_eq!((args.max_nodes, args.max_edges), (1000, 4000));
            }
            Commands::Pcode(PcodeCommands::Function(args)) => {
                assert!(args.high);
                assert_eq!((args.max_nodes, args.max_edges), (None, None));
            }
            _ => panic!("expected flow command"),
        }
        let parsed = Cli::try_parse_from(command.iter().copied().chain([
            "--max-nodes",
            "1",
            "--max-edges",
            "2147483647",
            "--program",
            "sample",
            "--project",
            "project",
        ]))
        .unwrap();
        let (nodes, edges, program, project) = match parsed.command {
            Commands::Graph(GraphCommands::Cfg(args)) => {
                (args.max_nodes, args.max_edges, args.program, args.project)
            }
            Commands::Pcode(PcodeCommands::Function(args)) => (
                args.max_nodes.unwrap(),
                args.max_edges.unwrap(),
                args.program,
                args.project,
            ),
            _ => panic!("expected flow command"),
        };
        assert_eq!((nodes, edges), (1, i32::MAX as u32));
        assert_eq!(program.as_deref(), Some("sample"));
        assert_eq!(project.as_deref(), Some("project"));
        for flags in [
            vec!["--filter", "id=b0"],
            vec!["--fields", "nodes"],
            vec!["--count"],
        ] {
            assert!(Cli::try_parse_from(command.iter().copied().chain(flags)).is_err());
        }
        for flag in ["--max-nodes", "--max-edges"] {
            for invalid in ["0", "2147483648"] {
                assert!(
                    Cli::try_parse_from(command.iter().copied().chain([flag, invalid])).is_err()
                );
            }
        }
        if high {
            let raw: Vec<_> = command
                .iter()
                .copied()
                .filter(|arg| *arg != "--high")
                .collect();
            assert!(Cli::try_parse_from(&raw).is_ok());
            for flag in ["--max-nodes", "--max-edges"] {
                assert!(Cli::try_parse_from(raw.iter().copied().chain([flag, "1"])).is_err());
            }
        }
    }
    assert!(Cli::try_parse_from(["ghidra-cli", "graph", "cfg"]).is_err());
}

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
fn disassembly_uses_limit_and_count() {
    for target in [vec!["main"], vec!["0x1000"]] {
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
    let cli = Cli::try_parse_from(["ghidra-cli", "disassemble", "main", "--count"]).unwrap();
    assert!(matches!(cli.command, Commands::Disasm(args) if args.options.count));
}

#[test]
fn define_code_accepts_positional_targets_and_bounds_without_query_options() {
    for target in ["entry", "0x1000"] {
        for end in [None, Some("0x2000")] {
            let mut args = vec!["ghidra-cli", "listing", "define-code", target];
            if let Some(end) = end {
                args.extend(["--end", end]);
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let Commands::Listing(ListingCommands::DefineCode(args)) = cli.command else {
                panic!("expected define-code")
            };
            assert_eq!(args.target, target);
            assert_eq!(args.end.as_deref(), end);
        }
    }
    for flags in [
        vec!["--limit", "1"],
        vec!["--count"],
        vec!["--count", "2"],
        vec!["--filter", "mnemonic=RET"],
        vec!["--sort", "address"],
        vec!["--skip", "1"],
        vec!["--fields", "address"],
        vec!["--format", "asm"],
    ] {
        assert!(Cli::try_parse_from(
            ["ghidra-cli", "listing", "define-code", "0x1000"]
                .into_iter()
                .chain(flags)
        )
        .is_err());
    }
}

#[test]
fn listing_undefine_accepts_explicit_bounds_and_optional_disassembly() {
    for disasm_at in [None, Some("0x1000")] {
        let mut command = vec![
            "ghidra-cli",
            "listing",
            "undefine",
            "0x1000",
            "--end",
            "0x1010",
        ];
        if let Some(address) = disasm_at {
            command.extend(["--disassemble-at", address]);
        }
        let cli = Cli::try_parse_from(&command).unwrap();
        let Commands::Listing(ListingCommands::Undefine(args)) = cli.command else {
            panic!("expected listing undefine");
        };
        assert_eq!(args.start, "0x1000");
        assert_eq!(args.end, "0x1010");
        assert_eq!(args.disasm_at.as_deref(), disasm_at);
    }
}

#[test]
fn parses_decompile_positional_target() {
    for with_jump_tables in [false, true] {
        let mut argv = vec!["ghidra-cli", "decompile", "FUN_00401000"];
        if with_jump_tables {
            argv.push("--with-jump-tables");
        }
        let cli = Cli::try_parse_from(argv).expect("decompile positional target should parse");
        match cli.command {
            Commands::Decompile(args) => {
                assert_eq!(args.target, "FUN_00401000");
                assert_eq!(args.with_jump_tables, with_jump_tables);
            }
            _ => panic!("expected decompile command"),
        }
    }
}

#[test]
fn parses_function_get_positional_target() {
    for with_signature in [false, true] {
        let mut argv = vec!["ghidra-cli", "function", "get", "main"];
        if with_signature {
            argv.push("--with-signature");
        }
        let cli = Cli::try_parse_from(argv).expect("function get positional target should parse");
        match cli.command {
            Commands::Function(FunctionCommands::Get(args)) => {
                assert_eq!(args.target, "main");
                assert_eq!(args.with_signature, with_signature);
            }
            _ => panic!("expected function get command"),
        }
    }
    assert!(Cli::try_parse_from([
        "ghidra-cli",
        "function",
        "disassemble",
        "main",
        "--with-signature"
    ])
    .is_err());
}
