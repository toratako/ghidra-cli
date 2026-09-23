use super::*;
use clap::CommandFactory;

mod inspection;
mod management;
mod memory;
mod output;
mod references;
mod types;

#[test]
fn targets_require_one_positional() {
    for command in [
        vec!["function", "delete"],
        vec!["listing", "define-code"],
        vec![
            "function",
            "set-signature",
            "--signature",
            "int entry(void)",
        ],
        vec!["function", "set-return-type", "--type", "int"],
        vec![
            "function",
            "set-calling-convention",
            "--convention",
            "__cdecl",
        ],
        vec!["function", "set-noreturn", "--value", "true"],
        vec![
            "function", "var", "set", "--var", "local_10", "--name", "value",
        ],
        vec!["function", "get"],
        vec!["function", "disassemble"],
        vec!["decompile"],
        vec!["disassemble"],
        vec!["xref", "to"],
        vec!["xref", "from"],
        vec!["graph", "callers"],
        vec!["graph", "callees"],
    ] {
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
                Commands::Listing(ListingCommands::DefineCode(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::Function(FunctionCommands::SetSignature(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::Function(FunctionCommands::SetReturnType(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::Function(FunctionCommands::SetCallingConvention(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::Function(FunctionCommands::SetNoReturn(args)) => {
                    (args.target, args.program, args.project)
                }
                Commands::Function(FunctionCommands::Var(FunctionVarCommands::Set(args))) => (
                    args.selection.target,
                    args.options.program,
                    args.options.project,
                ),
                Commands::Function(FunctionCommands::Get(args)) => {
                    (args.target, args.options.program, args.options.project)
                }
                Commands::Function(FunctionCommands::Disasm(args)) => {
                    (args.target, args.options.program, args.options.project)
                }
                Commands::Decompile(args) => {
                    (args.target, args.options.program, args.options.project)
                }
                Commands::Disasm(args) => (args.target, args.options.program, args.options.project),
                Commands::XRef(XRefCommands::To(args)) => {
                    (args.target, args.options.program, args.options.project)
                }
                Commands::XRef(XRefCommands::From(args)) => {
                    (args.target, args.options.program, args.options.project)
                }
                Commands::Graph(GraphCommands::Callers(args) | GraphCommands::Callees(args)) => {
                    (args.target, args.options.program, args.options.project)
                }
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
        let error = Cli::try_parse_from(
            ["ghidra-cli"]
                .into_iter()
                .chain(command.iter().copied())
                .chain(["entry", "other"]),
        )
        .err()
        .expect("second target must fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
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
        }
    }
}

#[test]
fn canonical_commands_parse() {
    for args in [
        vec!["xref", "to", "main"],
        vec!["xref", "from", "main"],
        vec!["string", "list"],
        vec!["string", "refs", "hello"],
        vec!["disassemble", "main"],
        vec!["function", "disassemble", "main"],
        vec!["listing", "define-code", "0x1000"],
        vec!["find", "string", "hello"],
        vec!["graph", "callers", "main"],
        vec!["graph", "callees", "main"],
        vec!["type", "import-c", "--code", "typedef int Word;"],
        vec!["function", "list"],
        vec!["function", "get", "main"],
        vec!["function", "list-calling-conventions"],
        vec!["program", "list-relocations"],
        vec!["bookmark", "list"],
        vec!["bookmark", "get", "overlay:0x1000"],
        vec!["memory", "info", "main"],
        vec!["type", "delete", "Word"],
        vec!["tag", "rename", "old", "new"],
        vec!["analysis", "option", "list"],
        vec!["analysis", "run"],
        vec!["decompile", "main"],
    ] {
        Cli::try_parse_from(["ghidra-cli"].into_iter().chain(args.iter().copied()))
            .unwrap_or_else(|error| panic!("{args:?}: {error}"));
    }
}

#[test]
fn import_and_type_apply_options_parse() {
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "program",
        "import",
        "sample.bin",
        "--name",
        "saved.bin",
        "--language",
        "x86:LE:32:default",
        "--compiler-spec",
        "gcc",
    ])
    .unwrap();
    let Commands::Program(ProgramCommands::Import(args)) = cli.command else {
        panic!("expected program import")
    };
    assert_eq!(args.name.as_deref(), Some("saved.bin"));
    assert_eq!(args.language.as_deref(), Some("x86:LE:32:default"));
    assert_eq!(args.compiler_spec.as_deref(), Some("gcc"));
    let cli = Cli::try_parse_from([
        "ghidra-cli",
        "type",
        "apply",
        "0x1000",
        "--type",
        "int",
        "--force",
    ])
    .unwrap();
    let Commands::Type(TypeCommands::Apply(args)) = cli.command else {
        panic!("expected type apply")
    };
    assert!(args.force);

    let help = Cli::try_parse_from(["ghidra-cli", "type", "apply", "--help"])
        .err()
        .unwrap()
        .to_string();
    assert!(help.contains("including instructions"), "{help}");
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
