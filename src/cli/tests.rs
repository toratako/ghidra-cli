use super::*;

mod inspection;
mod management;
mod memory;
mod output;
mod references;
mod types;
mod vtable;

#[test]
fn positional_targets_preserve_program_and_project_selection() {
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
                    (args.target, args.options.program, args.options.project)
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
    }
}

#[test]
fn import_and_define_data_options_parse() {
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
        "listing",
        "define-data",
        "0x1000",
        "--type",
        "int",
        "--force",
    ])
    .unwrap();
    let Commands::Listing(ListingCommands::DefineData(args)) = cli.command else {
        panic!("expected listing define-data")
    };
    assert!(args.force);
}
