use crate::cli::{self, Commands, QueryOptions};

/// Determines if a command requires the bridge to be running.
pub(super) fn requires_bridge(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Import(_)
            | Commands::Analyze(_)
            | Commands::Query(_)
            | Commands::Decompile(_)
            | Commands::Function(_)
            | Commands::Strings(_)
            | Commands::Memory(_)
            | Commands::Dump(_)
            | Commands::Summary(_)
            | Commands::XRef(_)
            | Commands::Symbol(_)
            | Commands::Type(_)
            | Commands::Tag(_)
            | Commands::Pcode(_)
            | Commands::Analyzer(_)
            | Commands::Comment(_)
            | Commands::Graph(_)
            | Commands::Find(_)
            | Commands::Diff(_)
            | Commands::Patch(_)
            | Commands::Script(_)
            | Commands::Disasm(_)
            | Commands::DisasmAt(_)
            | Commands::Clear(_)
            | Commands::Batch(_)
            | Commands::Stats(_)
            | Commands::Program(_)
            | Commands::Rename(_)
    )
}

/// Extract the project name from a command's args (if present).
pub(super) fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Import(args) => args.project.clone(),
        Commands::Analyze(args) => args.project.clone(),
        Commands::Query(args) => args.project.clone(),
        Commands::Summary(args) => args.options.project.clone(),
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.project.clone(),
            cli::FunctionCommands::Decompile(args) => args.options.project.clone(),
            cli::FunctionCommands::Get(args) => args.options.project.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.project.clone(),
            cli::FunctionCommands::Calls(args) => args.options.project.clone(),
            cli::FunctionCommands::XRefs(args) => args.options.project.clone(),
            cli::FunctionCommands::Rename(args) => args.project.clone(),
            cli::FunctionCommands::Create(args) => args.project.clone(),
            cli::FunctionCommands::Delete(args) => args.options.project.clone(),
            cli::FunctionCommands::SetSignature(args) => args.project.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.project.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.project.clone(),
            cli::FunctionCommands::SetVarType(args) => args.project.clone(),
            cli::FunctionCommands::SetNoReturn(args) => args.project.clone(),
            cli::FunctionCommands::Tag(cmd) => match cmd {
                cli::FunctionTagCommands::Add(args) => args.project.clone(),
                cli::FunctionTagCommands::Remove(args) => args.project.clone(),
                cli::FunctionTagCommands::List(args) => args.options.project.clone(),
            },
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.project.clone(),
            cli::StringsCommands::Refs(args) => args.options.project.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.project.clone(),
            cli::MemoryCommands::Read(args) => args.options.project.clone(),
            cli::MemoryCommands::Write(args) => args.project.clone(),
            cli::MemoryCommands::Search(args) => args.options.project.clone(),
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => opts.project.clone(),
            cli::DumpCommands::Exports(opts) => opts.project.clone(),
            cli::DumpCommands::Functions(opts) => opts.project.clone(),
            cli::DumpCommands::Strings(opts) => opts.project.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.project.clone(),
            cli::XRefCommands::From(args) => args.options.project.clone(),
            cli::XRefCommands::List(args) => args.options.project.clone(),
        },
        Commands::Stats(args) => args.options.project.clone(),
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::DisasmAt(args) => args.project.clone(),
        Commands::Clear(args) => args.project.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.project.clone(),
            cli::FindCommands::Bytes(args) => args.options.project.clone(),
            cli::FindCommands::Function(args) => args.options.project.clone(),
            cli::FindCommands::Calls(args) => args.options.project.clone(),
            cli::FindCommands::Crypto(opts) => opts.project.clone(),
            cli::FindCommands::Interesting(opts) => opts.project.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.project.clone(),
            cli::GraphCommands::Callers(args) => args.options.project.clone(),
            cli::GraphCommands::Callees(args) => args.options.project.clone(),
            cli::GraphCommands::Export(args) => args.options.project.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.project.clone(),
            cli::CommentCommands::Get(args) => args.options.project.clone(),
            cli::CommentCommands::Set(args) => args.project.clone(),
            cli::CommentCommands::Delete(args) => args.options.project.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => opts.project.clone(),
            cli::SymbolCommands::Get(args) => args.options.project.clone(),
            cli::SymbolCommands::Create(args) => args.project.clone(),
            cli::SymbolCommands::Delete(args) => args.options.project.clone(),
            cli::SymbolCommands::Rename(args) => args.project.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.project.clone(),
            cli::TypeCommands::Get(args) => args.options.project.clone(),
            cli::TypeCommands::Create(args) => args.project.clone(),
            cli::TypeCommands::Apply(args) => args.project.clone(),
            cli::TypeCommands::ImportC(args) => args.project.clone(),
            cli::TypeCommands::Delete(args) => args.project.clone(),
            cli::TypeCommands::Rename(args) => args.project.clone(),
            cli::TypeCommands::CreateEnum(args) => args.project.clone(),
            cli::TypeCommands::Typedef(args) => args.project.clone(),
            cli::TypeCommands::AddField(args) => args.project.clone(),
            cli::TypeCommands::DelField(args) => args.project.clone(),
        },
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => args.options.project.clone(),
            cli::TagCommands::Get(args) => args.options.project.clone(),
            cli::TagCommands::Create(args) => args.project.clone(),
            cli::TagCommands::Delete(args) => args.project.clone(),
            cli::TagCommands::Rename(args) => args.project.clone(),
            cli::TagCommands::SetComment(args) => args.project.clone(),
            cli::TagCommands::Add(args) => args.project.clone(),
            cli::TagCommands::Remove(args) => args.project.clone(),
        },
        Commands::Pcode(cmd) => match cmd {
            cli::PcodeCommands::At(args) => args.project.clone(),
            cli::PcodeCommands::Function(args) => args.project.clone(),
        },
        Commands::Analyzer(cmd) => match cmd {
            cli::AnalyzerCommands::List(args) => args.project.clone(),
            cli::AnalyzerCommands::Set(args) => args.project.clone(),
            cli::AnalyzerCommands::Run(args) => args.project.clone(),
        },
        Commands::Patch(cmd) => match cmd {
            cli::PatchCommands::Bytes(args) => args.project.clone(),
            cli::PatchCommands::Nop(args) => args.project.clone(),
            cli::PatchCommands::Export(args) => args.project.clone(),
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.project.clone(),
            cli::ScriptCommands::Python(args) => args.project.clone(),
            cli::ScriptCommands::Java(args) => args.project.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.project.clone(),
            cli::ProgramCommands::Open(args) => args.project.clone(),
            cli::ProgramCommands::Close(args) => args.project.clone(),
            cli::ProgramCommands::Delete(args) => args.project.clone(),
            cli::ProgramCommands::Info(args) => args.project.clone(),
            cli::ProgramCommands::Export(args) => args.project.clone(),
            cli::ProgramCommands::Save(args) => args.project.clone(),
        },
        Commands::Diff(cmd) => match cmd {
            cli::DiffCommands::Programs(args) => args.project.clone(),
            cli::DiffCommands::Functions(args) => args.project.clone(),
        },
        Commands::Batch(args) => args.project.clone(),
        Commands::Rename(args) => args.project.clone(),
        _ => None,
    }
}

/// Extract the --program argument from a command's args, if present.
/// Enables program switching before query execution when the requested
/// program differs from the bridge's current program.
pub(super) fn extract_program_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Analyze(args) => args.program.clone(),
        Commands::Query(args) => args.program.clone(),
        Commands::Summary(args) => args.options.program.clone(),
        Commands::Decompile(args) => args.options.program.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.program.clone(),
            cli::FunctionCommands::Decompile(args) => args.options.program.clone(),
            cli::FunctionCommands::Get(args) => args.options.program.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.program.clone(),
            cli::FunctionCommands::Calls(args) => args.options.program.clone(),
            cli::FunctionCommands::XRefs(args) => args.options.program.clone(),
            cli::FunctionCommands::Rename(args) => args.program.clone(),
            cli::FunctionCommands::Create(args) => args.program.clone(),
            cli::FunctionCommands::Delete(args) => args.options.program.clone(),
            cli::FunctionCommands::SetSignature(args) => args.program.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.program.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.program.clone(),
            cli::FunctionCommands::SetVarType(args) => args.program.clone(),
            cli::FunctionCommands::SetNoReturn(args) => args.program.clone(),
            cli::FunctionCommands::Tag(cmd) => match cmd {
                cli::FunctionTagCommands::Add(args) => args.program.clone(),
                cli::FunctionTagCommands::Remove(args) => args.program.clone(),
                cli::FunctionTagCommands::List(args) => args.options.program.clone(),
            },
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.program.clone(),
            cli::StringsCommands::Refs(args) => args.options.program.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.program.clone(),
            cli::MemoryCommands::Read(args) => args.options.program.clone(),
            cli::MemoryCommands::Write(args) => args.program.clone(),
            cli::MemoryCommands::Search(args) => args.options.program.clone(),
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => opts.program.clone(),
            cli::DumpCommands::Exports(opts) => opts.program.clone(),
            cli::DumpCommands::Functions(opts) => opts.program.clone(),
            cli::DumpCommands::Strings(opts) => opts.program.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.program.clone(),
            cli::XRefCommands::From(args) => args.options.program.clone(),
            cli::XRefCommands::List(args) => args.options.program.clone(),
        },
        Commands::Stats(args) => args.options.program.clone(),
        Commands::Disasm(args) => args.options.program.clone(),
        Commands::DisasmAt(args) => args.program.clone(),
        Commands::Clear(args) => args.program.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.program.clone(),
            cli::FindCommands::Bytes(args) => args.options.program.clone(),
            cli::FindCommands::Function(args) => args.options.program.clone(),
            cli::FindCommands::Calls(args) => args.options.program.clone(),
            cli::FindCommands::Crypto(opts) => opts.program.clone(),
            cli::FindCommands::Interesting(opts) => opts.program.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.program.clone(),
            cli::GraphCommands::Callers(args) => args.options.program.clone(),
            cli::GraphCommands::Callees(args) => args.options.program.clone(),
            cli::GraphCommands::Export(args) => args.options.program.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.program.clone(),
            cli::CommentCommands::Get(args) => args.options.program.clone(),
            cli::CommentCommands::Set(args) => args.program.clone(),
            cli::CommentCommands::Delete(args) => args.options.program.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => opts.program.clone(),
            cli::SymbolCommands::Get(args) => args.options.program.clone(),
            cli::SymbolCommands::Create(args) => args.program.clone(),
            cli::SymbolCommands::Delete(args) => args.options.program.clone(),
            cli::SymbolCommands::Rename(args) => args.program.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.program.clone(),
            cli::TypeCommands::Get(args) => args.options.program.clone(),
            cli::TypeCommands::Create(args) => args.program.clone(),
            cli::TypeCommands::Apply(args) => args.program.clone(),
            cli::TypeCommands::ImportC(args) => args.program.clone(),
            cli::TypeCommands::Delete(args) => args.program.clone(),
            cli::TypeCommands::Rename(args) => args.program.clone(),
            cli::TypeCommands::CreateEnum(args) => args.program.clone(),
            cli::TypeCommands::Typedef(args) => args.program.clone(),
            cli::TypeCommands::AddField(args) => args.program.clone(),
            cli::TypeCommands::DelField(args) => args.program.clone(),
        },
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => args.options.program.clone(),
            cli::TagCommands::Get(args) => args.options.program.clone(),
            cli::TagCommands::Create(args) => args.program.clone(),
            cli::TagCommands::Delete(args) => args.program.clone(),
            cli::TagCommands::Rename(args) => args.program.clone(),
            cli::TagCommands::SetComment(args) => args.program.clone(),
            cli::TagCommands::Add(args) => args.program.clone(),
            cli::TagCommands::Remove(args) => args.program.clone(),
        },
        Commands::Pcode(cmd) => match cmd {
            cli::PcodeCommands::At(args) => args.program.clone(),
            cli::PcodeCommands::Function(args) => args.program.clone(),
        },
        Commands::Analyzer(cmd) => match cmd {
            cli::AnalyzerCommands::List(args) => args.program.clone(),
            cli::AnalyzerCommands::Set(args) => args.program.clone(),
            cli::AnalyzerCommands::Run(args) => args.program.clone(),
        },
        Commands::Patch(cmd) => match cmd {
            cli::PatchCommands::Bytes(args) => args.program.clone(),
            cli::PatchCommands::Nop(args) => args.program.clone(),
            cli::PatchCommands::Export(args) => args.program.clone(),
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.program.clone(),
            cli::ScriptCommands::Python(args) => args.program.clone(),
            cli::ScriptCommands::Java(args) => args.program.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.program.clone(),
            cli::ProgramCommands::Open(args) => args.program.clone(),
            cli::ProgramCommands::Close(args) => args.program.clone(),
            cli::ProgramCommands::Delete(args) => args.program.clone(),
            cli::ProgramCommands::Info(args) => args.program.clone(),
            cli::ProgramCommands::Export(args) => args.program.clone(),
            cli::ProgramCommands::Save(args) => args.program.clone(),
        },
        Commands::Batch(args) => args.program.clone(),
        Commands::Rename(args) => args.program.clone(),
        _ => None,
    }
}

/// Extract QueryOptions from a command, if it has them.
pub(super) fn extract_query_options(command: &Commands) -> Option<QueryOptions> {
    match command {
        Commands::Query(args) => Some(QueryOptions {
            program: args.program.clone(),
            project: args.project.clone(),
            filter: args.filter.clone(),
            fields: args.fields.clone(),
            format: args.format.clone(),
            limit: args.limit,
            offset: args.offset,
            sort: args.sort.clone(),
            count: args.count,
            json: args.json,
        }),
        Commands::Summary(args) => Some(args.options.clone()),
        Commands::Decompile(args) => Some(args.options.clone()),
        Commands::Disasm(args) => Some(args.options.clone()),
        Commands::Stats(args) => Some(args.options.clone()),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => Some(args.options.clone()),
            cli::FunctionCommands::Get(args) => Some(args.options.clone()),
            cli::FunctionCommands::Decompile(args) => Some(args.options.clone()),
            cli::FunctionCommands::Disasm(args) => Some(args.options.clone()),
            cli::FunctionCommands::Calls(args) => Some(args.options.clone()),
            cli::FunctionCommands::XRefs(args) => Some(args.options.clone()),
            cli::FunctionCommands::Delete(args) => Some(args.options.clone()),
            cli::FunctionCommands::Tag(cli::FunctionTagCommands::List(args)) => {
                Some(args.options.clone())
            }
            _ => None,
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => Some(opts.clone()),
            cli::StringsCommands::Refs(args) => Some(args.options.clone()),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => Some(opts.clone()),
            cli::MemoryCommands::Read(args) => Some(args.options.clone()),
            cli::MemoryCommands::Search(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => Some(opts.clone()),
            cli::DumpCommands::Exports(opts) => Some(opts.clone()),
            cli::DumpCommands::Functions(opts) => Some(opts.clone()),
            cli::DumpCommands::Strings(opts) => Some(opts.clone()),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => Some(args.options.clone()),
            cli::XRefCommands::From(args) => Some(args.options.clone()),
            cli::XRefCommands::List(args) => Some(args.options.clone()),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => Some(opts.clone()),
            cli::SymbolCommands::Get(args) => Some(args.options.clone()),
            cli::SymbolCommands::Delete(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => Some(opts.clone()),
            cli::TypeCommands::Get(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => Some(args.options.clone()),
            cli::TagCommands::Get(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => Some(opts.clone()),
            cli::CommentCommands::Get(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => Some(opts.clone()),
            cli::GraphCommands::Callers(args) => Some(args.options.clone()),
            cli::GraphCommands::Callees(args) => Some(args.options.clone()),
            cli::GraphCommands::Export(args) => Some(args.options.clone()),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => Some(args.options.clone()),
            cli::FindCommands::Bytes(args) => Some(args.options.clone()),
            cli::FindCommands::Function(args) => Some(args.options.clone()),
            cli::FindCommands::Calls(args) => Some(args.options.clone()),
            cli::FindCommands::Crypto(opts) => Some(opts.clone()),
            cli::FindCommands::Interesting(opts) => Some(opts.clone()),
        },
        _ => None,
    }
}
