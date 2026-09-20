use crate::cli::{self, Commands, QueryOptions};

/// Determines if a command requires the bridge to be running.
pub(super) fn requires_bridge(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Import(_)
            | Commands::Analyze(_)
            | Commands::Decompile(_)
            | Commands::Function(_)
            | Commands::Strings(_)
            | Commands::Memory(_)
            | Commands::XRef(_)
            | Commands::Symbol(_)
            | Commands::Type(_)
            | Commands::Tag(_)
            | Commands::Pcode(_)
            | Commands::Analyzer(_)
            | Commands::Comment(_)
            | Commands::Graph(_)
            | Commands::Find(_)
            | Commands::Script(_)
            | Commands::Disasm(_)
            | Commands::DefineCode(_)
            | Commands::Clear(_)
            | Commands::Batch(_)
            | Commands::Program(_)
    )
}

/// Extract the project name from a command's args (if present).
pub(super) fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Import(args) => args.project.clone(),
        Commands::Analyze(args) => args.project.clone(),
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.project.clone(),
            cli::FunctionCommands::Get(args) => args.options.project.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.project.clone(),
            cli::FunctionCommands::Rename(args) => args.project.clone(),
            cli::FunctionCommands::Create(args) => args.project.clone(),
            cli::FunctionCommands::Delete(args) => args.project.clone(),
            cli::FunctionCommands::SetSignature(args) => args.project.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.project.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.project.clone(),
            cli::FunctionCommands::EditVar(args) => args.project.clone(),
            cli::FunctionCommands::SetNoReturn(args) => args.project.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.project.clone(),
            cli::StringsCommands::Refs(args) => args.options.project.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.project.clone(),
            cli::MemoryCommands::Read(args) => args.options.project.clone(),
            cli::MemoryCommands::Write(args) => args.project.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.project.clone(),
            cli::XRefCommands::From(args) => args.options.project.clone(),
        },
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::DefineCode(args) => args.project.clone(),
        Commands::Clear(args) => args.project.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.project.clone(),
            cli::FindCommands::Text(args) => args.options.project.clone(),
            cli::FindCommands::Bytes(args) => args.options.project.clone(),
            cli::FindCommands::Instruction(args) => args.options.project.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.project.clone(),
            cli::GraphCommands::Callers(args) => args.options.project.clone(),
            cli::GraphCommands::Callees(args) => args.options.project.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.project.clone(),
            cli::CommentCommands::Get(args) => args.options.project.clone(),
            cli::CommentCommands::Set(args) => args.project.clone(),
            cli::CommentCommands::Delete(args) => args.project.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts)
            | cli::SymbolCommands::Externals(opts)
            | cli::SymbolCommands::EntryPoints(opts) => opts.project.clone(),
            cli::SymbolCommands::Get(args) => args.options.project.clone(),
            cli::SymbolCommands::CreateLabel(args) => args.project.clone(),
            cli::SymbolCommands::Delete(args) => args.options.project.clone(),
            cli::SymbolCommands::Rename(args) => args.project.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.project.clone(),
            cli::TypeCommands::Get(args) => args.options.project.clone(),
            cli::TypeCommands::Create(cmd) => match cmd {
                cli::TypeCreateCommands::Struct(args) => args.project.clone(),
                cli::TypeCreateCommands::Union(args) => args.project.clone(),
                cli::TypeCreateCommands::Enum(args) => args.project.clone(),
                cli::TypeCreateCommands::Typedef(args) => args.project.clone(),
            },
            cli::TypeCommands::Apply(args) => args.project.clone(),
            cli::TypeCommands::ImportC(args) => args.project.clone(),
            cli::TypeCommands::Delete(args) => args.project.clone(),
            cli::TypeCommands::Rename(args) => args.project.clone(),
            cli::TypeCommands::AddField(args) => args.project.clone(),
            cli::TypeCommands::SetField(args) => args.project.clone(),
            cli::TypeCommands::ClearField(args) => args.project.clone(),
            cli::TypeCommands::DelField(args) => args.project.clone(),
            cli::TypeCommands::DelEnumMember(args) => args.project.clone(),
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
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.project.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.project.clone(),
            cli::ProgramCommands::Open(args) => args.project.clone(),
            cli::ProgramCommands::Close(args) => args.project.clone(),
            cli::ProgramCommands::Delete(args) => args.project.clone(),
            cli::ProgramCommands::Info(args) | cli::ProgramCommands::Stats(args) => {
                args.project.clone()
            }
            cli::ProgramCommands::Export(args) => args.project.clone(),
            cli::ProgramCommands::Save(args) => args.project.clone(),
        },
        Commands::Batch(args) => args.project.clone(),
        _ => None,
    }
}

/// Extract the --program argument from a command's args, if present.
/// Enables program switching before query execution when the requested
/// program differs from the bridge's current program.
pub(super) fn extract_program_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Analyze(args) => args.program.clone(),
        Commands::Decompile(args) => args.options.program.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.program.clone(),
            cli::FunctionCommands::Get(args) => args.options.program.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.program.clone(),
            cli::FunctionCommands::Rename(args) => args.program.clone(),
            cli::FunctionCommands::Create(args) => args.program.clone(),
            cli::FunctionCommands::Delete(args) => args.program.clone(),
            cli::FunctionCommands::SetSignature(args) => args.program.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.program.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.program.clone(),
            cli::FunctionCommands::EditVar(args) => args.program.clone(),
            cli::FunctionCommands::SetNoReturn(args) => args.program.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.program.clone(),
            cli::StringsCommands::Refs(args) => args.options.program.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.program.clone(),
            cli::MemoryCommands::Read(args) => args.options.program.clone(),
            cli::MemoryCommands::Write(args) => args.program.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.program.clone(),
            cli::XRefCommands::From(args) => args.options.program.clone(),
        },
        Commands::Disasm(args) => args.options.program.clone(),
        Commands::DefineCode(args) => args.program.clone(),
        Commands::Clear(args) => args.program.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.program.clone(),
            cli::FindCommands::Text(args) => args.options.program.clone(),
            cli::FindCommands::Bytes(args) => args.options.program.clone(),
            cli::FindCommands::Instruction(args) => args.options.program.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.program.clone(),
            cli::GraphCommands::Callers(args) => args.options.program.clone(),
            cli::GraphCommands::Callees(args) => args.options.program.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.program.clone(),
            cli::CommentCommands::Get(args) => args.options.program.clone(),
            cli::CommentCommands::Set(args) => args.program.clone(),
            cli::CommentCommands::Delete(args) => args.program.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts)
            | cli::SymbolCommands::Externals(opts)
            | cli::SymbolCommands::EntryPoints(opts) => opts.program.clone(),
            cli::SymbolCommands::Get(args) => args.options.program.clone(),
            cli::SymbolCommands::CreateLabel(args) => args.program.clone(),
            cli::SymbolCommands::Delete(args) => args.options.program.clone(),
            cli::SymbolCommands::Rename(args) => args.program.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.program.clone(),
            cli::TypeCommands::Get(args) => args.options.program.clone(),
            cli::TypeCommands::Create(cmd) => match cmd {
                cli::TypeCreateCommands::Struct(args) => args.program.clone(),
                cli::TypeCreateCommands::Union(args) => args.program.clone(),
                cli::TypeCreateCommands::Enum(args) => args.program.clone(),
                cli::TypeCreateCommands::Typedef(args) => args.program.clone(),
            },
            cli::TypeCommands::Apply(args) => args.program.clone(),
            cli::TypeCommands::ImportC(args) => args.program.clone(),
            cli::TypeCommands::Delete(args) => args.program.clone(),
            cli::TypeCommands::Rename(args) => args.program.clone(),
            cli::TypeCommands::AddField(args) => args.program.clone(),
            cli::TypeCommands::SetField(args) => args.program.clone(),
            cli::TypeCommands::ClearField(args) => args.program.clone(),
            cli::TypeCommands::DelField(args) => args.program.clone(),
            cli::TypeCommands::DelEnumMember(args) => args.program.clone(),
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
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.program.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.program.clone(),
            cli::ProgramCommands::Open(args) => args.program.clone(),
            cli::ProgramCommands::Close(args) => args.program.clone(),
            cli::ProgramCommands::Delete(args) => args.program.clone(),
            cli::ProgramCommands::Info(args) | cli::ProgramCommands::Stats(args) => {
                args.program.clone()
            }
            cli::ProgramCommands::Export(args) => args.program.clone(),
            cli::ProgramCommands::Save(args) => args.program.clone(),
        },
        Commands::Batch(args) => args.program.clone(),
        _ => None,
    }
}

/// Extract QueryOptions from a command, if it has them.
pub(super) fn extract_query_options(command: &Commands) -> Option<QueryOptions> {
    match command {
        Commands::Decompile(args) => Some(args.options.clone()),
        Commands::Disasm(args) => Some(args.options.clone()),
        Commands::Program(cli::ProgramCommands::Info(opts) | cli::ProgramCommands::Stats(opts)) => {
            Some(opts.into())
        }
        Commands::Symbol(
            cli::SymbolCommands::Externals(opts) | cli::SymbolCommands::EntryPoints(opts),
        ) => Some(opts.clone()),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => Some(args.options.clone()),
            cli::FunctionCommands::Get(args) => Some(args.options.clone()),
            cli::FunctionCommands::Disasm(args) => Some(args.options.clone()),
            cli::FunctionCommands::Delete(args) => Some(QueryOptions {
                program: args.program.clone(),
                project: args.project.clone(),
                fields: args.fields.clone(),
                format: args.format,
                filter: None,
                limit: None,
                offset: None,
                sort: None,
                count: false,
                json: false,
            }),
            _ => None,
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => Some(opts.clone()),
            cli::StringsCommands::Refs(args) => Some(args.options.clone()),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => Some(opts.clone()),
            cli::MemoryCommands::Read(args) => Some((&args.options).into()),
            _ => None,
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => Some(args.options.clone()),
            cli::XRefCommands::From(args) => Some(args.options.clone()),
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
            cli::TagCommands::Get(args) => Some((&args.options).into()),
            _ => None,
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => Some(opts.clone()),
            cli::CommentCommands::Get(args) => Some(args.options.clone()),
            cli::CommentCommands::Delete(args) => Some(QueryOptions {
                program: args.program.clone(),
                project: args.project.clone(),
                fields: args.fields.clone(),
                format: args.format,
                filter: None,
                limit: None,
                offset: None,
                sort: None,
                count: false,
                json: false,
            }),
            _ => None,
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => Some(opts.clone()),
            cli::GraphCommands::Callers(args) => Some(args.options.clone()),
            cli::GraphCommands::Callees(args) => Some(args.options.clone()),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => Some(args.options.clone()),
            cli::FindCommands::Text(args) => Some(args.options.clone()),
            cli::FindCommands::Bytes(args) => Some(args.options.clone()),
            cli::FindCommands::Instruction(args) => Some(args.options.clone()),
        },
        _ => None,
    }
}

/// Must match the fetch arguments forwarded by execute_via_bridge.
pub(super) fn query_fetch_support(command: &Commands) -> crate::query::FetchSupport {
    use crate::query::FetchSupport::{Client, Limit, Paged};
    match command {
        Commands::Function(cli::FunctionCommands::List(_))
        | Commands::Symbol(cli::SymbolCommands::List(_))
        | Commands::Type(cli::TypeCommands::List(_)) => Paged("name"),
        Commands::Strings(cli::StringsCommands::List(_))
        | Commands::Find(cli::FindCommands::String(_)) => Paged("value"),
        Commands::Comment(cli::CommentCommands::List(_)) => Paged("text"),
        Commands::Symbol(
            cli::SymbolCommands::Externals(_) | cli::SymbolCommands::EntryPoints(_),
        ) => Limit,
        Commands::Function(cli::FunctionCommands::Disasm(_))
        | Commands::Tag(cli::TagCommands::List(_))
        | Commands::Graph(
            cli::GraphCommands::Calls(_)
            | cli::GraphCommands::Callers(_)
            | cli::GraphCommands::Callees(_),
        )
        | Commands::Find(
            cli::FindCommands::Text(_)
            | cli::FindCommands::Bytes(_)
            | cli::FindCommands::Instruction(_),
        ) => Limit,
        Commands::Disasm(_) => Limit,
        _ => Client,
    }
}

/// Validate the command's bounds even when filtering keeps its limit in Rust.
pub(super) fn validate_query_bounds(
    command: &Commands,
    plan: &crate::query::QueryPlan,
) -> anyhow::Result<()> {
    let int_limit = matches!(
        command,
        Commands::Symbol(cli::SymbolCommands::Externals(_) | cli::SymbolCommands::EntryPoints(_))
            | Commands::Tag(cli::TagCommands::List(_))
            | Commands::Graph(_)
            | Commands::Find(cli::FindCommands::Instruction(_))
    );
    if int_limit {
        let limit = plan
            .post
            .as_ref()
            .and_then(|query| query.limit)
            .or(plan.fetch.limit);
        anyhow::ensure!(
            limit.is_none_or(|limit| limit <= i32::MAX as usize),
            "--limit must be between 0 and {} for this command (0 means unlimited)",
            i32::MAX
        );
    }
    if let Commands::Graph(cli::GraphCommands::Callers(args) | cli::GraphCommands::Callees(args)) =
        command
    {
        anyhow::ensure!(
            args.depth.is_none_or(|depth| depth <= i32::MAX as usize),
            "--depth must be between 0 and {}",
            i32::MAX
        );
    }
    Ok(())
}
