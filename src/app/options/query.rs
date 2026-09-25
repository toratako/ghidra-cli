use crate::cli::{self, Commands, QueryOptions};

/// Extract QueryOptions from a command, if it has them.
pub(in crate::app) fn extract_query_options(command: &Commands) -> Option<QueryOptions> {
    match command {
        Commands::Program(cli::ProgramCommands::Context(cmd)) => match cmd {
            cli::ProgramContextCommands::List(opts) => Some(opts.clone()),
            cli::ProgramContextCommands::Get(args) => Some(args.options.clone()),
            cli::ProgramContextCommands::Set(args) => Some((&args.options).into()),
            cli::ProgramContextCommands::Clear(args) => Some((&args.options).into()),
        },
        Commands::Program(cli::ProgramCommands::Rebase(args)) => Some((&args.options).into()),
        Commands::Equate(cmd) => match cmd {
            cli::EquateCommands::List(opts) => Some(opts.clone()),
            cli::EquateCommands::Get(args) | cli::EquateCommands::Delete(args) => {
                Some((&args.options).into())
            }
            cli::EquateCommands::Create(args) => Some((&args.options).into()),
            cli::EquateCommands::Attach(args) | cli::EquateCommands::Detach(args) => {
                Some((&args.options).into())
            }
        },
        Commands::Namespace(cmd) => match cmd {
            cli::NamespaceCommands::List(opts) => Some(opts.clone()),
            cli::NamespaceCommands::Get(args) => Some((&args.options).into()),
            cli::NamespaceCommands::Create(args) => Some((&args.options).into()),
            cli::NamespaceCommands::Rename(args) => Some((&args.options).into()),
            cli::NamespaceCommands::Move(args) => Some((&args.options).into()),
            cli::NamespaceCommands::Delete(args) => Some((&args.options).into()),
        },
        Commands::Analysis(cli::AnalysisCommands::Option(cmd)) => match cmd {
            cli::AnalysisOptionCommands::List(opts) => Some(opts.clone()),
            cli::AnalysisOptionCommands::Get(args) => Some((&args.options).into()),
            cli::AnalysisOptionCommands::Set(args) => Some((&args.options).into()),
        },
        Commands::Decompile(args) => Some((&args.options).into()),
        Commands::Disasm(args) => Some(args.options.clone()),
        Commands::Listing(cli::ListingCommands::Flow(cmd)) => Some(cmd.options().into()),
        Commands::Program(cli::ProgramCommands::Info(args) | cli::ProgramCommands::Stats(args)) => {
            Some((&args.options).into())
        }
        Commands::Program(
            cli::ProgramCommands::ListRelocations(args)
            | cli::ProgramCommands::ListCallingConventions(args),
        ) => Some(args.options.clone()),
        Commands::Symbol(
            cli::SymbolCommands::Externals(opts) | cli::SymbolCommands::EntryPoints(opts),
        ) => Some(opts.clone()),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::Tag(cmd) => match cmd {
                cli::TagCommands::List(args) => Some(args.options.clone()),
                cli::TagCommands::Get(args) => Some((&args.options).into()),
                _ => None,
            },
            cli::FunctionCommands::List(args) => Some(args.options.clone()),
            cli::FunctionCommands::Get(args) => Some((&args.options).into()),
            cli::FunctionCommands::SetBody(args) => Some((&args.options).into()),
            cli::FunctionCommands::SetThunk(args) => Some((&args.options).into()),
            cli::FunctionCommands::ClearThunk(args) => Some((&args.options).into()),
            cli::FunctionCommands::CallSignature(cmd) => Some(cmd.options().into()),
            cli::FunctionCommands::Var(cmd) => match cmd {
                cli::FunctionVarCommands::List(args) => Some(args.options.clone()),
                cli::FunctionVarCommands::Get(args) => Some((&args.options).into()),
                cli::FunctionVarCommands::Set(args) => Some((&args.options).into()),
                cli::FunctionVarCommands::InferStruct(args) => Some((&args.options).into()),
            },
            cli::FunctionCommands::Disasm(args) => Some(args.options.clone()),
            cli::FunctionCommands::Delete(args) => Some(QueryOptions {
                program: args.program.clone(),
                project: args.project.clone(),
                fields: args.fields.clone(),
                exclude_fields: args.exclude_fields.clone(),
                format: args.format,
                filter: None,
                limit: None,
                skip: None,
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
            cli::MemoryCommands::FileMappings(args) => Some(args.options.clone()),
            cli::MemoryCommands::Block(cmd) => Some(cmd.options()),
            cli::MemoryCommands::Info(args) => Some((&args.options).into()),
            cli::MemoryCommands::Read(args) => Some((&args.options).into()),
            cli::MemoryCommands::ReadVtable(args) => Some((&args.options).into()),
            _ => None,
        },
        Commands::Data(cmd) => match cmd {
            cli::DataCommands::List(opts) => Some(opts.clone()),
            cli::DataCommands::Read(args) => Some((&args.options).into()),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => Some(args.options.clone()),
            cli::XRefCommands::From(args) => Some(args.options.clone()),
            cli::XRefCommands::Create(args) => Some((&args.options).into()),
            cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args) => {
                Some((&args.options).into())
            }
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => Some(opts.clone()),
            cli::SymbolCommands::Get(args) => Some(args.options.clone()),
            cli::SymbolCommands::Delete(args) => Some((&args.options).into()),
            cli::SymbolCommands::SetNamespace(args) => Some((&args.options).into()),
            cli::SymbolCommands::SetPrimary(args) => Some((&args.options).into()),
            _ => None,
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => Some(opts.clone()),
            cli::TypeCommands::Get(args) => Some((&args.options).into()),
            cli::TypeCommands::Uses(args) => Some(args.options.clone()),
            cli::TypeCommands::Archive(
                cli::TypeArchiveCommands::Import(args) | cli::TypeArchiveCommands::Export(args),
            ) => Some((&args.options).into()),
            cli::TypeCommands::Archive(cli::TypeArchiveCommands::Inspect(args)) => {
                Some((&args.options).into())
            }
            cli::TypeCommands::Clone(args) => Some((&args.options).into()),
            cli::TypeCommands::Resize(args) => Some((&args.options).into()),
            cli::TypeCommands::Move(args) => Some((&args.options).into()),
            cli::TypeCommands::Category(cmd) => match cmd {
                cli::TypeCategoryCommands::List(args) => Some(args.options.clone()),
                cli::TypeCategoryCommands::Create(args)
                | cli::TypeCategoryCommands::Delete(args) => Some((&args.options).into()),
            },
            cli::TypeCommands::Field(cli::TypeFieldCommands::CreateBitfield(args)) => {
                Some((&args.options).into())
            }
            cli::TypeCommands::Field(cli::TypeFieldCommands::Uses(args)) => {
                Some(args.options.clone())
            }
            _ => None,
        },
        Commands::Bookmark(cmd) => match cmd {
            cli::BookmarkCommands::List(opts) => Some(opts.clone()),
            cli::BookmarkCommands::Get(args) => Some(args.options.clone()),
            cli::BookmarkCommands::Set(args) => Some((&args.options).into()),
            cli::BookmarkCommands::Delete(args) => Some((&args.options).into()),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => Some(opts.clone()),
            cli::CommentCommands::Get(args) => Some(args.options.clone()),
            cli::CommentCommands::Delete(args) => Some(QueryOptions {
                program: args.program.clone(),
                project: args.project.clone(),
                fields: args.fields.clone(),
                exclude_fields: args.exclude_fields.clone(),
                format: args.format,
                filter: None,
                limit: None,
                skip: None,
                sort: None,
                count: false,
                json: false,
            }),
            _ => None,
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Cfg(_) => None,
            cli::GraphCommands::Calls(opts) => Some(opts.clone()),
            cli::GraphCommands::Callers(args) => Some(args.options.clone()),
            cli::GraphCommands::Callees(args) => Some(args.options.clone()),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::VirtualCallers(args) => Some(args.options.clone()),
            cli::FindCommands::AddressTables(args) => Some(args.options.clone()),
            cli::FindCommands::FunctionCandidates(args) => Some(args.options.clone()),
            cli::FindCommands::String(args) => Some(args.options.clone()),
            cli::FindCommands::Text(args) => Some(args.options.clone()),
            cli::FindCommands::Bytes(args) => Some(args.options.clone()),
            cli::FindCommands::Instruction(args) => Some(args.options.clone()),
            cli::FindCommands::Constant(args) => Some(args.options.clone()),
        },
        _ => None,
    }
}

/// Must match the fetch arguments forwarded by execute_via_bridge.
pub(in crate::app) fn query_fetch_support(command: &Commands) -> crate::query::FetchSupport {
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
        | Commands::Function(cli::FunctionCommands::Tag(cli::TagCommands::List(_)))
        | Commands::Graph(
            cli::GraphCommands::Calls(_)
            | cli::GraphCommands::Callers(_)
            | cli::GraphCommands::Callees(_),
        )
        | Commands::Find(
            cli::FindCommands::VirtualCallers(_)
            | cli::FindCommands::AddressTables(_)
            | cli::FindCommands::FunctionCandidates(_)
            | cli::FindCommands::Text(_)
            | cli::FindCommands::Bytes(_)
            | cli::FindCommands::Instruction(_)
            | cli::FindCommands::Constant(_),
        ) => Limit,
        Commands::Disasm(_) => Limit,
        Commands::Data(cli::DataCommands::List(_)) => Limit,
        Commands::Type(
            cli::TypeCommands::Uses(_) | cli::TypeCommands::Field(cli::TypeFieldCommands::Uses(_)),
        ) => Limit,
        _ => Client,
    }
}

/// Validate the command's bounds even when filtering keeps its limit in Rust.
pub(in crate::app) fn validate_query_bounds(
    command: &Commands,
    plan: &crate::query::QueryPlan,
) -> anyhow::Result<()> {
    if let Commands::Find(cli::FindCommands::Constant(args)) = command {
        args.validate().map_err(anyhow::Error::msg)?;
    }
    let int_limit = matches!(
        command,
        Commands::Symbol(cli::SymbolCommands::Externals(_) | cli::SymbolCommands::EntryPoints(_))
            | Commands::Function(cli::FunctionCommands::Tag(cli::TagCommands::List(_)))
            | Commands::Graph(_)
            | Commands::Find(cli::FindCommands::Instruction(_) | cli::FindCommands::Constant(_))
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
    anyhow::ensure!(
        plan.page
            .limit
            .is_none_or(|limit| limit <= i64::MAX as usize),
        "--limit must be between 0 and {} (0 means unlimited)",
        i64::MAX
    );
    anyhow::ensure!(
        plan.page.offset <= i64::MAX as usize,
        "--skip must be between 0 and {}",
        i64::MAX
    );
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
