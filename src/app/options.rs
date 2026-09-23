use crate::cli::{self, Commands, QueryOptions};

/// Determines if a command requires the bridge to be running.
pub(super) fn requires_bridge(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Decompile(_)
            | Commands::Function(_)
            | Commands::Strings(_)
            | Commands::Memory(_)
            | Commands::Data(_)
            | Commands::XRef(_)
            | Commands::Symbol(_)
            | Commands::Equate(_)
            | Commands::Namespace(_)
            | Commands::Type(_)
            | Commands::Tag(_)
            | Commands::Pcode(_)
            | Commands::Analysis(_)
            | Commands::Comment(_)
            | Commands::Bookmark(_)
            | Commands::Graph(_)
            | Commands::Find(_)
            | Commands::Script(_)
            | Commands::Disasm(_)
            | Commands::Listing(_)
            | Commands::Batch(_)
            | Commands::Program(_)
    )
}

/// Extract the project name from a command's args (if present).
pub(super) fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.project.clone(),
            cli::FunctionCommands::ListCallingConventions(opts) => opts.project.clone(),
            cli::FunctionCommands::Get(args) => args.options.project.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.project.clone(),
            cli::FunctionCommands::Rename(args) => args.project.clone(),
            cli::FunctionCommands::Create(args) => args.project.clone(),
            cli::FunctionCommands::Delete(args) => args.project.clone(),
            cli::FunctionCommands::SetSignature(args) => args.project.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.project.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.project.clone(),
            cli::FunctionCommands::SetStackPurge(args) => args.project.clone(),
            cli::FunctionCommands::SetBody(args) => args.options.project.clone(),
            cli::FunctionCommands::SetThunk(args) => args.options.project.clone(),
            cli::FunctionCommands::ClearThunk(args) => args.options.project.clone(),
            cli::FunctionCommands::CallSignature(cmd) => cmd.options().project.clone(),
            cli::FunctionCommands::Var(cmd) => match cmd {
                cli::FunctionVarCommands::List(args) => args.options.project.clone(),
                cli::FunctionVarCommands::Get(args) => args.options.project.clone(),
                cli::FunctionVarCommands::Set(args) => args.options.project.clone(),
                cli::FunctionVarCommands::InferStruct(args) => args.options.project.clone(),
            },
            cli::FunctionCommands::SetNoReturn(args) => args.project.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.project.clone(),
            cli::StringsCommands::Refs(args) => args.options.project.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.project.clone(),
            cli::MemoryCommands::FileMappings(args) => args.options.project.clone(),
            cli::MemoryCommands::Block(cmd) => cmd.options().project.clone(),
            cli::MemoryCommands::Info(args) => args.options.project.clone(),
            cli::MemoryCommands::Read(args) => args.options.project.clone(),
            cli::MemoryCommands::ReadVtable(args) => args.options.project.clone(),
            cli::MemoryCommands::Write(args) => args.project.clone(),
        },
        Commands::Data(cmd) => match cmd {
            cli::DataCommands::List(opts) => opts.project.clone(),
            cli::DataCommands::Read(args) => args.options.project.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.project.clone(),
            cli::XRefCommands::From(args) => args.options.project.clone(),
            cli::XRefCommands::Create(cli::XRefCreateCommands::Memory(args)) => {
                args.options.project.clone()
            }
            cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args) => {
                args.options.project.clone()
            }
        },
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::Listing(cmd) => match cmd {
            cli::ListingCommands::DefineCode(args) => args.project.clone(),
            cli::ListingCommands::Undefine(args) => args.project.clone(),
            cli::ListingCommands::Flow(cmd) => cmd.options().project.clone(),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::VirtualCallers(args) => args.options.project.clone(),
            cli::FindCommands::AddressTables(args) => args.options.project.clone(),
            cli::FindCommands::String(args) => args.options.project.clone(),
            cli::FindCommands::Text(args) => args.options.project.clone(),
            cli::FindCommands::Bytes(args) => args.options.project.clone(),
            cli::FindCommands::Instruction(args) => args.options.project.clone(),
            cli::FindCommands::Constant(args) => args.options.project.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Cfg(args) => args.project.clone(),
            cli::GraphCommands::Calls(opts) => opts.project.clone(),
            cli::GraphCommands::Callers(args) => args.options.project.clone(),
            cli::GraphCommands::Callees(args) => args.options.project.clone(),
        },
        Commands::Bookmark(cmd) => match cmd {
            cli::BookmarkCommands::List(opts) => opts.project.clone(),
            cli::BookmarkCommands::Get(args) => args.options.project.clone(),
            cli::BookmarkCommands::Set(args) => args.options.project.clone(),
            cli::BookmarkCommands::Delete(args) => args.options.project.clone(),
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
            cli::SymbolCommands::SetNamespace(args) => args.options.project.clone(),
            cli::SymbolCommands::SetPrimary(args) => args.options.project.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.project.clone(),
            cli::TypeCommands::Get(args) => args.options.project.clone(),
            cli::TypeCommands::Uses(args) => args.options.project.clone(),
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
            cli::TypeCommands::Clone(args) => args.options.project.clone(),
            cli::TypeCommands::Resize(args) => args.options.project.clone(),
            cli::TypeCommands::Move(args) => args.options.project.clone(),
            cli::TypeCommands::Category(cmd) => match cmd {
                cli::TypeCategoryCommands::List(args) => args.options.project.clone(),
                cli::TypeCategoryCommands::Create(args)
                | cli::TypeCategoryCommands::Delete(args) => args.options.project.clone(),
            },
            cli::TypeCommands::Field(cmd) => match cmd {
                cli::TypeFieldCommands::Uses(args) => args.options.project.clone(),
                cli::TypeFieldCommands::Append(args) => args.project.clone(),
                cli::TypeFieldCommands::CreateBitfield(args) => args.options.project.clone(),
                cli::TypeFieldCommands::Set(args) => args.project.clone(),
                cli::TypeFieldCommands::Clear(args) => args.project.clone(),
                cli::TypeFieldCommands::Delete(args) => args.project.clone(),
            },
            cli::TypeCommands::Enum(cli::TypeEnumCommands::Member(cmd)) => match cmd {
                cli::TypeEnumMemberCommands::Delete(args) => args.project.clone(),
            },
        },
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => args.options.project.clone(),
            cli::TagCommands::Get(args) => args.options.project.clone(),
            cli::TagCommands::Create(args) => args.project.clone(),
            cli::TagCommands::Delete(args) => args.project.clone(),
            cli::TagCommands::Rename(args) => args.project.clone(),
            cli::TagCommands::SetComment(args) => args.project.clone(),
            cli::TagCommands::Attach(args) => args.project.clone(),
            cli::TagCommands::Detach(args) => args.project.clone(),
        },
        Commands::Pcode(cmd) => match cmd {
            cli::PcodeCommands::At(args) => args.project.clone(),
            cli::PcodeCommands::Function(args) => args.project.clone(),
        },
        Commands::Analysis(cmd) => match cmd {
            cli::AnalysisCommands::Run(args) => args.project.clone(),
            cli::AnalysisCommands::Option(cmd) => match cmd {
                cli::AnalysisOptionCommands::List(opts) => opts.project.clone(),
                cli::AnalysisOptionCommands::Get(args) => args.options.project.clone(),
                cli::AnalysisOptionCommands::Set(args) => args.options.project.clone(),
            },
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.project.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::Context(cmd) => match cmd {
                cli::ProgramContextCommands::List(opts) => opts.project.clone(),
                cli::ProgramContextCommands::Get(args) => args.options.project.clone(),
                cli::ProgramContextCommands::Set(args) => args.options.project.clone(),
                cli::ProgramContextCommands::Clear(args) => args.options.project.clone(),
            },
            cli::ProgramCommands::Rebase(args) => args.options.project.clone(),
            cli::ProgramCommands::Import(args) => args.project.clone(),
            cli::ProgramCommands::ListRelocations(args) => args.options.project.clone(),
            cli::ProgramCommands::List(args) => args.project.clone(),
            cli::ProgramCommands::Open(args) => args.project.clone(),
            cli::ProgramCommands::Close(args) => args.project.clone(),
            cli::ProgramCommands::Delete(args) => args.project.clone(),
            cli::ProgramCommands::Info(args) | cli::ProgramCommands::Stats(args) => {
                args.options.project.clone()
            }
            cli::ProgramCommands::Export(args) => args.project.clone(),
            cli::ProgramCommands::Save(args) => args.project.clone(),
        },
        Commands::Equate(cmd) => match cmd {
            cli::EquateCommands::List(opts) => opts.project.clone(),
            cli::EquateCommands::Get(args) | cli::EquateCommands::Delete(args) => {
                args.options.project.clone()
            }
            cli::EquateCommands::Create(args) => args.options.project.clone(),
            cli::EquateCommands::Attach(args) | cli::EquateCommands::Detach(args) => {
                args.options.project.clone()
            }
        },
        Commands::Namespace(cmd) => match cmd {
            cli::NamespaceCommands::List(opts) => opts.project.clone(),
            cli::NamespaceCommands::Get(args) => args.options.project.clone(),
            cli::NamespaceCommands::Create(args) => args.options.project.clone(),
        },
        Commands::Batch(args) => args.project.clone(),
        _ => None,
    }
}

/// Extract the --program argument from a command's args, if present.
/// Binds the requested program to each bridge operation for this command.
pub(super) fn extract_program_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Decompile(args) => args.options.program.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => args.options.program.clone(),
            cli::FunctionCommands::ListCallingConventions(opts) => opts.program.clone(),
            cli::FunctionCommands::Get(args) => args.options.program.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.program.clone(),
            cli::FunctionCommands::Rename(args) => args.program.clone(),
            cli::FunctionCommands::Create(args) => args.program.clone(),
            cli::FunctionCommands::Delete(args) => args.program.clone(),
            cli::FunctionCommands::SetSignature(args) => args.program.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.program.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.program.clone(),
            cli::FunctionCommands::SetStackPurge(args) => args.program.clone(),
            cli::FunctionCommands::SetBody(args) => args.options.program.clone(),
            cli::FunctionCommands::SetThunk(args) => args.options.program.clone(),
            cli::FunctionCommands::ClearThunk(args) => args.options.program.clone(),
            cli::FunctionCommands::CallSignature(cmd) => cmd.options().program.clone(),
            cli::FunctionCommands::Var(cmd) => match cmd {
                cli::FunctionVarCommands::List(args) => args.options.program.clone(),
                cli::FunctionVarCommands::Get(args) => args.options.program.clone(),
                cli::FunctionVarCommands::Set(args) => args.options.program.clone(),
                cli::FunctionVarCommands::InferStruct(args) => args.options.program.clone(),
            },
            cli::FunctionCommands::SetNoReturn(args) => args.program.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.program.clone(),
            cli::StringsCommands::Refs(args) => args.options.program.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.program.clone(),
            cli::MemoryCommands::FileMappings(args) => args.options.program.clone(),
            cli::MemoryCommands::Block(cmd) => cmd.options().program.clone(),
            cli::MemoryCommands::Info(args) => args.options.program.clone(),
            cli::MemoryCommands::Read(args) => args.options.program.clone(),
            cli::MemoryCommands::ReadVtable(args) => args.options.program.clone(),
            cli::MemoryCommands::Write(args) => args.program.clone(),
        },
        Commands::Data(cmd) => match cmd {
            cli::DataCommands::List(opts) => opts.program.clone(),
            cli::DataCommands::Read(args) => args.options.program.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.program.clone(),
            cli::XRefCommands::From(args) => args.options.program.clone(),
            cli::XRefCommands::Create(cli::XRefCreateCommands::Memory(args)) => {
                args.options.program.clone()
            }
            cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args) => {
                args.options.program.clone()
            }
        },
        Commands::Disasm(args) => args.options.program.clone(),
        Commands::Listing(cmd) => match cmd {
            cli::ListingCommands::DefineCode(args) => args.program.clone(),
            cli::ListingCommands::Undefine(args) => args.program.clone(),
            cli::ListingCommands::Flow(cmd) => cmd.options().program.clone(),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::VirtualCallers(args) => args.options.program.clone(),
            cli::FindCommands::AddressTables(args) => args.options.program.clone(),
            cli::FindCommands::String(args) => args.options.program.clone(),
            cli::FindCommands::Text(args) => args.options.program.clone(),
            cli::FindCommands::Bytes(args) => args.options.program.clone(),
            cli::FindCommands::Instruction(args) => args.options.program.clone(),
            cli::FindCommands::Constant(args) => args.options.program.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Cfg(args) => args.program.clone(),
            cli::GraphCommands::Calls(opts) => opts.program.clone(),
            cli::GraphCommands::Callers(args) => args.options.program.clone(),
            cli::GraphCommands::Callees(args) => args.options.program.clone(),
        },
        Commands::Bookmark(cmd) => match cmd {
            cli::BookmarkCommands::List(opts) => opts.program.clone(),
            cli::BookmarkCommands::Get(args) => args.options.program.clone(),
            cli::BookmarkCommands::Set(args) => args.options.program.clone(),
            cli::BookmarkCommands::Delete(args) => args.options.program.clone(),
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
            cli::SymbolCommands::SetNamespace(args) => args.options.program.clone(),
            cli::SymbolCommands::SetPrimary(args) => args.options.program.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.program.clone(),
            cli::TypeCommands::Get(args) => args.options.program.clone(),
            cli::TypeCommands::Uses(args) => args.options.program.clone(),
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
            cli::TypeCommands::Clone(args) => args.options.program.clone(),
            cli::TypeCommands::Resize(args) => args.options.program.clone(),
            cli::TypeCommands::Move(args) => args.options.program.clone(),
            cli::TypeCommands::Category(cmd) => match cmd {
                cli::TypeCategoryCommands::List(args) => args.options.program.clone(),
                cli::TypeCategoryCommands::Create(args)
                | cli::TypeCategoryCommands::Delete(args) => args.options.program.clone(),
            },
            cli::TypeCommands::Field(cmd) => match cmd {
                cli::TypeFieldCommands::Uses(args) => args.options.program.clone(),
                cli::TypeFieldCommands::Append(args) => args.program.clone(),
                cli::TypeFieldCommands::CreateBitfield(args) => args.options.program.clone(),
                cli::TypeFieldCommands::Set(args) => args.program.clone(),
                cli::TypeFieldCommands::Clear(args) => args.program.clone(),
                cli::TypeFieldCommands::Delete(args) => args.program.clone(),
            },
            cli::TypeCommands::Enum(cli::TypeEnumCommands::Member(cmd)) => match cmd {
                cli::TypeEnumMemberCommands::Delete(args) => args.program.clone(),
            },
        },
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => args.options.program.clone(),
            cli::TagCommands::Get(args) => args.options.program.clone(),
            cli::TagCommands::Create(args) => args.program.clone(),
            cli::TagCommands::Delete(args) => args.program.clone(),
            cli::TagCommands::Rename(args) => args.program.clone(),
            cli::TagCommands::SetComment(args) => args.program.clone(),
            cli::TagCommands::Attach(args) => args.program.clone(),
            cli::TagCommands::Detach(args) => args.program.clone(),
        },
        Commands::Pcode(cmd) => match cmd {
            cli::PcodeCommands::At(args) => args.program.clone(),
            cli::PcodeCommands::Function(args) => args.program.clone(),
        },
        Commands::Analysis(cmd) => match cmd {
            cli::AnalysisCommands::Run(args) => args.program.clone(),
            cli::AnalysisCommands::Option(cmd) => match cmd {
                cli::AnalysisOptionCommands::List(opts) => opts.program.clone(),
                cli::AnalysisOptionCommands::Get(args) => args.options.program.clone(),
                cli::AnalysisOptionCommands::Set(args) => args.options.program.clone(),
            },
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.program.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::Context(cmd) => match cmd {
                cli::ProgramContextCommands::List(opts) => opts.program.clone(),
                cli::ProgramContextCommands::Get(args) => args.options.program.clone(),
                cli::ProgramContextCommands::Set(args) => args.options.program.clone(),
                cli::ProgramContextCommands::Clear(args) => args.options.program.clone(),
            },
            cli::ProgramCommands::Rebase(args) => {
                args.name.clone().or_else(|| args.options.program.clone())
            }
            cli::ProgramCommands::Import(_) => None,
            cli::ProgramCommands::ListRelocations(args) => {
                args.name.clone().or_else(|| args.options.program.clone())
            }
            cli::ProgramCommands::List(_) => None,
            cli::ProgramCommands::Open(args) => Some(args.name.clone()),
            cli::ProgramCommands::Close(args) => args.name.clone().or_else(|| args.program.clone()),
            cli::ProgramCommands::Delete(args) => Some(args.name.clone()),
            cli::ProgramCommands::Info(args) | cli::ProgramCommands::Stats(args) => {
                args.name.clone().or_else(|| args.options.program.clone())
            }
            cli::ProgramCommands::Export(args) => Some(args.name.clone()),
            cli::ProgramCommands::Save(args) => args.name.clone().or_else(|| args.program.clone()),
        },
        Commands::Equate(cmd) => match cmd {
            cli::EquateCommands::List(opts) => opts.program.clone(),
            cli::EquateCommands::Get(args) | cli::EquateCommands::Delete(args) => {
                args.options.program.clone()
            }
            cli::EquateCommands::Create(args) => args.options.program.clone(),
            cli::EquateCommands::Attach(args) | cli::EquateCommands::Detach(args) => {
                args.options.program.clone()
            }
        },
        Commands::Namespace(cmd) => match cmd {
            cli::NamespaceCommands::List(opts) => opts.program.clone(),
            cli::NamespaceCommands::Get(args) => args.options.program.clone(),
            cli::NamespaceCommands::Create(args) => args.options.program.clone(),
        },
        Commands::Batch(args) => args.program.clone(),
        _ => None,
    }
}

/// Extract QueryOptions from a command, if it has them.
pub(super) fn extract_query_options(command: &Commands) -> Option<QueryOptions> {
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
        Commands::Program(cli::ProgramCommands::ListRelocations(args)) => {
            Some(args.options.clone())
        }
        Commands::Symbol(
            cli::SymbolCommands::Externals(opts) | cli::SymbolCommands::EntryPoints(opts),
        ) => Some(opts.clone()),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(args) => Some(args.options.clone()),
            cli::FunctionCommands::ListCallingConventions(opts) => Some(opts.clone()),
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
            cli::MemoryCommands::Map(opts) => Some(opts.clone()),
            cli::MemoryCommands::FileMappings(args) => Some(args.options.clone()),
            cli::MemoryCommands::Block(cmd) => Some(cmd.options().into()),
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
            cli::XRefCommands::Create(cli::XRefCreateCommands::Memory(args)) => {
                Some((&args.options).into())
            }
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
        Commands::Tag(cmd) => match cmd {
            cli::TagCommands::List(args) => Some(args.options.clone()),
            cli::TagCommands::Get(args) => Some((&args.options).into()),
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
            cli::FindCommands::VirtualCallers(_)
            | cli::FindCommands::AddressTables(_)
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
pub(super) fn validate_query_bounds(
    command: &Commands,
    plan: &crate::query::QueryPlan,
) -> anyhow::Result<()> {
    if let Commands::Find(cli::FindCommands::Constant(args)) = command {
        args.validate().map_err(anyhow::Error::msg)?;
    }
    let int_limit = matches!(
        command,
        Commands::Symbol(cli::SymbolCommands::Externals(_) | cli::SymbolCommands::EntryPoints(_))
            | Commands::Tag(cli::TagCommands::List(_))
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
