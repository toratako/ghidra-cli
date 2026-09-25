use crate::cli::{self, Commands};

/// Extract the project name from a command's args (if present).
pub(in crate::app) fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::Tag(cmd) => match cmd {
                cli::TagCommands::List(args) => args.options.project.clone(),
                cli::TagCommands::Get(args) => args.options.project.clone(),
                cli::TagCommands::Create(args) => args.project.clone(),
                cli::TagCommands::Delete(args) => args.project.clone(),
                cli::TagCommands::Rename(args) => args.project.clone(),
                cli::TagCommands::SetComment(args) => args.project.clone(),
                cli::TagCommands::Attach(args) => args.project.clone(),
                cli::TagCommands::Detach(args) => args.project.clone(),
            },
            cli::FunctionCommands::List(args) => args.options.project.clone(),
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
            cli::MemoryCommands::FileMappings(args) => args.options.project.clone(),
            cli::MemoryCommands::Block(cmd) => cmd.options().project,
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
            cli::XRefCommands::Create(args) => args.options.project.clone(),
            cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args) => {
                args.options.project.clone()
            }
        },
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::Listing(cmd) => match cmd {
            cli::ListingCommands::DefineCode(args) => args.project.clone(),
            cli::ListingCommands::DefineData(args) => args.project.clone(),
            cli::ListingCommands::Undefine(args) => args.project.clone(),
            cli::ListingCommands::Flow(cmd) => cmd.options().project.clone(),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::VirtualCallers(args) => args.options.project.clone(),
            cli::FindCommands::AddressTables(args) => args.options.project.clone(),
            cli::FindCommands::FunctionCandidates(args) => args.options.project.clone(),
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
            cli::TypeCommands::ImportC(args) => args.project.clone(),
            cli::TypeCommands::Archive(
                cli::TypeArchiveCommands::Import(args) | cli::TypeArchiveCommands::Export(args),
            ) => args.options.project.clone(),
            cli::TypeCommands::Archive(cli::TypeArchiveCommands::Inspect(args)) => {
                args.options.project.clone()
            }
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
            cli::ProgramCommands::ListRelocations(args)
            | cli::ProgramCommands::ListCallingConventions(args) => args.options.project.clone(),
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
            cli::NamespaceCommands::Rename(args) => args.options.project.clone(),
            cli::NamespaceCommands::Move(args) => args.options.project.clone(),
            cli::NamespaceCommands::Delete(args) => args.options.project.clone(),
        },
        Commands::Batch(args) => args.project.clone(),
        _ => None,
    }
}

/// Extract the --program argument from a command's args, if present.
/// Binds the requested program to each bridge operation for this command.
pub(in crate::app) fn extract_program_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Decompile(args) => args.options.program.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::Tag(cmd) => match cmd {
                cli::TagCommands::List(args) => args.options.program.clone(),
                cli::TagCommands::Get(args) => args.options.program.clone(),
                cli::TagCommands::Create(args) => args.program.clone(),
                cli::TagCommands::Delete(args) => args.program.clone(),
                cli::TagCommands::Rename(args) => args.program.clone(),
                cli::TagCommands::SetComment(args) => args.program.clone(),
                cli::TagCommands::Attach(args) => args.program.clone(),
                cli::TagCommands::Detach(args) => args.program.clone(),
            },
            cli::FunctionCommands::List(args) => args.options.program.clone(),
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
            cli::MemoryCommands::FileMappings(args) => args.options.program.clone(),
            cli::MemoryCommands::Block(cmd) => cmd.options().program,
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
            cli::XRefCommands::Create(args) => args.options.program.clone(),
            cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args) => {
                args.options.program.clone()
            }
        },
        Commands::Disasm(args) => args.options.program.clone(),
        Commands::Listing(cmd) => match cmd {
            cli::ListingCommands::DefineCode(args) => args.program.clone(),
            cli::ListingCommands::DefineData(args) => args.program.clone(),
            cli::ListingCommands::Undefine(args) => args.program.clone(),
            cli::ListingCommands::Flow(cmd) => cmd.options().program.clone(),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::VirtualCallers(args) => args.options.program.clone(),
            cli::FindCommands::AddressTables(args) => args.options.program.clone(),
            cli::FindCommands::FunctionCandidates(args) => args.options.program.clone(),
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
            cli::TypeCommands::ImportC(args) => args.program.clone(),
            cli::TypeCommands::Archive(
                cli::TypeArchiveCommands::Import(args) | cli::TypeArchiveCommands::Export(args),
            ) => args.options.program.clone(),
            cli::TypeCommands::Archive(cli::TypeArchiveCommands::Inspect(_)) => None,
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
            cli::ProgramCommands::ListRelocations(args)
            | cli::ProgramCommands::ListCallingConventions(args) => {
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
            cli::NamespaceCommands::Rename(args) => args.options.program.clone(),
            cli::NamespaceCommands::Move(args) => args.options.program.clone(),
            cli::NamespaceCommands::Delete(args) => args.options.program.clone(),
        },
        Commands::Batch(args) => args.program.clone(),
        _ => None,
    }
}
