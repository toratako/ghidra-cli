mod query;
mod target;

use crate::cli::Commands;

pub(super) use query::{extract_query_options, query_fetch_support, validate_query_bounds};
pub(super) use target::{extract_program_from_command, extract_project_from_command};

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
