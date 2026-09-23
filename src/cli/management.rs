use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum BridgeCommands {
    /// Start the bridge
    Start {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },
    /// Stop the bridge
    Stop {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Restart the bridge
    Restart {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },
    /// Show bridge status
    Status {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Ping the bridge
    Ping {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum JobCommands {
    /// List active, queued, and recently completed jobs
    List {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Show one job by ID
    Get {
        /// Job ID
        #[arg(value_parser = super::numeric::parse::<u64>)]
        job_id: u64,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Request cooperative cancellation (defaults to the active job)
    Cancel {
        /// Job ID; omit to cancel the currently active job
        #[arg(value_parser = super::numeric::parse::<u64>)]
        job_id: Option<u64>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
}
