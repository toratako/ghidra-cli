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
        /// Job UUID
        #[arg(value_parser = parse_job_id)]
        job_id: String,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Retrieve a completed job's response; exit 0 means retrieval, even if the job failed
    Result {
        /// Job UUID
        #[arg(value_parser = parse_job_id)]
        job_id: String,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
    /// Request cooperative cancellation (defaults to the active job)
    Cancel {
        /// Job UUID; omit to cancel the currently active job
        #[arg(value_parser = parse_job_id)]
        job_id: Option<String>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
}

fn parse_job_id(value: &str) -> Result<String, String> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| "job ID must be a UUID".to_owned())?;
    let canonical = id.to_string();
    if !canonical.eq_ignore_ascii_case(value) {
        return Err("job ID must be a UUID".to_owned());
    }
    Ok(canonical)
}
