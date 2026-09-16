use thiserror::Error;

#[derive(Error, Debug)]
pub enum GhidraError {
    #[error("Ghidra installation not found. Set GHIDRA_INSTALL_DIR or run 'ghidra-cli init'")]
    GhidraNotFound,

    #[error("Failed to parse filter: {0}")]
    FilterParseError(String),

    #[error("Invalid filter expression: {0}")]
    InvalidFilter(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[allow(dead_code)]
    #[error("Invalid data type: {0}")]
    InvalidDataType(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("{stage} failed at {path}: {source}")]
    PathIo {
        stage: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

pub type Result<T> = std::result::Result<T, GhidraError>;

pub(crate) fn path_io(
    stage: &'static str,
    path: &std::path::Path,
    source: std::io::Error,
) -> GhidraError {
    GhidraError::PathIo {
        stage,
        path: path.to_owned(),
        source,
    }
}

/// Share structured diagnostics between standalone errors and workflow checkpoints.
pub(crate) fn diagnostic_detail(error: &anyhow::Error) -> serde_json::Value {
    let mut detail = error
        .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
        .map(|error| error.detail.clone())
        .unwrap_or_else(|| serde_json::json!({}));
    for cause in error.chain() {
        if let Some(GhidraError::PathIo {
            stage,
            path,
            source,
        }) = cause.downcast_ref::<GhidraError>()
        {
            detail["stage"] = serde_json::json!(stage);
            detail["path"] = serde_json::json!(path);
            detail["cause"] = serde_json::json!(source.to_string());
            detail["os_error"] = serde_json::json!(source.raw_os_error());
            break;
        }
    }
    detail
}
