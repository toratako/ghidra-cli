use thiserror::Error;

#[derive(Error, Debug)]
pub enum GhidraError {
    #[error(transparent)]
    Installation(Box<crate::ghidra::installation::DetectionError>),

    #[error("Failed to parse filter: {0}")]
    FilterParseError(String),

    #[error("Invalid filter expression: {0}")]
    InvalidFilter(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

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

/// Stable machine-readable names; unknown/future standard-library kinds stay "other".
fn io_kind_name(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::HostUnreachable => "host_unreachable",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_not_available",
        ErrorKind::NetworkDown => "network_down",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::NotADirectory => "not_a_directory",
        ErrorKind::IsADirectory => "is_a_directory",
        ErrorKind::DirectoryNotEmpty => "directory_not_empty",
        ErrorKind::ReadOnlyFilesystem => "read_only_filesystem",
        ErrorKind::StaleNetworkFileHandle => "stale_network_file_handle",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::TimedOut => "timed_out",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::StorageFull => "storage_full",
        ErrorKind::NotSeekable => "not_seekable",
        ErrorKind::QuotaExceeded => "quota_exceeded",
        ErrorKind::FileTooLarge => "file_too_large",
        ErrorKind::ResourceBusy => "resource_busy",
        ErrorKind::ExecutableFileBusy => "executable_file_busy",
        ErrorKind::Deadlock => "deadlock",
        ErrorKind::CrossesDevices => "crosses_devices",
        ErrorKind::TooManyLinks => "too_many_links",
        ErrorKind::InvalidFilename => "invalid_filename",
        ErrorKind::ArgumentListTooLong => "argument_list_too_long",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::OutOfMemory => "out_of_memory",
        _ => "other",
    }
}

/// Share structured diagnostics between standalone errors and workflow checkpoints.
pub(crate) fn diagnostic_detail(error: &anyhow::Error) -> serde_json::Value {
    let mut detail = error
        .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
        .map(|error| error.detail.clone())
        .unwrap_or_else(|| serde_json::json!({}));
    if error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_some()
        || error
            .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
            .is_some()
    {
        detail["outcome_unknown"] = serde_json::json!(true);
    }
    if let Some(job) = error.downcast_ref::<crate::ipc::protocol::BridgeJob>() {
        detail["job_id"] = serde_json::json!(job.id);
        detail["command"] = serde_json::json!(job.command);
    }
    for cause in error.chain() {
        if let Some(GhidraError::Installation(error)) = cause.downcast_ref::<GhidraError>() {
            detail["installation"] = serde_json::json!(error);
        }
        if let Some(GhidraError::PathIo {
            stage,
            path,
            source,
        }) = cause.downcast_ref::<GhidraError>()
        {
            detail["stage"] = serde_json::json!(stage);
            detail["path"] = serde_json::json!(path.to_string_lossy());
            detail["cause"] = serde_json::json!(source.to_string());
            // Libraries such as tempfile retain ErrorKind but can hide the
            // native code. Report the kind independently; never parse Display.
            detail["io_kind"] = serde_json::json!(io_kind_name(source.kind()));
            detail["os_error"] = serde_json::json!(source.raw_os_error());
            break;
        }
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Error, ErrorKind};

    #[test]
    fn io_classification_does_not_invent_codes_from_error_text() {
        for (kind, expected) in [
            (ErrorKind::ReadOnlyFilesystem, "read_only_filesystem"),
            (ErrorKind::PermissionDenied, "permission_denied"),
            (ErrorKind::Other, "other"),
        ] {
            let source = Error::new(kind, "wrapped failure (os error 30)");
            let error = anyhow::Error::new(path_io("config.stage", "config.yaml".as_ref(), source))
                .context(crate::ipc::protocol::BridgeCommandError {
                    message: "workflow failed".into(),
                    detail: json!({"import_status": "saved"}),
                });
            let detail = diagnostic_detail(&error);
            assert_eq!(detail["io_kind"], expected);
            assert!(detail["os_error"].is_null());
            assert_eq!(detail["stage"], "config.stage");
            assert_eq!(detail["path"], "config.yaml");
            assert_eq!(detail["import_status"], "saved");
        }
    }

    #[test]
    fn tempfile_failure_retains_kind_when_native_code_is_hidden() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let source = tempfile::tempdir_in(&missing).unwrap_err();
        assert_eq!(source.kind(), ErrorKind::NotFound);
        assert_eq!(source.raw_os_error(), None);
        let detail = diagnostic_detail(&path_io("doctor.create", &missing, source).into());
        assert_eq!(detail["io_kind"], "not_found");
        assert!(detail["os_error"].is_null());
        assert_eq!(detail["path"], json!(missing));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn native_io_failure_retains_its_code_and_classification() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let source = std::fs::File::open(&missing).unwrap_err();
        let code = source.raw_os_error().expect("native filesystem error");
        let detail = diagnostic_detail(&path_io("config.read", &missing, source).into());
        assert_eq!(detail["io_kind"], "not_found");
        assert_eq!(detail["os_error"], code);
    }
}
