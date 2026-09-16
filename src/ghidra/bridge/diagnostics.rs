//! Filesystem and transport prerequisites, plus an opt-in real Ghidra lifecycle check.
use super::{import, sources, BridgeStartMode};
use crate::config::Config;
use crate::ipc::client::BridgeClient;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn probe_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| crate::error::path_io("doctor.directory", path, e))?;
    let scratch = tempfile::Builder::new()
        .prefix("ghidra-cli-doctor-")
        .tempdir_in(path)
        .map_err(|e| crate::error::path_io("doctor.create", path, e))?;
    let original = scratch.path().join("write");
    let renamed = scratch.path().join("renamed");
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&original)?;
        file.write_all(b"ghidra-cli doctor\n")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&original, &renamed)?;
        std::fs::remove_file(&renamed)
    })();
    result.map_err(|e| crate::error::path_io("doctor.write_rename_delete", path, e))?;
    scratch
        .close()
        .map_err(|e| crate::error::path_io("doctor.cleanup", path, e))?;
    Ok(())
}

pub fn storage_checks(config: &Config) -> Vec<Value> {
    let config_path = Config::config_path()
        .map_err(anyhow::Error::from)
        .and_then(|path| {
            // Follow existing links just as Config::save does; never replace a link.
            if std::fs::symlink_metadata(&path).is_ok() {
                Ok(dunce::canonicalize(&path)
                    .with_context(|| format!("Resolve configuration {}", path.display()))?)
            } else {
                Ok(path)
            }
        });
    let paths = [
        (
            "config",
            config_path,
            true,
            "GHIDRA_CLI_CONFIG / platform config directory",
        ),
        (
            "bridge_sources",
            sources::root_path(),
            false,
            "platform config directory (XDG_CONFIG_HOME on Linux)",
        ),
        (
            "bridge_state",
            super::data_dir_path(),
            false,
            "platform data directory (XDG_DATA_HOME on Linux)",
        ),
        (
            "projects",
            config.get_project_dir().map_err(anyhow::Error::from),
            false,
            "--projects-dir / GHIDRA_PROJECT_DIR / config / default",
        ),
        (
            "temporary",
            Ok(std::env::temp_dir()),
            false,
            "platform temporary directory",
        ),
    ];
    paths.into_iter().map(|(name, resolved, file, source)| {
        let path = match resolved.and_then(|path| Ok(std::path::absolute(path)?)) {
            Ok(path) => path,
            Err(error) => return json!({"name": name, "ok": false, "source": source, "message": format!("{error:#}")}),
        };
        let directory = if file { path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")) } else { &path };
        match probe_directory(directory) {
            Ok(()) => json!({"name": name, "path": path, "source": source, "ok": true}),
            Err(error) => json!({"name": name, "path": path, "source": source, "ok": false,
                "message": format!("{error:#}"), "detail": crate::error::diagnostic_detail(&error)}),
        }
    }).collect()
}

pub fn loopback_check() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("doctor.loopback_bind: cannot listen on 127.0.0.1")?;
    listener.set_nonblocking(true)?;
    let timeout = Duration::from_secs(2);
    let mut client = TcpStream::connect_timeout(&listener.local_addr()?, timeout)
        .context("doctor.loopback_connect: cannot connect to 127.0.0.1")?;
    client.set_write_timeout(Some(timeout))?;
    let deadline = Instant::now() + timeout;
    let (mut server, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).context("doctor.loopback_accept failed"),
        }
    };
    server.set_read_timeout(Some(timeout))?;
    client.write_all(b"ping")?;
    let mut data = [0; 4];
    server.read_exact(&mut data)?;
    anyhow::ensure!(&data == b"ping", "Loopback data did not match");
    Ok(())
}

pub fn runtime_check(config: &Config) -> Result<Value> {
    let install = config.get_ghidra_install_dir()?;
    let directory = config.get_project_dir()?;
    let work = tempfile::Builder::new()
        .prefix("ghidra-cli-doctor-")
        .tempdir_in(&directory)
        .with_context(|| format!("Create diagnostic project in {}", directory.display()))?;
    let project: PathBuf = work.path().join("doctor");
    let receipt = import::run_bootstrap(
        &project,
        &install,
        &json!({"create_project": true}),
        Some(config.get_launch_timeout()),
    )?;
    let port = super::ensure_bridge_running(&project, &install, BridgeStartMode::Project)?;
    let ping = BridgeClient::new(port).ping();
    if let Err(error) = super::stop_bridge(&project) {
        let retained = work.keep();
        return Err(error).with_context(|| {
            format!(
                "Diagnostic bridge could not stop; project retained at {}",
                retained.display()
            )
        });
    }
    anyhow::ensure!(ping?, "Diagnostic bridge did not respond to ping");
    work.close()
        .context("Could not remove diagnostic project after shutdown")?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_probe_cleans_up_and_reports_blocking_path() {
        let temp = tempfile::tempdir().unwrap();
        probe_directory(temp.path()).unwrap();
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
        let file = temp.path().join("file");
        std::fs::write(&file, "retain").unwrap();
        let path = file.join("child");
        let error = probe_directory(&path).unwrap_err();
        assert_eq!(crate::error::diagnostic_detail(&error)["path"], json!(path));
        assert_eq!(std::fs::read_to_string(file).unwrap(), "retain");
    }
}
