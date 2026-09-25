use crate::error::{path_io, GhidraError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const CONFIG_LOCK_FILE: &str = ".ghidra-cli-config.lock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ghidra_install_dir: Option<PathBuf>,
    #[serde(default)]
    pub ghidra_jar: Option<PathBuf>,
    pub ghidra_project_dir: Option<PathBuf>,
    /// Per-invocation project directory override; never read from or written to YAML.
    #[serde(skip)]
    pub projects_dir_override: Option<PathBuf>,
    /// Full JDK home for Ghidra to use (must be a JDK, not a JRE). When unset,
    /// ghidra-cli auto-detects a suitable JDK.
    #[serde(default)]
    pub java_home: Option<PathBuf>,
    pub default_program: Option<String>,
    pub default_project: Option<String>,
    pub default_output_format: Option<String>,
    pub default_limit: Option<usize>,
    /// Bounded cap (seconds) for bridge launch readiness: JVM start + OSGi
    /// compile + project open + binary load. Does NOT cover analysis, which runs
    /// as an unbounded TCP operation. Overridable via `GHIDRA_CLI_LAUNCH_TIMEOUT`.
    /// Defaults to 180s when unset (must accommodate the first-run OSGi compile).
    #[serde(default)]
    pub launch_timeout_secs: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ghidra_install_dir: None,
            ghidra_jar: None,
            ghidra_project_dir: None,
            projects_dir_override: None,
            java_home: None,
            default_program: None,
            default_project: None,
            default_output_format: Some("auto".to_string()),
            default_limit: Some(1000),
            launch_timeout_secs: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::config_path()?)
    }

    fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(content) => Ok(serde_yaml::from_str(&content)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(path_io("config.read", path, error)),
        }
    }

    /// Replace the configuration atomically. For read-modify-write changes use
    /// `update`, which also holds the lock while reading the current values.
    pub fn save(&self) -> Result<()> {
        self.save_at(&Self::config_path()?)
    }

    fn save_at(&self, path: &Path) -> Result<()> {
        let (path, _lock) = Self::locked_write_path(path)?;
        self.save_to(&path)
    }

    /// Serialize a configuration change with other CLI processes. A failed
    /// callback or write leaves the previously published configuration intact.
    pub fn update(change: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        Self::update_at(&Self::config_path()?, change)
    }

    fn update_at(path: &Path, change: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        let (path, _lock) = Self::locked_write_path(path)?;
        let mut config = Self::load_from(&path)?;
        change(&mut config)?;
        config.save_to(&path)?;
        Ok(config)
    }

    fn locked_write_path(path: &Path) -> Result<(PathBuf, fs::File)> {
        // Lock the stable parent before canonicalizing the replaceable file. A
        // file-specific lock chosen after canonicalizing the file races with
        // another process replacing it on Windows.
        let mut path = path.to_path_buf();
        let mut followed_link = false;
        let mut seen = HashSet::new();
        loop {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            if !followed_link {
                fs::create_dir_all(parent).map_err(|e| path_io("config.directory", parent, e))?;
            }
            let parent =
                dunce::canonicalize(parent).map_err(|e| path_io("config.resolve", parent, e))?;
            let name = path.file_name().ok_or_else(|| {
                GhidraError::ConfigError("Configuration path must name a file".into())
            })?;
            let candidate = parent.join(name);
            let lock_path = parent.join(CONFIG_LOCK_FILE);
            if candidate == lock_path {
                return Err(GhidraError::ConfigError(
                    "Configuration path conflicts with its lock file".into(),
                ));
            }
            if !seen.insert(candidate.clone()) {
                return Err(path_io(
                    "config.resolve",
                    &candidate,
                    std::io::Error::other("Configuration symlink loop"),
                ));
            }
            // CLI updates replace the target, never the link. Follow a link
            // without creating a lock file in its directory; the target's
            // parent lock coordinates direct and symlink callers.
            if fs::symlink_metadata(&candidate).is_ok_and(|m| m.file_type().is_symlink()) {
                path = Self::link_target(&candidate, &parent)?;
                followed_link = true;
                continue;
            }
            let lock = Self::lock(&parent)?;
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    path = Self::link_target(&candidate, &parent)?;
                    followed_link = true;
                }
                Ok(_) => {
                    let resolved = dunce::canonicalize(&candidate)
                        .map_err(|e| path_io("config.resolve", &candidate, e))?;
                    if resolved == lock_path {
                        return Err(GhidraError::ConfigError(
                            "Configuration path conflicts with its lock file".into(),
                        ));
                    }
                    return Ok((resolved, lock));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !followed_link => {
                    return Ok((candidate, lock));
                }
                Err(error) => return Err(path_io("config.resolve", &candidate, error)),
            }
        }
    }

    fn link_target(path: &Path, parent: &Path) -> Result<PathBuf> {
        let target = fs::read_link(path).map_err(|e| path_io("config.resolve", path, e))?;
        Ok(if target.is_absolute() {
            target
        } else {
            parent.join(target)
        })
    }

    fn lock(parent: &Path) -> Result<fs::File> {
        // Keep the lock file: unlinking it could let another process lock a
        // different inode. Closing the handle releases the OS-backed lock.
        let lock_path = parent.join(CONFIG_LOCK_FILE);
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| path_io("config.lock", &lock_path, e))?;
        lock.lock()
            .map_err(|e| path_io("config.lock", &lock_path, e))?;
        Ok(lock)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let content = serde_yaml::to_string(self)?;
        let mut staged = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| path_io("config.stage", parent, e))?;
        if let Ok(metadata) = fs::metadata(path) {
            staged
                .as_file()
                .set_permissions(metadata.permissions())
                .map_err(|e| path_io("config.permissions", path, e))?;
        }
        staged
            .write_all(content.as_bytes())
            .map_err(|e| path_io("config.write", path, e))?;
        staged
            .as_file()
            .sync_all()
            .map_err(|e| path_io("config.sync", path, e))?;
        // tempfile::persist uses MoveFileExW on Windows, which cannot replace
        // a destination held open by a reader.
        // std::fs::rename also supports POSIX replacement semantics there.
        // Clear tempfile's temporary attribute and retain cleanup on failure.
        let (file, staged_path) = staged
            .keep()
            .map_err(|error| path_io("config.publish", path, error.error))?;
        let mut staged_path = tempfile::TempPath::try_from_path(staged_path)
            .map_err(|error| path_io("config.publish", path, error))?;
        drop(file);
        fs::rename(&staged_path, path).map_err(|error| path_io("config.publish", path, error))?;
        staged_path.disable_cleanup(true);
        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        // Check for override via environment variable
        if let Ok(path) = std::env::var("GHIDRA_CLI_CONFIG") {
            return Ok(PathBuf::from(path));
        }

        let config_dir = dirs::config_dir().ok_or_else(|| {
            GhidraError::ConfigError("Could not determine config directory".to_string())
        })?;

        Ok(config_dir.join("ghidra-cli").join("config.yaml"))
    }

    pub fn get_ghidra_installation(&self) -> Result<crate::ghidra::installation::Installation> {
        crate::ghidra::installation::resolve(self)
    }

    pub fn get_project_dir(&self) -> Result<PathBuf> {
        if let Some(dir) = &self.projects_dir_override {
            return Ok(dir.clone());
        }
        // Environment overrides the persisted setting.
        if let Ok(dir) = std::env::var("GHIDRA_PROJECT_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_project_dir {
            return Ok(dir.clone());
        }

        Self::default_project_dir()
    }

    /// Default location for Ghidra projects when neither the `GHIDRA_PROJECT_DIR`
    /// env var nor `ghidra_project_dir` config is set.
    ///
    /// Ghidra 12.1+ rejects any project *location* directory whose path contains a
    /// component beginning with '.' (`ProjectLocator` ->
    /// `GhidraURL.checkLocalAbsolutePath` -> `NamingUtilities.checkName`). On Linux
    /// every XDG base directory lives under a hidden directory (`~/.cache`,
    /// `~/.local/share`, `~/.config`), so the cache-dir default is unusable there.
    /// macOS (`~/Library/Caches`) and Windows (`~/AppData/Local`) have no hidden
    /// components, so we keep the cache-dir location for them and only fall back to
    /// a non-hidden `~/ghidra-cli-projects` when the cache path has a dot element.
    pub fn default_project_dir() -> Result<PathBuf> {
        if let Some(cache_dir) = dirs::cache_dir() {
            let candidate = cache_dir.join("ghidra-cli").join("projects");
            if !has_hidden_component(&candidate) {
                return Ok(candidate);
            }
        }

        let home = dirs::home_dir().ok_or_else(|| {
            GhidraError::ConfigError("Could not determine home directory".to_string())
        })?;
        Ok(home.join("ghidra-cli-projects"))
    }

    /// Explicit JDK home override: `GHIDRA_CLI_JAVA_HOME` env (set from the
    /// `--java-home` flag in main) takes precedence over the config value.
    pub fn get_java_home(&self) -> Option<PathBuf> {
        std::env::var_os("GHIDRA_CLI_JAVA_HOME")
            .map(PathBuf::from)
            .or_else(|| self.java_home.clone())
    }

    /// Bounded cap for bridge launch readiness. `GHIDRA_CLI_LAUNCH_TIMEOUT`
    /// (seconds) overrides the config value, which overrides the 180s default.
    pub fn get_launch_timeout(&self) -> std::time::Duration {
        let secs = std::env::var("GHIDRA_CLI_LAUNCH_TIMEOUT")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .or(self.launch_timeout_secs)
            .unwrap_or(180);
        std::time::Duration::from_secs(secs)
    }
}

/// Whether any normal component of `path` begins with '.' (a hidden directory).
/// Ghidra 12.1+ rejects such components in a project location path.
fn has_hidden_component(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::Normal(s) if s.to_string_lossy().starts_with('.')))
}

#[cfg(test)]
mod tests;
