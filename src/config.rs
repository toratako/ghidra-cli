use crate::error::{path_io, GhidraError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ghidra_install_dir: Option<PathBuf>,
    pub ghidra_project_dir: Option<PathBuf>,
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
    pub aliases: std::collections::HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ghidra_install_dir: None,
            ghidra_project_dir: None,
            java_home: None,
            default_program: None,
            default_project: None,
            default_output_format: Some("auto".to_string()),
            default_limit: Some(1000),
            launch_timeout_secs: None,
            aliases: std::collections::HashMap::new(),
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
        let path = Self::write_path(path)?;
        let _lock = Self::lock(&path)?;
        self.save_to(&path)
    }

    /// Serialize a configuration change with other CLI processes. A failed
    /// callback or write leaves the previously published configuration intact.
    pub fn update(change: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        Self::update_at(&Self::config_path()?, change)
    }

    fn update_at(path: &Path, change: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        let path = Self::write_path(path)?;
        let _lock = Self::lock(&path)?;
        let mut config = Self::load_from(&path)?;
        change(&mut config)?;
        config.save_to(&path)?;
        Ok(config)
    }

    fn write_path(path: &Path) -> Result<PathBuf> {
        // Resolve dotfiles symlinks before choosing the sidecar lock or replacing
        // the file. Direct and symlink callers must update the same target and
        // synchronize on the same lock, while retaining the original link.
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(dunce::canonicalize(path).map_err(|e| path_io("config.resolve", path, e))?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                fs::create_dir_all(parent).map_err(|e| path_io("config.directory", parent, e))?;
                let name = path.file_name().ok_or_else(|| {
                    GhidraError::ConfigError("Configuration path must name a file".into())
                })?;
                Ok(dunce::canonicalize(parent)
                    .map_err(|e| path_io("config.resolve", parent, e))?
                    .join(name))
            }
            Err(error) => Err(path_io("config.resolve", path, error)),
        }
    }

    fn lock(path: &Path) -> Result<fs::File> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|e| path_io("config.directory", parent, e))?;
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        // Keep the lock file: unlinking it could let another process lock a
        // different inode. Closing the handle releases the OS-backed lock.
        let lock_path = PathBuf::from(lock_name);
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
        staged
            .persist(path)
            .map_err(|error| path_io("config.publish", path, error.error))?;
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

    pub fn get_ghidra_install_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(dir) = std::env::var("GHIDRA_INSTALL_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_install_dir {
            return Ok(dir.clone());
        }

        // Try to auto-detect on Windows
        #[cfg(target_os = "windows")]
        {
            if let Some(dir) = Self::detect_ghidra_windows() {
                return Ok(dir);
            }
        }

        Err(GhidraError::GhidraNotFound)
    }

    pub fn get_project_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
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

    #[cfg(target_os = "windows")]
    pub fn detect_ghidra_windows() -> Option<PathBuf> {
        // Helper function to check if a path is a valid Ghidra installation
        let is_valid_ghidra =
            |path: &PathBuf| -> bool { path.join("support").join("analyzeHeadless.bat").exists() };

        // Check common installation paths
        let mut common_paths = vec![
            PathBuf::from("C:\\Program Files\\Ghidra"),
            PathBuf::from("C:\\Program Files (x86)\\Ghidra"),
            PathBuf::from("C:\\ghidra"),
        ];

        // Add user's home directory paths
        if let Some(home) = dirs::home_dir() {
            common_paths.push(home.join("ghidra"));
        }

        for path in common_paths {
            if !path.exists() {
                continue;
            }

            // First check if the path itself is a Ghidra installation
            if is_valid_ghidra(&path) {
                return Some(path);
            }

            // Look for ghidra_* subdirectories
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_dir() {
                        let name = entry_path.file_name()?.to_str()?;
                        if name.starts_with("ghidra_") && is_valid_ghidra(&entry_path) {
                            return Some(entry_path);
                        }
                    }
                }
            }
        }

        None
    }

    /// Explicit JDK home override: `GHIDRA_CLI_JAVA_HOME` env (set from the
    /// `--java-home` flag in main) takes precedence over the config value.
    pub fn get_java_home(&self) -> Option<PathBuf> {
        std::env::var("GHIDRA_CLI_JAVA_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| self.java_home.clone())
    }

    pub fn get_default_program(&self) -> Option<String> {
        std::env::var("GHIDRA_DEFAULT_PROGRAM")
            .ok()
            .or_else(|| self.default_program.clone())
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
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn config_symlink_is_preserved_by_save_and_concurrent_updates() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("dotfiles.yaml");
        let link = temp.path().join("config.yaml");
        Config::default().save_at(&target).unwrap();
        std::os::unix::fs::symlink("dotfiles.yaml", &link).unwrap();
        let config = Config {
            default_limit: Some(0),
            ..Config::default()
        };
        config.save_at(&link).unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(Config::load_from(&target).unwrap().default_limit, Some(0));
        assert_eq!(
            Config::write_path(&target).unwrap(),
            Config::write_path(&link).unwrap()
        );
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let path = if index % 2 == 0 {
                    target.clone()
                } else {
                    link.clone()
                };
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        Config::update_at(&path, |config| {
                            config.default_limit = Some(config.default_limit.unwrap() + 1);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("dotfiles.yaml")
        );
        assert_eq!(Config::load_from(&target).unwrap().default_limit, Some(40));
        assert!(!temp.path().join("config.yaml.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_config_symlink_is_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("config.yaml");
        std::os::unix::fs::symlink("missing.yaml", &link).unwrap();
        assert!(Config::default().save_at(&link).is_err());
        assert!(Config::update_at(&link, |_| Ok(())).is_err());
        assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("missing.yaml"));
    }

    #[test]
    fn failed_update_preserves_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.yaml");
        let original = "default_project: keep-me\naliases: {}\n";
        fs::write(&path, original).unwrap();
        let result = Config::update_at(&path, |config| {
            config.default_project = Some("discard-me".into());
            Err(GhidraError::ConfigError("rejected".into()))
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), original);
    }

    #[test]
    fn invalid_config_is_not_replaced_by_update() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.yaml");
        fs::write(&path, "[invalid yaml").unwrap();
        assert!(Config::update_at(&path, |_| Ok(())).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "[invalid yaml");
    }

    #[test]
    fn concurrent_updates_preserve_every_increment() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.yaml");
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        Config::update_at(&path, |config| {
                            config.default_limit = Some(config.default_limit.unwrap() + 1);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(Config::load_from(&path).unwrap().default_limit, Some(1040));
    }

    #[test]
    fn failed_publication_preserves_destination_and_cleans_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.yaml");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), "original").unwrap();
        assert!(Config::default().save_to(&path).is_err());
        assert_eq!(fs::read_to_string(path.join("keep")).unwrap(), "original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.default_limit, Some(1000));
    }

    #[test]
    fn legacy_timeout_is_ignored_and_not_reserialized() {
        let config: Config = serde_yaml::from_str("timeout: 1800\naliases: {}\n").unwrap();
        let serialized = serde_yaml::to_string(&config).unwrap();
        assert!(!serialized.contains("timeout:"), "{serialized}");
    }

    #[test]
    fn default_project_dir_has_no_hidden_component() {
        let dir = Config::default_project_dir().expect("default project dir");
        assert!(
            !has_hidden_component(&dir),
            "default project dir must not contain a dot-prefixed component (Ghidra 12.1+): {}",
            dir.display()
        );
    }

    #[test]
    fn has_hidden_component_detects_dot_dirs() {
        assert!(has_hidden_component(Path::new(
            "/home/u/.cache/ghidra-cli/projects"
        )));
        assert!(has_hidden_component(Path::new(
            "/home/u/.local/share/ghidra-cli"
        )));
        assert!(!has_hidden_component(Path::new(
            "/home/u/ghidra-cli/projects"
        )));
        assert!(!has_hidden_component(Path::new(
            "/Users/u/Library/Caches/ghidra-cli/projects"
        )));
    }
}
