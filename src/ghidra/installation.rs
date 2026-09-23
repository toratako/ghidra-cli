//! Ghidra installation selection. Discovery only reads files: it never runs
//! launchers/package managers, writes configuration, or searches arbitrary trees.

use crate::config::Config;
use crate::error::{path_io, GhidraError, Result};
use serde::Serialize;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct Installation {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub version: String,
    pub source: String,
}

impl Installation {
    pub fn launcher(&self) -> PathBuf {
        self.path
            .join("support")
            .join(Platform::native().launcher())
    }
}

#[derive(Debug, Serialize)]
pub struct CheckedPath {
    #[serde(serialize_with = "serialize_path")]
    path: PathBuf,
    source: String,
    message: String,
}

// JSON cannot represent arbitrary OS strings. Match human path diagnostics
// without letting a non-UTF-8 filename panic while reporting a detection error.
fn serialize_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
}

#[derive(Debug, Serialize)]
pub struct DetectionError {
    pub status: &'static str,
    pub candidates: Vec<Installation>,
    pub checked: Vec<CheckedPath>,
    #[serde(skip)]
    cause: Option<Box<GhidraError>>,
}

impl fmt::Display for DetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.status {
            "invalid" => "Invalid Ghidra installation",
            "ambiguous" => "Multiple Ghidra installations found",
            _ => "Ghidra installation not found",
        })?;
        for candidate in &self.candidates {
            write!(
                f,
                "\n  {} ({}; {})",
                candidate.path.display(),
                candidate.version,
                candidate.source
            )?;
        }
        for check in &self.checked {
            write!(
                f,
                "\n  {} ({}): {}",
                check.path.display(),
                check.source,
                check.message
            )?;
        }
        f.write_str("\nSet GHIDRA_INSTALL_DIR or use 'ghidra-cli config set ghidra_install_dir PATH' to select an existing Ghidra installation.")
    }
}

impl std::error::Error for DetectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|e| e as _)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    Mac,
    Windows,
}

impl Platform {
    fn native() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Mac
        } else {
            Self::Linux
        }
    }

    fn launcher(self) -> &'static str {
        if self == Self::Windows {
            "analyzeHeadless.bat"
        } else {
            "analyzeHeadless"
        }
    }

    fn commands(self) -> &'static [&'static str] {
        // Upstream launcher names/layout:
        // https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/GettingStarted.md
        // Nix exports ghidra and ghidra-analyzeHeadless as symlinks into lib/ghidra:
        // https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/security/ghidra/build.nix
        // https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/security/ghidra/default.nix
        if self == Self::Windows {
            &[
                "ghidra.bat",
                "ghidraRun.bat",
                "analyzeHeadless.bat",
                "ghidra-analyzeHeadless.bat",
            ]
        } else {
            &[
                "ghidra",
                "ghidraRun",
                "analyzeHeadless",
                "ghidra-analyzeHeadless",
            ]
        }
    }
}

struct SearchRoot {
    path: PathBuf,
    source: &'static str,
    inspect_root: bool,
    child_prefix: Option<&'static str>,
}

impl SearchRoot {
    fn exact(path: impl Into<PathBuf>, source: &'static str) -> Self {
        Self {
            path: path.into(),
            source,
            inspect_root: true,
            child_prefix: None,
        }
    }
}

fn package_roots(
    platform: Platform,
    brew_prefix: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Vec<SearchRoot> {
    let mut roots = Vec::new();
    match platform {
        Platform::Linux => {
            // Arch package file list (including support/analyzeHeadless):
            // https://archlinux.org/packages/extra/x86_64/ghidra/files/
            roots.push(SearchRoot::exact("/opt/ghidra", "Arch package layout"));
            // Kali installation and Pentoo overlay use the same root:
            // https://gitlab.com/kalilinux/packages/ghidra/-/blob/kali/master/debian/rules
            // https://github.com/pentoo/pentoo-overlay/blob/master/dev-util/ghidra/ghidra-12.1.3-r1.ebuild
            roots.push(SearchRoot::exact(
                "/usr/share/ghidra",
                "Kali/Pentoo package layout",
            ));
            // https://github.com/void-linux/void-packages/blob/master/srcpkgs/ghidra/template
            roots.push(SearchRoot::exact(
                "/usr/libexec/ghidra",
                "Void package layout",
            ));
        }
        Platform::Mac => {
            // MacPorts javadest = ${prefix}/share/java/${name}-${version}:
            // https://github.com/macports/macports-ports/blob/master/devel/ghidra/Portfile
            // Default prefix /opt/local: https://guide.macports.org/#installing
            roots.push(SearchRoot {
                path: "/opt/local/share/java".into(),
                source: "MacPorts package layout",
                inspect_root: false,
                child_prefix: Some("ghidra-"),
            });
        }
        Platform::Windows => {
            // Preserve the CLI's existing Windows search scope. These are legacy
            // CLI heuristics, NOT vendor/package-manager default installations:
            // https://github.com/toratako/ghidra-cli/blob/e624b1062fcaeedf78fda093450fcebe7706fc34/src/config.rs#L244-L287
            let mut paths = vec![
                PathBuf::from(r"C:\Program Files\Ghidra"),
                PathBuf::from(r"C:\Program Files (x86)\Ghidra"),
                PathBuf::from(r"C:\ghidra"),
            ];
            if let Some(home) = home {
                paths.push(home.join("ghidra"));
            }
            roots.extend(paths.into_iter().map(|path| SearchRoot {
                path,
                source: "Windows search path",
                inspect_root: true,
                child_prefix: Some("ghidra_"),
            }));
        }
    }
    if platform != Platform::Windows {
        // Homebrew installs the distribution in libexec; opt/ghidra selects the
        // active keg. Do not enumerate the Cellar or pick its newest directory.
        // https://github.com/Homebrew/homebrew-core/blob/master/Formula/g/ghidra.rb
        // https://docs.brew.sh/Formula-Cookbook#terminology
        // Standard prefixes and HOMEBREW_PREFIX:
        // https://docs.brew.sh/Installation
        // https://docs.brew.sh/Manpage#environment
        let defaults: &[&str] = if platform == Platform::Mac {
            &["/opt/homebrew", "/usr/local"]
        } else {
            &["/home/linuxbrew/.linuxbrew"]
        };
        let prefixes = brew_prefix
            .into_iter()
            .filter(|p| p.is_absolute())
            .chain(defaults.iter().map(PathBuf::from));
        roots.extend(
            prefixes.map(|p| {
                SearchRoot::exact(p.join("opt/ghidra/libexec"), "Homebrew package layout")
            }),
        );
    }
    roots
}

// Inputs are explicit so unit tests never consult the host's PATH, home,
// environment overrides, or actual package-manager installations.
struct Inputs {
    platform: Platform,
    environment: Option<OsString>,
    configured: Option<PathBuf>,
    path: OsString,
    roots: Vec<SearchRoot>,
}

pub fn resolve(config: &Config) -> Result<Installation> {
    let platform = Platform::native();
    resolve_inputs(Inputs {
        platform,
        environment: std::env::var_os("GHIDRA_INSTALL_DIR"),
        configured: config.ghidra_install_dir.clone(),
        path: std::env::var_os("PATH").unwrap_or_default(),
        roots: package_roots(
            platform,
            std::env::var_os("HOMEBREW_PREFIX").map(PathBuf::from),
            dirs::home_dir(),
        ),
    })
}

fn resolve_inputs(inputs: Inputs) -> Result<Installation> {
    let mut search = Search::default();
    let explicit = inputs
        .environment
        .map(|p| (PathBuf::from(p), "GHIDRA_INSTALL_DIR"))
        .or_else(|| inputs.configured.map(|p| (p, "config ghidra_install_dir")));
    if let Some((path, source)) = explicit {
        return inspect_for(&path, source, inputs.platform).map_err(|cause| {
            search.reject(&path, source, &cause);
            search.error("invalid", Some(cause))
        });
    }

    for directory in std::env::split_paths(&inputs.path).filter(|p| p.is_absolute()) {
        let source = format!("PATH {}", directory.display());
        for name in inputs.platform.commands() {
            let command = directory.join(name);
            match fs::symlink_metadata(&command) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    search.reject(&command, &source, &e);
                    continue;
                }
                Ok(_) => {}
            }
            match dunce::canonicalize(&command) {
                Ok(real) => match require_file(&real) {
                    Ok(()) => {
                        if let Some(root) = command_root(&real) {
                            search.probe(&root, &source, inputs.platform);
                        }
                    }
                    Err(e) => search.reject(&command, &source, &e),
                },
                Err(e) => search.reject(&command, &source, &e),
            }
        }
        if !search.candidates.is_empty() {
            return search.select();
        }
    }

    for root in inputs.roots {
        if root.inspect_root {
            search.probe(&root.path, root.source, inputs.platform);
        }
        if let Some(prefix) = root.child_prefix {
            match fs::read_dir(&root.path) {
                Ok(entries) => {
                    // Sorting only stabilizes diagnostics. It never selects a version.
                    let mut children = Vec::new();
                    for entry in entries {
                        match entry {
                            Ok(entry)
                                if entry.file_name().to_string_lossy().starts_with(prefix) =>
                            {
                                children.push(entry.path())
                            }
                            Ok(_) => {}
                            Err(e) => search.reject(&root.path, root.source, &e),
                        }
                    }
                    children.sort();
                    if children.is_empty() && !root.inspect_root {
                        search.reject(
                            &root.path,
                            root.source,
                            &"No Ghidra package directories found",
                        );
                    }
                    for path in children {
                        search.probe(&path, root.source, inputs.platform);
                    }
                }
                Err(e) if !root.inspect_root => search.reject(&root.path, root.source, &e),
                Err(_) => {} // The direct probe already records this root's failure.
            }
        }
    }
    search.select()
}

fn command_root(real: &Path) -> Option<PathBuf> {
    let parent = real.parent()?;
    if parent.file_name()? == "support" {
        Some(parent.parent()?.to_path_buf())
    } else if parent.file_name()? == "bin" {
        // Homebrew's public command is a wrapper in <keg>/bin. Its sibling
        // libexec contains the distribution (Formula URL in package_roots).
        Some(parent.parent()?.join("libexec"))
    } else {
        Some(parent.to_path_buf())
    }
}

#[derive(Default)]
struct Search {
    candidates: Vec<Installation>,
    checked: Vec<CheckedPath>,
    incomplete: bool,
}

impl Search {
    fn reject(&mut self, path: &Path, source: &str, reason: &impl fmt::Display) {
        self.checked.push(CheckedPath {
            path: path.into(),
            source: source.into(),
            message: reason.to_string(),
        });
    }

    fn probe(&mut self, path: &Path, source: &str, platform: Platform) {
        match inspect_for(path, source, platform) {
            Ok(installation) => {
                if !self.candidates.iter().any(|i| i.path == installation.path) {
                    self.candidates.push(installation);
                }
            }
            Err(e) => {
                self.incomplete |= fs::symlink_metadata(path).is_ok();
                self.reject(path, source, &e);
            }
        }
    }

    fn error(self, status: &'static str, cause: Option<GhidraError>) -> GhidraError {
        GhidraError::Installation(Box::new(DetectionError {
            status,
            candidates: self.candidates,
            checked: self.checked,
            cause: cause.map(Box::new),
        }))
    }

    fn select(mut self) -> Result<Installation> {
        match self.candidates.len() {
            0 => {
                let status = if self.incomplete {
                    "invalid"
                } else {
                    "not_found"
                };
                Err(self.error(status, None))
            }
            1 => Ok(self.candidates.remove(0)),
            _ => Err(self.error("ambiguous", None)),
        }
    }
}

pub(crate) fn inspect(path: &Path) -> Result<Installation> {
    inspect_for(path, "installation path", Platform::native())
}

fn inspect_for(path: &Path, source: &str, platform: Platform) -> Result<Installation> {
    if path.as_os_str().is_empty() {
        return Err(GhidraError::ConfigError(
            "Ghidra installation path is empty".into(),
        ));
    }
    // Check the launcher first so an incomplete tree identifies the missing
    // platform entry point. Never accept directories in place of these files.
    require_file(&path.join("support").join(platform.launcher()))?;
    let properties = path.join("Ghidra/application.properties");
    require_file(&properties)?;
    let text = fs::read_to_string(&properties)
        .map_err(|e| path_io("installation.read", &properties, e))?;
    let version = text
        .lines()
        .filter_map(|l| l.trim().split_once('='))
        .find(|(key, _)| key.trim() == "application.version")
        .map(|(_, value)| value.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            GhidraError::ConfigError(format!(
                "Missing application.version in {}",
                properties.display()
            ))
        })?;
    // Release/build output, including DEV/NIX distro builds, must have the
    // bootstrap runtime. A source checkout is not an installed distribution.
    // https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/RuntimeScripts/Linux/support/launch.sh
    require_file(&path.join("Ghidra/Framework/Utility/lib/Utility.jar"))?;
    require_file(&path.join("support/LaunchSupport.jar"))?;
    Ok(Installation {
        path: dunce::canonicalize(path).map_err(|e| path_io("installation.resolve", path, e))?,
        version: version.into(),
        source: source.into(),
    })
}

fn require_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|e| path_io("installation.inspect", path, e))?;
    if !metadata.is_file() {
        return Err(GhidraError::ConfigError(format!(
            "Expected an installation file at {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
