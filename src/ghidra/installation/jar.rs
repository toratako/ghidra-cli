use super::{path_io, require_file, GhidraError, Path, Result};
use std::fs::File;
use std::io::Read;
use zip::ZipArchive;

pub(super) fn validate_path(path: &Path) -> Result<()> {
    // GhidraJarApplicationLayout decodes the JAR URL with URLDecoder, which
    // interprets a literal '+' as a space and can open a different artifact.
    // Check the canonical path actually passed to Java, not a symlink alias.
    if path.as_os_str().as_encoded_bytes().contains(&b'+') {
        return Err(GhidraError::ConfigError(format!(
            "Ghidra JAR path {} contains '+', which Ghidra decodes as a space; move the JAR to a path without '+' and update GHIDRA_JAR or ghidra_jar",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn properties(path: &Path) -> Result<String> {
    require_file(path)?;
    let file = File::open(path).map_err(|e| path_io("installation.read", path, e))?;
    let invalid = |message: String| {
        GhidraError::ConfigError(format!("Invalid Ghidra JAR {}: {message}", path.display()))
    };
    let mut archive = ZipArchive::new(file).map_err(|e| invalid(e.to_string()))?;
    let manifest = read_entry(&mut archive, "META-INF/MANIFEST.MF").map_err(invalid)?;
    let main_class = main_class(&manifest).map_err(|message| invalid(message.into()))?;
    // The Java launcher applies String.trim(), which removes ASCII control
    // characters and spaces rather than all Unicode whitespace.
    if main_class
        .as_deref()
        .map(|value| value.trim_matches(|c| c <= '\u{20}'))
        != Some("ghidra.JarRun")
    {
        return Err(invalid("manifest Main-Class must be ghidra.JarRun".into()));
    }
    // These establish the official single-JAR layout and headless entry point.
    // Compilation and runtime diagnostics check actual bridge compatibility.
    for name in [
        "ghidra/JarRun.class",
        "ghidra/GhidraJarApplicationLayout.class",
        "ghidra/app/util/headless/AnalyzeHeadless.class",
        "_Root/Ghidra/MODULE_LIST",
    ] {
        let entry = archive
            .by_name(name)
            .map_err(|e| invalid(format!("{name}: {e}")))?;
        if !entry.is_file() || entry.size() == 0 {
            return Err(invalid(format!("{name}: expected a nonempty file")));
        }
    }
    read_entry(&mut archive, "_Root/Ghidra/application.properties").map_err(invalid)
}

fn read_entry(archive: &mut ZipArchive<File>, name: &str) -> std::result::Result<String, String> {
    let mut entry = archive.by_name(name).map_err(|e| format!("{name}: {e}"))?;
    let mut text = String::new();
    entry
        .read_to_string(&mut text)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(text)
}

fn main_class(mut manifest: &str) -> std::result::Result<Option<String>, &'static str> {
    // Java parses every manifest section before launching the main class.
    // Only main-section attributes supply Main-Class; later sections start
    // with Name. A leading space continues the preceding attribute.
    let mut attribute = String::new();
    let mut main_class = None;
    let mut main_section = true;
    let mut section_started = false;
    while let Some(end) = manifest.find(['\r', '\n']) {
        let line = &manifest[..end];
        let remaining = &manifest[end..];
        manifest = remaining.strip_prefix("\r\n").unwrap_or(&remaining[1..]);
        if line.is_empty() {
            attribute.clear();
            main_section = false;
            section_started = false;
            continue;
        }
        if let Some(continuation) = line.strip_prefix(' ') {
            if attribute.is_empty() {
                return Err("invalid manifest continuation");
            }
            attribute.push_str(continuation);
        } else {
            // Header syntax is checked even when a following continuation
            // never completes; name validity is checked when committed below.
            let (name, _) = manifest_attribute(line)?;
            if !main_section && !section_started && !name.eq_ignore_ascii_case("Name") {
                return Err("manifest section must begin with Name");
            }
            attribute = line.into();
        }
        // java.util.jar.Attributes ignores unterminated physical lines and
        // commits an attribute only after all its continuation lines complete.
        if manifest.starts_with(' ') {
            continue;
        }
        let (name, value) = manifest_attribute(&attribute)?;
        if name.is_empty()
            || name.len() > 70
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err("invalid manifest attribute name");
        }
        // Duplicate names retain their final complete value.
        if main_section && name.eq_ignore_ascii_case("Main-Class") {
            main_class = Some(value.to_owned());
        }
        section_started = true;
        attribute.clear();
    }
    Ok(main_class)
}

fn manifest_attribute(line: &str) -> std::result::Result<(&str, &str), &'static str> {
    line.split_once(':')
        .and_then(|(name, value)| value.strip_prefix(' ').map(|value| (name, value)))
        .ok_or("invalid manifest header")
}
