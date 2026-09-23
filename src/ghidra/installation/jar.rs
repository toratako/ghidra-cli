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
    let manifest = read_entry(&mut archive, "META-INF/MANIFEST.MF").map_err(&invalid)?;
    if main_class(&manifest).as_deref() != Some("ghidra.JarRun") {
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

fn main_class(manifest: &str) -> Option<String> {
    // Only main-section attributes apply to the JAR. Manifest lines beginning
    // with a space continue the preceding attribute, including Main-Class.
    let mut attributes: Vec<String> = Vec::new();
    for line in manifest.lines().take_while(|line| !line.is_empty()) {
        if let Some(continuation) = line.strip_prefix(' ') {
            attributes.last_mut()?.push_str(continuation);
        } else {
            attributes.push(line.into());
        }
    }
    attributes.iter().find_map(|attribute| {
        let (name, value) = attribute.split_once(": ")?;
        name.eq_ignore_ascii_case("Main-Class")
            .then(|| value.to_owned())
    })
}
