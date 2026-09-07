//! Embedded Java source bundle shared by startup and compile diagnostics.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const SOURCES: &[(&str, &str)] = &[
    (
        "GhidraCliBridge.java",
        include_str!("../scripts/GhidraCliBridge.java"),
    ),
    (
        "ghidracli/AddressResolver.java",
        include_str!("../scripts/ghidracli/AddressResolver.java"),
    ),
    (
        "ghidracli/AnalysisCommands.java",
        include_str!("../scripts/ghidracli/AnalysisCommands.java"),
    ),
    (
        "ghidracli/ArtifactManifest.java",
        include_str!("../scripts/ghidracli/ArtifactManifest.java"),
    ),
    (
        "ghidracli/BridgeRuntime.java",
        include_str!("../scripts/ghidracli/BridgeRuntime.java"),
    ),
    (
        "ghidracli/BridgeServer.java",
        include_str!("../scripts/ghidracli/BridgeServer.java"),
    ),
    (
        "ghidracli/CommandDispatcher.java",
        include_str!("../scripts/ghidracli/CommandDispatcher.java"),
    ),
    (
        "ghidracli/CommentCommands.java",
        include_str!("../scripts/ghidracli/CommentCommands.java"),
    ),
    (
        "ghidracli/DecompileCommands.java",
        include_str!("../scripts/ghidracli/DecompileCommands.java"),
    ),
    (
        "ghidracli/DiffCommands.java",
        include_str!("../scripts/ghidracli/DiffCommands.java"),
    ),
    (
        "ghidracli/FunctionCommands.java",
        include_str!("../scripts/ghidracli/FunctionCommands.java"),
    ),
    (
        "ghidracli/FunctionQueries.java",
        include_str!("../scripts/ghidracli/FunctionQueries.java"),
    ),
    (
        "ghidracli/FunctionSignatureCommands.java",
        include_str!("../scripts/ghidracli/FunctionSignatureCommands.java"),
    ),
    (
        "ghidracli/GraphCommands.java",
        include_str!("../scripts/ghidracli/GraphCommands.java"),
    ),
    (
        "ghidracli/JobScheduler.java",
        include_str!("../scripts/ghidracli/JobScheduler.java"),
    ),
    (
        "ghidracli/JobTaskMonitor.java",
        include_str!("../scripts/ghidracli/JobTaskMonitor.java"),
    ),
    (
        "ghidracli/JsonProtocol.java",
        include_str!("../scripts/ghidracli/JsonProtocol.java"),
    ),
    (
        "ghidracli/ListingCommands.java",
        include_str!("../scripts/ghidracli/ListingCommands.java"),
    ),
    (
        "ghidracli/MemoryCommands.java",
        include_str!("../scripts/ghidracli/MemoryCommands.java"),
    ),
    (
        "ghidracli/NameSuggestions.java",
        include_str!("../scripts/ghidracli/NameSuggestions.java"),
    ),
    (
        "ghidracli/PcodeCommands.java",
        include_str!("../scripts/ghidracli/PcodeCommands.java"),
    ),
    (
        "ghidracli/ProgramCommands.java",
        include_str!("../scripts/ghidracli/ProgramCommands.java"),
    ),
    (
        "ghidracli/ProgramSession.java",
        include_str!("../scripts/ghidracli/ProgramSession.java"),
    ),
    (
        "ghidracli/ProgramTransaction.java",
        include_str!("../scripts/ghidracli/ProgramTransaction.java"),
    ),
    (
        "ghidracli/ScriptAccess.java",
        include_str!("../scripts/ghidracli/ScriptAccess.java"),
    ),
    (
        "ghidracli/ScriptCommands.java",
        include_str!("../scripts/ghidracli/ScriptCommands.java"),
    ),
    (
        "ghidracli/SearchCommands.java",
        include_str!("../scripts/ghidracli/SearchCommands.java"),
    ),
    (
        "ghidracli/SymbolCommands.java",
        include_str!("../scripts/ghidracli/SymbolCommands.java"),
    ),
    (
        "ghidracli/TagCommands.java",
        include_str!("../scripts/ghidracli/TagCommands.java"),
    ),
    (
        "ghidracli/TagSupport.java",
        include_str!("../scripts/ghidracli/TagSupport.java"),
    ),
    (
        "ghidracli/TypeCommands.java",
        include_str!("../scripts/ghidracli/TypeCommands.java"),
    ),
    (
        "ghidracli/TypeImportCommands.java",
        include_str!("../scripts/ghidracli/TypeImportCommands.java"),
    ),
    (
        "ghidracli/TypeResolver.java",
        include_str!("../scripts/ghidracli/TypeResolver.java"),
    ),
    (
        "ghidracli/XrefCommands.java",
        include_str!("../scripts/ghidracli/XrefCommands.java"),
    ),
];

/// Write a complete source tree into a private, empty directory.
pub(super) fn write_to(directory: &Path) -> Result<Vec<PathBuf>> {
    write_sources(directory, SOURCES)
}

fn write_sources(directory: &Path, sources: &[(&str, &str)]) -> Result<Vec<PathBuf>> {
    sources
        .iter()
        .map(|(name, source)| {
            let path = directory.join(name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, source)?;
            Ok(path)
        })
        .collect()
}

/// Publish a complete bundle once, then reuse it without touching timestamps.
/// Different CLI builds never overwrite sources that a running JVM may use.
pub(super) fn install() -> Result<PathBuf> {
    let root = dirs::config_dir()
        .context("Could not determine config directory")?
        .join("ghidra-cli")
        .join("bridge-sources");
    install_sources(&root, SOURCES)
}

fn install_sources(root: &Path, sources: &[(&str, &str)]) -> Result<PathBuf> {
    let mut hash = md5::Context::new();
    for (name, source) in sources {
        hash.consume(name.as_bytes());
        hash.consume([0]);
        hash.consume(source.as_bytes());
        hash.consume([0]);
    }
    let destination = root.join(format!("{:x}", hash.compute()));
    if destination.is_dir() {
        return Ok(destination);
    }

    std::fs::create_dir_all(root)?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(root)?;
    write_sources(staging.path(), sources)?;
    if let Err(error) = std::fs::rename(staging.path(), &destination) {
        // Another project may have published the identical complete bundle.
        if !destination.is_dir() {
            return Err(error).context("Could not publish Java bridge sources");
        }
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_updates_do_not_mix_sources_or_rewrite_existing_files() {
        let root = tempfile::tempdir().unwrap();
        let old = install_sources(
            root.path(),
            &[("Entry.java", "old"), ("Old.java", "helper")],
        )
        .unwrap();
        let modified = std::fs::metadata(old.join("Entry.java"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            old,
            install_sources(
                root.path(),
                &[("Entry.java", "old"), ("Old.java", "helper")]
            )
            .unwrap()
        );
        assert_eq!(
            modified,
            std::fs::metadata(old.join("Entry.java"))
                .unwrap()
                .modified()
                .unwrap()
        );

        let new = install_sources(
            root.path(),
            &[("Entry.java", "new"), ("pkg/New.java", "helper")],
        )
        .unwrap();
        assert_ne!(old, new);
        assert!(!new.join("Old.java").exists());
        assert_eq!(
            std::fs::read_to_string(new.join("pkg/New.java")).unwrap(),
            "helper"
        );
        assert_eq!(
            std::fs::read_to_string(old.join("Entry.java")).unwrap(),
            "old"
        );
    }

    #[test]
    fn concurrent_publishers_receive_complete_bundle() {
        let root = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let bundle = install_sources(root.path(), SOURCES).unwrap();
                        for (name, source) in SOURCES {
                            assert_eq!(
                                std::fs::read_to_string(bundle.join(name)).unwrap(),
                                *source
                            );
                        }
                        bundle
                    })
                })
                .collect();
            let paths: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect();
            assert!(paths.iter().all(|path| path == &paths[0]));
        });
    }

    #[test]
    fn all_java_sources_are_embedded() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ghidra/scripts");
        let mut files: Vec<_> = walkdir::WalkDir::new(&root)
            .into_iter()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "java"))
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        files.sort();
        let mut embedded: Vec<_> = SOURCES.iter().map(|(name, _)| name.to_string()).collect();
        embedded.sort();
        assert_eq!(files, embedded);
    }
}
