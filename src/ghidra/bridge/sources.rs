//! Embedded Java source bundle shared by startup and compile diagnostics.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) const JAR_LAUNCHER: &str = include_str!("../scripts/GhidraCliJarLauncher.java");

const SOURCES: &[(&str, &str)] = &[
    ("GhidraCliJarLauncher.java", JAR_LAUNCHER),
    (
        "GhidraCliBootstrap.java",
        include_str!("../scripts/GhidraCliBootstrap.java"),
    ),
    (
        "GhidraCliBridge.java",
        include_str!("../scripts/GhidraCliBridge.java"),
    ),
    (
        "ghidracli/analysis/AnalysisCommands.java",
        include_str!("../scripts/ghidracli/analysis/AnalysisCommands.java"),
    ),
    (
        "ghidracli/analysis/AnalysisContext.java",
        include_str!("../scripts/ghidracli/analysis/AnalysisContext.java"),
    ),
    (
        "ghidracli/analysis/AnalysisLimits.java",
        include_str!("../scripts/ghidracli/analysis/AnalysisLimits.java"),
    ),
    (
        "ghidracli/analysis/CallReferences.java",
        include_str!("../scripts/ghidracli/analysis/CallReferences.java"),
    ),
    (
        "ghidracli/analysis/DecompileAddresses.java",
        include_str!("../scripts/ghidracli/analysis/DecompileAddresses.java"),
    ),
    (
        "ghidracli/analysis/DecompileCommands.java",
        include_str!("../scripts/ghidracli/analysis/DecompileCommands.java"),
    ),
    (
        "ghidracli/analysis/DecompileWarnings.java",
        include_str!("../scripts/ghidracli/analysis/DecompileWarnings.java"),
    ),
    (
        "ghidracli/analysis/DecompileScan.java",
        include_str!("../scripts/ghidracli/analysis/DecompileScan.java"),
    ),
    (
        "ghidracli/analysis/FieldUses.java",
        include_str!("../scripts/ghidracli/analysis/FieldUses.java"),
    ),
    (
        "ghidracli/analysis/GraphCommands.java",
        include_str!("../scripts/ghidracli/analysis/GraphCommands.java"),
    ),
    (
        "ghidracli/analysis/HighPcodeModel.java",
        include_str!("../scripts/ghidracli/analysis/HighPcodeModel.java"),
    ),
    (
        "ghidracli/analysis/HighPcodeOutput.java",
        include_str!("../scripts/ghidracli/analysis/HighPcodeOutput.java"),
    ),
    (
        "ghidracli/analysis/InstructionCfg.java",
        include_str!("../scripts/ghidracli/analysis/InstructionCfg.java"),
    ),
    (
        "ghidracli/analysis/PcodeCommands.java",
        include_str!("../scripts/ghidracli/analysis/PcodeCommands.java"),
    ),
    (
        "ghidracli/analysis/SemanticTypeUsesCommands.java",
        include_str!("../scripts/ghidracli/analysis/SemanticTypeUsesCommands.java"),
    ),
    (
        "ghidracli/analysis/StructureInferenceCommands.java",
        include_str!("../scripts/ghidracli/analysis/StructureInferenceCommands.java"),
    ),
    (
        "ghidracli/analysis/VtableCommands.java",
        include_str!("../scripts/ghidracli/analysis/VtableCommands.java"),
    ),
    (
        "ghidracli/analysis/VtableHeaders.java",
        include_str!("../scripts/ghidracli/analysis/VtableHeaders.java"),
    ),
    (
        "ghidracli/analysis/VtableReader.java",
        include_str!("../scripts/ghidracli/analysis/VtableReader.java"),
    ),
    (
        "ghidracli/analysis/VirtualCallersCommands.java",
        include_str!("../scripts/ghidracli/analysis/VirtualCallersCommands.java"),
    ),
    (
        "ghidracli/analysis/VirtualCallTrace.java",
        include_str!("../scripts/ghidracli/analysis/VirtualCallTrace.java"),
    ),
    (
        "ghidracli/function/FunctionBodyCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionBodyCommands.java"),
    ),
    (
        "ghidracli/function/FunctionCallSignatureCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionCallSignatureCommands.java"),
    ),
    (
        "ghidracli/function/FunctionCandidateSearch.java",
        include_str!("../scripts/ghidracli/function/FunctionCandidateSearch.java"),
    ),
    (
        "ghidracli/function/FunctionCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionCommands.java"),
    ),
    (
        "ghidracli/function/FunctionQueries.java",
        include_str!("../scripts/ghidracli/function/FunctionQueries.java"),
    ),
    (
        "ghidracli/function/FunctionReturnType.java",
        include_str!("../scripts/ghidracli/function/FunctionReturnType.java"),
    ),
    (
        "ghidracli/function/FunctionSignatureCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionSignatureCommands.java"),
    ),
    (
        "ghidracli/function/FunctionSignatureSupport.java",
        include_str!("../scripts/ghidracli/function/FunctionSignatureSupport.java"),
    ),
    (
        "ghidracli/function/FunctionThunkCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionThunkCommands.java"),
    ),
    (
        "ghidracli/function/FunctionVariableCommands.java",
        include_str!("../scripts/ghidracli/function/FunctionVariableCommands.java"),
    ),
    (
        "ghidracli/function/FunctionVariables.java",
        include_str!("../scripts/ghidracli/function/FunctionVariables.java"),
    ),
    (
        "ghidracli/function/TagCommands.java",
        include_str!("../scripts/ghidracli/function/TagCommands.java"),
    ),
    (
        "ghidracli/function/TagSupport.java",
        include_str!("../scripts/ghidracli/function/TagSupport.java"),
    ),
    (
        "ghidracli/listing/AddressTableSearch.java",
        include_str!("../scripts/ghidracli/listing/AddressTableSearch.java"),
    ),
    (
        "ghidracli/listing/ConstantSearch.java",
        include_str!("../scripts/ghidracli/listing/ConstantSearch.java"),
    ),
    (
        "ghidracli/listing/DataCommands.java",
        include_str!("../scripts/ghidracli/listing/DataCommands.java"),
    ),
    (
        "ghidracli/listing/InstructionFlow.java",
        include_str!("../scripts/ghidracli/listing/InstructionFlow.java"),
    ),
    (
        "ghidracli/listing/InstructionListing.java",
        include_str!("../scripts/ghidracli/listing/InstructionListing.java"),
    ),
    (
        "ghidracli/listing/ListingCommands.java",
        include_str!("../scripts/ghidracli/listing/ListingCommands.java"),
    ),
    (
        "ghidracli/listing/ListingFlowCommands.java",
        include_str!("../scripts/ghidracli/listing/ListingFlowCommands.java"),
    ),
    (
        "ghidracli/listing/SearchCommands.java",
        include_str!("../scripts/ghidracli/listing/SearchCommands.java"),
    ),
    (
        "ghidracli/listing/StringQueries.java",
        include_str!("../scripts/ghidracli/listing/StringQueries.java"),
    ),
    (
        "ghidracli/memory/FileMappingCommands.java",
        include_str!("../scripts/ghidracli/memory/FileMappingCommands.java"),
    ),
    (
        "ghidracli/memory/MemoryBlockCommands.java",
        include_str!("../scripts/ghidracli/memory/MemoryBlockCommands.java"),
    ),
    (
        "ghidracli/memory/MemoryBlockInfo.java",
        include_str!("../scripts/ghidracli/memory/MemoryBlockInfo.java"),
    ),
    (
        "ghidracli/memory/MemoryCommands.java",
        include_str!("../scripts/ghidracli/memory/MemoryCommands.java"),
    ),
    (
        "ghidracli/memory/MemoryInfoCommands.java",
        include_str!("../scripts/ghidracli/memory/MemoryInfoCommands.java"),
    ),
    (
        "ghidracli/memory/MemoryPatch.java",
        include_str!("../scripts/ghidracli/memory/MemoryPatch.java"),
    ),
    (
        "ghidracli/memory/MemorySources.java",
        include_str!("../scripts/ghidracli/memory/MemorySources.java"),
    ),
    (
        "ghidracli/memory/PointerValues.java",
        include_str!("../scripts/ghidracli/memory/PointerValues.java"),
    ),
    (
        "ghidracli/program/ProgramCommands.java",
        include_str!("../scripts/ghidracli/program/ProgramCommands.java"),
    ),
    (
        "ghidracli/program/ProgramContextCommands.java",
        include_str!("../scripts/ghidracli/program/ProgramContextCommands.java"),
    ),
    (
        "ghidracli/program/ProgramExportCommands.java",
        include_str!("../scripts/ghidracli/program/ProgramExportCommands.java"),
    ),
    (
        "ghidracli/program/ProgramRebaseCommands.java",
        include_str!("../scripts/ghidracli/program/ProgramRebaseCommands.java"),
    ),
    (
        "ghidracli/project/GarFile.java",
        include_str!("../scripts/ghidracli/project/GarFile.java"),
    ),
    (
        "ghidracli/project/ImportSupport.java",
        include_str!("../scripts/ghidracli/project/ImportSupport.java"),
    ),
    (
        "ghidracli/project/ProjectArchive.java",
        include_str!("../scripts/ghidracli/project/ProjectArchive.java"),
    ),
    (
        "ghidracli/project/ProjectDeletion.java",
        include_str!("../scripts/ghidracli/project/ProjectDeletion.java"),
    ),
    (
        "ghidracli/protocol/JsonProtocol.java",
        include_str!("../scripts/ghidracli/protocol/JsonProtocol.java"),
    ),
    (
        "ghidracli/query/AddressCodec.java",
        include_str!("../scripts/ghidracli/query/AddressCodec.java"),
    ),
    (
        "ghidracli/query/AddressResolver.java",
        include_str!("../scripts/ghidracli/query/AddressResolver.java"),
    ),
    (
        "ghidracli/query/IntegerLiteral.java",
        include_str!("../scripts/ghidracli/query/IntegerLiteral.java"),
    ),
    (
        "ghidracli/query/ListQuery.java",
        include_str!("../scripts/ghidracli/query/ListQuery.java"),
    ),
    (
        "ghidracli/query/NameSuggestions.java",
        include_str!("../scripts/ghidracli/query/NameSuggestions.java"),
    ),
    (
        "ghidracli/runtime/BridgeReply.java",
        include_str!("../scripts/ghidracli/runtime/BridgeReply.java"),
    ),
    (
        "ghidracli/runtime/BridgeRuntime.java",
        include_str!("../scripts/ghidracli/runtime/BridgeRuntime.java"),
    ),
    (
        "ghidracli/runtime/BridgeServer.java",
        include_str!("../scripts/ghidracli/runtime/BridgeServer.java"),
    ),
    (
        "ghidracli/runtime/CommandDispatcher.java",
        include_str!("../scripts/ghidracli/runtime/CommandDispatcher.java"),
    ),
    (
        "ghidracli/runtime/JobResultStore.java",
        include_str!("../scripts/ghidracli/runtime/JobResultStore.java"),
    ),
    (
        "ghidracli/runtime/JobScheduler.java",
        include_str!("../scripts/ghidracli/runtime/JobScheduler.java"),
    ),
    (
        "ghidracli/runtime/JobTaskMonitor.java",
        include_str!("../scripts/ghidracli/runtime/JobTaskMonitor.java"),
    ),
    (
        "ghidracli/script/ArtifactManifest.java",
        include_str!("../scripts/ghidracli/script/ArtifactManifest.java"),
    ),
    (
        "ghidracli/script/ScriptCommands.java",
        include_str!("../scripts/ghidracli/script/ScriptCommands.java"),
    ),
    (
        "ghidracli/session/DecompilerSession.java",
        include_str!("../scripts/ghidracli/session/DecompilerSession.java"),
    ),
    (
        "ghidracli/session/ProgramSession.java",
        include_str!("../scripts/ghidracli/session/ProgramSession.java"),
    ),
    (
        "ghidracli/session/ProgramTransaction.java",
        include_str!("../scripts/ghidracli/session/ProgramTransaction.java"),
    ),
    (
        "ghidracli/session/ScriptAccess.java",
        include_str!("../scripts/ghidracli/session/ScriptAccess.java"),
    ),
    (
        "ghidracli/symbol/BookmarkCommands.java",
        include_str!("../scripts/ghidracli/symbol/BookmarkCommands.java"),
    ),
    (
        "ghidracli/symbol/CommentCommands.java",
        include_str!("../scripts/ghidracli/symbol/CommentCommands.java"),
    ),
    (
        "ghidracli/symbol/EquateCommands.java",
        include_str!("../scripts/ghidracli/symbol/EquateCommands.java"),
    ),
    (
        "ghidracli/symbol/NamespaceCommands.java",
        include_str!("../scripts/ghidracli/symbol/NamespaceCommands.java"),
    ),
    (
        "ghidracli/symbol/NamespaceSupport.java",
        include_str!("../scripts/ghidracli/symbol/NamespaceSupport.java"),
    ),
    (
        "ghidracli/symbol/SymbolCommands.java",
        include_str!("../scripts/ghidracli/symbol/SymbolCommands.java"),
    ),
    (
        "ghidracli/symbol/XrefCommands.java",
        include_str!("../scripts/ghidracli/symbol/XrefCommands.java"),
    ),
    (
        "ghidracli/types/BitFieldCommands.java",
        include_str!("../scripts/ghidracli/types/BitFieldCommands.java"),
    ),
    (
        "ghidracli/types/BitFields.java",
        include_str!("../scripts/ghidracli/types/BitFields.java"),
    ),
    (
        "ghidracli/types/SignatureTypes.java",
        include_str!("../scripts/ghidracli/types/SignatureTypes.java"),
    ),
    (
        "ghidracli/types/StructureFields.java",
        include_str!("../scripts/ghidracli/types/StructureFields.java"),
    ),
    (
        "ghidracli/types/TypeArchiveCommands.java",
        include_str!("../scripts/ghidracli/types/TypeArchiveCommands.java"),
    ),
    (
        "ghidracli/types/TypeArchiveGraph.java",
        include_str!("../scripts/ghidracli/types/TypeArchiveGraph.java"),
    ),
    (
        "ghidracli/types/TypeCommands.java",
        include_str!("../scripts/ghidracli/types/TypeCommands.java"),
    ),
    (
        "ghidracli/types/TypeDefinitionCommands.java",
        include_str!("../scripts/ghidracli/types/TypeDefinitionCommands.java"),
    ),
    (
        "ghidracli/types/TypeFields.java",
        include_str!("../scripts/ghidracli/types/TypeFields.java"),
    ),
    (
        "ghidracli/types/TypeFieldTarget.java",
        include_str!("../scripts/ghidracli/types/TypeFieldTarget.java"),
    ),
    (
        "ghidracli/types/TypeImportCommands.java",
        include_str!("../scripts/ghidracli/types/TypeImportCommands.java"),
    ),
    (
        "ghidracli/types/TypeResizeCommands.java",
        include_str!("../scripts/ghidracli/types/TypeResizeCommands.java"),
    ),
    (
        "ghidracli/types/TypeResolver.java",
        include_str!("../scripts/ghidracli/types/TypeResolver.java"),
    ),
    (
        "ghidracli/types/TypeUseMatcher.java",
        include_str!("../scripts/ghidracli/types/TypeUseMatcher.java"),
    ),
    (
        "ghidracli/types/TypeUsesCommands.java",
        include_str!("../scripts/ghidracli/types/TypeUsesCommands.java"),
    ),
    (
        "ghidracli/types/UnionFields.java",
        include_str!("../scripts/ghidracli/types/UnionFields.java"),
    ),
];

/// Write a complete source tree into a private, empty directory.
pub(super) fn write_to(directory: &Path) -> Result<Vec<PathBuf>> {
    write_sources(directory, SOURCES)
}

fn write_sources(directory: &Path, sources: &[(&str, &str)]) -> Result<Vec<PathBuf>> {
    write_files(directory, &source_files(sources))
}

fn source_files<'a>(sources: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a [u8])> {
    sources
        .iter()
        .map(|(name, source)| (*name, source.as_bytes()))
        .collect()
}

fn write_files(directory: &Path, files: &[(&str, &[u8])]) -> Result<Vec<PathBuf>> {
    files
        .iter()
        .map(|(name, source)| {
            let path = directory.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| {
                crate::error::path_io("bridge.sources_directory", path.parent().unwrap(), e)
            })?;
            std::fs::write(&path, source)
                .map_err(|e| crate::error::path_io("bridge.sources_write", &path, e))?;
            Ok(path)
        })
        .collect()
}

/// Publish a complete bundle once, then reuse it without touching timestamps.
/// Different CLI builds never overwrite sources that a running JVM may use.
pub(super) fn install() -> Result<PathBuf> {
    install_sources(&root_path()?, SOURCES)
}

pub(super) fn root_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("Could not determine config directory")?
        .join("ghidra-cli")
        .join("bridge-sources"))
}

fn install_sources(root: &Path, sources: &[(&str, &str)]) -> Result<PathBuf> {
    install_files(root, &source_files(sources))
}

/// Publish immutable launch resources with the same lifetime as source bundles.
pub(super) fn install_files(root: &Path, files: &[(&str, &[u8])]) -> Result<PathBuf> {
    let mut hash = md5::Context::new();
    for (name, contents) in files {
        hash.consume(name.as_bytes());
        hash.consume([0]);
        hash.consume(contents);
        hash.consume([0]);
    }
    let destination = root.join(format!("{:x}", hash.finalize()));
    if destination.is_dir() {
        return Ok(destination);
    }

    std::fs::create_dir_all(root)
        .map_err(|e| crate::error::path_io("bridge.sources_directory", root, e))?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(root)
        .map_err(|e| crate::error::path_io("bridge.sources_staging", root, e))?;
    write_files(staging.path(), files)?;
    if let Err(error) = std::fs::rename(staging.path(), &destination) {
        // Another project may have published the identical complete bundle.
        if !destination.is_dir() {
            return Err(
                crate::error::path_io("bridge.sources_publish", &destination, error).into(),
            );
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

    #[test]
    fn java_packages_match_paths_and_have_no_cycles() {
        use std::collections::{BTreeMap, BTreeSet};

        let mut dependencies: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (path, source) in SOURCES {
            let expected = path
                .rsplit_once('/')
                .map(|(parent, _)| parent.replace('/', "."));
            let declared = source.lines().find_map(|line| {
                line.strip_prefix("package ")
                    .and_then(|s| s.strip_suffix(';'))
            });
            assert_eq!(
                declared,
                expected.as_deref(),
                "package/source mismatch: {path}"
            );
            if let Some(package) = expected {
                dependencies.entry(package).or_default();
            }
        }

        let packages: Vec<_> = dependencies.keys().cloned().collect();
        for (path, source) in SOURCES {
            let Some((parent, _)) = path.rsplit_once('/') else {
                continue; // Ghidra's default-package entry scripts.
            };
            let package = parent.replace('/', ".");
            for line in source.lines() {
                let Some(import) = line.strip_prefix("import ") else {
                    continue;
                };
                let import = import.strip_prefix("static ").unwrap_or(import);
                if !import.starts_with("ghidracli.") {
                    continue;
                }
                let target = packages
                    .iter()
                    .find(|candidate| import.starts_with(&format!("{candidate}.")))
                    .unwrap_or_else(|| panic!("unknown bridge package in {path}: {line}"));
                if target != &package {
                    dependencies
                        .get_mut(&package)
                        .unwrap()
                        .insert(target.clone());
                }
            }
        }

        while !dependencies.is_empty() {
            let leaves: BTreeSet<_> = dependencies
                .iter()
                .filter(|(_, targets)| targets.is_empty())
                .map(|(package, _)| package.clone())
                .collect();
            assert!(
                !leaves.is_empty(),
                "cyclic Java package dependencies: {dependencies:#?}"
            );
            dependencies.retain(|package, _| !leaves.contains(package));
            for targets in dependencies.values_mut() {
                targets.retain(|target| !leaves.contains(target));
            }
        }
    }
}
