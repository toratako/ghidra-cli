use crate::config::Config;
use std::path::{Path, PathBuf};

/// Whether a Ghidra project already exists on disk for the given project path.
///
/// `project_path` is `<parent>/<name>`; analyzeHeadless materializes the project
/// as sibling `<parent>/<name>.gpr` (project file) and `<parent>/<name>.rep`
/// (project directory). Either marks an existing project we can `-process`.
pub(super) fn project_exists(project_path: &Path) -> bool {
    match (project_path.file_name(), project_path.parent()) {
        (Some(name), Some(parent)) => {
            let name = name.to_string_lossy();
            parent.join(format!("{}.gpr", name)).exists()
                || parent.join(format!("{}.rep", name)).exists()
        }
        _ => false,
    }
}

/// Whether a project contains persisted program data and can be opened with
/// `analyzeHeadless -process`.
///
/// A stale or newly-created empty project may have both `.gpr` and `.rep`
/// artifacts but only index files under `.rep/idata`. Starting a project-mode
/// bridge for that state fails before the bridge script can accept an import.
/// Real program data lives in bucket subdirectories under `idata`.
pub(super) fn project_has_program_data(project_path: &Path) -> bool {
    let (Some(name), Some(parent)) = (project_path.file_name(), project_path.parent()) else {
        return false;
    };
    let name = name.to_string_lossy();
    let gpr = parent.join(format!("{}.gpr", name));
    let idata = parent.join(format!("{}.rep", name)).join("idata");

    gpr.is_file()
        && std::fs::read_dir(idata)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .any(|entry| entry.path().is_dir())
            })
            .unwrap_or(false)
}

/// Load config, applying the global `--projects-dir` override (if any) onto
/// `ghidra_project_dir`. This keeps the precedence in [`Config::get_project_dir`]
/// (env var > config field > default) while letting the CLI flag win in-process
/// without mutating global state.
pub(super) fn load_config(projects_dir: &Option<PathBuf>) -> anyhow::Result<Config> {
    let mut config = Config::load()?;
    if let Some(dir) = projects_dir {
        config.ghidra_project_dir = Some(dir.clone());
    }
    Ok(config)
}

/// Resolve a project name to its full path on disk.
pub(super) fn resolve_project_path(
    project: &Option<String>,
    config: &Config,
) -> anyhow::Result<PathBuf> {
    let project_name = project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))?;

    let project_dir = config.get_project_dir()?;

    if PathBuf::from(&project_name).is_absolute() {
        Ok(PathBuf::from(project_name))
    } else {
        Ok(project_dir.join(project_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_project_artifacts_are_not_program_data() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("stale");
        std::fs::write(temp.path().join("stale.gpr"), []).unwrap();
        std::fs::create_dir_all(temp.path().join("stale.rep/idata")).unwrap();
        std::fs::write(temp.path().join("stale.rep/idata/~index.dat"), []).unwrap();

        assert!(project_exists(&project));
        assert!(!project_has_program_data(&project));
    }

    #[test]
    fn idata_bucket_marks_project_as_populated() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("populated");
        std::fs::write(temp.path().join("populated.gpr"), []).unwrap();
        std::fs::create_dir_all(temp.path().join("populated.rep/idata/00")).unwrap();

        assert!(project_has_program_data(&project));
    }
}
