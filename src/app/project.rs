use crate::config::Config;
use crate::ghidra::project::ProjectPaths;
use std::path::{Path, PathBuf};

/// Whether an import can reuse a project containing persisted program data.
///
/// A stale or newly-created empty project may have both `.gpr` and `.rep`
/// artifacts but only index files under `.rep/idata`. The import workflow uses
/// the one-shot importer to initialize such projects.
/// Real program data lives in bucket subdirectories under `idata`.
pub(super) fn project_has_program_data(project_path: &Path) -> bool {
    ProjectPaths::new(project_path).is_some_and(|paths| paths.has_program_data())
}

/// Load config with a transient `--projects-dir` override. Directory precedence
/// is CLI > environment > configuration > default, without changing the process
/// environment or the persisted configuration.
pub(super) fn load_config(projects_dir: &Option<PathBuf>) -> anyhow::Result<Config> {
    let mut config = Config::load()?;
    config.projects_dir_override = projects_dir.clone();
    Ok(config)
}

pub(super) fn resolve_project_name(
    project: &Option<String>,
    config: &Config,
) -> anyhow::Result<String> {
    project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))
}

/// Resolve a project name to its full path on disk.
pub(super) fn resolve_project_path(
    project: &Option<String>,
    config: &Config,
) -> anyhow::Result<PathBuf> {
    let project_name = resolve_project_name(project, config)?;

    let project_dir = config.get_project_dir()?;

    let path = if PathBuf::from(&project_name).is_absolute() {
        PathBuf::from(project_name)
    } else {
        project_dir.join(project_name)
    };
    Ok(std::path::absolute(path)?)
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
