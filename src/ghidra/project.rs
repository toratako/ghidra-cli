//! On-disk project layout shared by local management and import selection.

use std::path::{Path, PathBuf};

/// Reject paths that cannot retain their filesystem identity in Ghidra.
pub(crate) fn validate_project_path(project: &Path) -> anyhow::Result<()> {
    let path = project.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Project path cannot be represented as UTF-8: {}",
            project.display()
        )
    })?;
    #[cfg(unix)]
    anyhow::ensure!(
        !path.contains('\\'),
        "Project path cannot contain backslashes on Unix: {}",
        project.display()
    );
    #[cfg(not(unix))]
    let _ = path;
    anyhow::ensure!(
        !project
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".gpr")),
        "Use a project base path without the .gpr suffix: {}",
        project.display()
    );
    Ok(())
}

pub(crate) struct ProjectPaths {
    pub descriptor: PathBuf,
    pub data: PathBuf,
}

impl ProjectPaths {
    pub fn new(project: &Path) -> Option<Self> {
        let project = project.parent()?.join(project.file_name()?);
        Some(Self {
            descriptor: project.with_added_extension("gpr"),
            data: project.with_added_extension("rep"),
        })
    }

    pub fn exists(&self) -> bool {
        // Deletion must still claim and remove dangling project artifacts.
        self.descriptor.symlink_metadata().is_ok() || self.data.symlink_metadata().is_ok()
    }

    pub fn has_program_data(&self) -> bool {
        self.descriptor.is_file()
            && std::fs::read_dir(self.data.join("idata"))
                .map(|entries| entries.flatten().any(|entry| entry.path().is_dir()))
                .unwrap_or(false)
    }
}

pub(crate) fn list_projects(directory: &Path) -> std::io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut projects = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if entry.path().is_dir() {
            if let Some(name) = name.strip_suffix(".rep") {
                projects.insert(name.to_owned());
            }
        } else if entry.path().is_file() {
            if let Some(name) = name.strip_suffix(".gpr") {
                projects.insert(name.to_owned());
            }
        }
    }
    Ok(projects.into_iter().collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // APFS rejects invalid UTF-8 filenames, so creating this fixture requires Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn artifact_names_preserve_os_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let project = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"project\xff".to_vec()));
        let paths = ProjectPaths::new(&project).unwrap();
        assert_eq!(paths.descriptor, project.with_added_extension("gpr"));
        assert_eq!(paths.data, project.with_added_extension("rep"));
        std::fs::write(temp.path().join("project\u{fffd}.gpr"), []).unwrap();
        assert!(!paths.exists());
        std::fs::write(project.with_added_extension("gpr"), []).unwrap();
        assert!(paths.exists());
    }

    #[test]
    fn project_listing_preserves_directory_read_errors() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("projects");
        assert!(list_projects(&directory).unwrap().is_empty());
        std::os::unix::fs::symlink("projects", &directory).unwrap();
        let expected = std::fs::read_dir(&directory).unwrap_err();
        let error = list_projects(&directory).unwrap_err();
        assert_eq!(error.kind(), expected.kind());
        assert_eq!(error.raw_os_error(), expected.raw_os_error());
    }
}
