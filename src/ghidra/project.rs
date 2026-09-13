//! On-disk project layout shared by local management and import selection.

use std::path::{Path, PathBuf};

pub(crate) struct ProjectPaths {
    pub descriptor: PathBuf,
    pub data: PathBuf,
    pub legacy: PathBuf,
}

impl ProjectPaths {
    pub fn new(project: &Path) -> Option<Self> {
        let name = project.file_name()?.to_string_lossy();
        let parent = project.parent()?;
        Some(Self {
            descriptor: parent.join(format!("{name}.gpr")),
            data: parent.join(format!("{name}.rep")),
            legacy: project.to_path_buf(),
        })
    }

    pub fn exists(&self) -> bool {
        self.descriptor.exists() || self.data.exists()
    }

    pub fn has_program_data(&self) -> bool {
        self.descriptor.is_file()
            && std::fs::read_dir(self.data.join("idata"))
                .map(|entries| entries.flatten().any(|entry| entry.path().is_dir()))
                .unwrap_or(false)
    }

    pub fn is_empty_reservation(&self) -> bool {
        self.legacy.is_dir()
            && std::fs::read_dir(&self.legacy).is_ok_and(|mut entries| entries.next().is_none())
    }
}

pub(crate) fn list_projects(directory: &Path) -> std::io::Result<Vec<String>> {
    let mut projects = std::collections::BTreeSet::new();
    if directory.exists() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if entry.path().is_dir() {
                if let Some(name) = name.strip_suffix(".rep") {
                    projects.insert(name.to_owned());
                } else if ProjectPaths::new(&entry.path())
                    .is_some_and(|paths| paths.is_empty_reservation())
                {
                    projects.insert(name.to_owned());
                }
            } else if entry.path().is_file() {
                if let Some(name) = name.strip_suffix(".gpr") {
                    projects.insert(name.to_owned());
                }
            }
        }
    }
    Ok(projects.into_iter().collect())
}
