pub mod bridge;
pub mod installation;
pub mod java;
pub(crate) mod project;

use crate::config::Config;
use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct GhidraClient {
    install_dir: PathBuf,
    project_dir: PathBuf,
}

impl GhidraClient {
    pub fn new(config: Config) -> Result<Self> {
        let install_dir = config.get_ghidra_install_dir()?;
        let project_dir = std::path::absolute(config.get_project_dir()?)?;

        // Create project directory if it doesn't exist
        if !project_dir.exists() {
            std::fs::create_dir_all(&project_dir)?;
        }

        Ok(Self {
            install_dir,
            project_dir,
        })
    }

    #[allow(dead_code)] // Doctor resolves the launcher without creating project directories.
    pub fn verify_installation(&self) -> Result<()> {
        installation::inspect(&self.install_dir)?;
        Ok(())
    }

    pub fn get_project_path(&self, project_name: &str) -> PathBuf {
        self.project_dir.join(project_name)
    }

    pub fn get_project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub fn delete_project(&self, name: &str) -> anyhow::Result<bool> {
        bridge::delete_project(&self.get_project_path(name), &self.install_dir)
    }

    pub fn archive_project(&self, name: &str, output: &Path) -> anyhow::Result<serde_json::Value> {
        bridge::archive::archive_project(&self.get_project_path(name), output, &self.install_dir)
    }

    pub fn restore_project(&self, archive: &Path, name: &str) -> anyhow::Result<serde_json::Value> {
        bridge::archive::restore_project(archive, &self.get_project_path(name), &self.install_dir)
    }
}
