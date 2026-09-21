use super::*;

#[test]
fn project_directory_override_is_never_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let configured = temp.path().join("configured");
    let requested = temp.path().join("requested");
    let config = Config {
        ghidra_project_dir: Some(configured.clone()),
        projects_dir_override: Some(requested.clone()),
        ..Config::default()
    };
    assert_eq!(config.get_project_dir().unwrap(), requested);
    let path = temp.path().join("config.yaml");
    config.save_at(&path).unwrap();
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("projects_dir_override"));
    let restored = Config::load_from(&path).unwrap();
    assert_eq!(restored.projects_dir_override, None);
    assert_eq!(restored.ghidra_project_dir, Some(configured));
}

#[cfg(unix)]
#[test]
fn config_symlink_is_preserved_by_save_and_concurrent_updates() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dotfiles.yaml");
    let link = temp.path().join("config.yaml");
    Config::default().save_at(&target).unwrap();
    std::os::unix::fs::symlink("dotfiles.yaml", &link).unwrap();
    let config = Config {
        default_limit: Some(0),
        ..Config::default()
    };
    config.save_at(&link).unwrap();
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(Config::load_from(&target).unwrap().default_limit, Some(0));
    assert_eq!(
        Config::write_path(&target).unwrap(),
        Config::write_path(&link).unwrap()
    );
    std::thread::scope(|scope| {
        for index in 0..8 {
            let path = if index % 2 == 0 {
                target.clone()
            } else {
                link.clone()
            };
            scope.spawn(move || {
                for _ in 0..5 {
                    Config::update_at(&path, |config| {
                        config.default_limit = Some(config.default_limit.unwrap() + 1);
                        Ok(())
                    })
                    .unwrap();
                }
            });
        }
    });
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("dotfiles.yaml")
    );
    assert_eq!(Config::load_from(&target).unwrap().default_limit, Some(40));
    assert!(!temp.path().join("config.yaml.lock").exists());
}

#[cfg(unix)]
#[test]
fn dangling_config_symlink_is_not_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("config.yaml");
    std::os::unix::fs::symlink("missing.yaml", &link).unwrap();
    assert!(Config::default().save_at(&link).is_err());
    assert!(Config::update_at(&link, |_| Ok(())).is_err());
    assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("missing.yaml"));
}

#[test]
fn failed_update_preserves_config() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    let original = "default_project: keep-me\n";
    fs::write(&path, original).unwrap();
    let result = Config::update_at(&path, |config| {
        config.default_project = Some("discard-me".into());
        Err(GhidraError::ConfigError("rejected".into()))
    });
    assert!(result.is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), original);
}

#[test]
fn invalid_config_is_not_replaced_by_update() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    fs::write(&path, "[invalid yaml").unwrap();
    assert!(Config::update_at(&path, |_| Ok(())).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "[invalid yaml");
}

#[test]
fn concurrent_updates_preserve_every_increment() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..5 {
                    Config::update_at(&path, |config| {
                        config.default_limit = Some(config.default_limit.unwrap() + 1);
                        Ok(())
                    })
                    .unwrap();
                }
            });
        }
    });
    assert_eq!(Config::load_from(&path).unwrap().default_limit, Some(1040));
}

#[cfg(unix)]
#[test]
fn save_and_update_preserve_shared_config_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    fs::write(&path, "default_project: original\n").unwrap();
    // A replacement must remain group-readable without opening it to everyone.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

    Config {
        default_project: Some("saved-project".into()),
        ..Config::default()
    }
    .save_at(&path)
    .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );

    Config::update_at(&path, |config| {
        config.default_limit = Some(37);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let restored = Config::load_from(&path).unwrap();
    assert_eq!(restored.default_project.as_deref(), Some("saved-project"));
    assert_eq!(restored.default_limit, Some(37));
}

#[test]
fn save_and_update_replace_config_while_previous_version_is_open() {
    use std::io::Read;

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("user's config");
    let path = dir.join("config.yaml");
    Config::default().save_at(&path).unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let mut reader = fs::File::open(&path).unwrap();

    Config::update_at(&path, |config| {
        config.default_limit = Some(42);
        Ok(())
    })
    .unwrap();
    assert_eq!(Config::load_from(&path).unwrap().default_limit, Some(42));
    let mut previous = String::new();
    reader.read_to_string(&mut previous).unwrap();
    assert_eq!(previous, original);

    let mut reader = fs::File::open(&path).unwrap();
    Config::default().save_at(&path).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let mut previous = String::new();
    reader.read_to_string(&mut previous).unwrap();
    assert_eq!(
        serde_yaml::from_str::<Config>(&previous)
            .unwrap()
            .default_limit,
        Some(42)
    );
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TEMPORARY;

        assert_eq!(
            fs::metadata(&path).unwrap().file_attributes() & FILE_ATTRIBUTE_TEMPORARY,
            0
        );
    }
}

#[cfg(windows)]
#[test]
fn blocked_replacement_preserves_config_and_cleans_staging() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    Config::default().save_at(&path).unwrap();
    let original = fs::read_to_string(&path).unwrap();
    // Unlike ordinary readers, this handle explicitly forbids replacement.
    let reader = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .unwrap();
    let result = Config::update_at(&path, |config| {
        config.default_limit = Some(42);
        Ok(())
    });
    assert!(matches!(
        result,
        Err(GhidraError::PathIo {
            stage: "config.publish",
            ..
        })
    ));
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    drop(reader);

    Config::update_at(&path, |config| {
        config.default_limit = Some(42);
        Ok(())
    })
    .unwrap();
    assert_eq!(Config::load_from(&path).unwrap().default_limit, Some(42));
}

#[test]
fn failed_publication_preserves_destination_and_cleans_staging() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("keep"), "original").unwrap();
    assert!(Config::default().save_to(&path).is_err());
    assert_eq!(fs::read_to_string(path.join("keep")).unwrap(), "original");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.default_limit, Some(1000));
}

#[test]
fn default_project_dir_has_no_hidden_component() {
    let dir = Config::default_project_dir().expect("default project dir");
    assert!(
        !has_hidden_component(&dir),
        "default project dir must not contain a dot-prefixed component (Ghidra 12.1+): {}",
        dir.display()
    );
}

#[test]
fn has_hidden_component_detects_dot_dirs() {
    assert!(has_hidden_component(Path::new(
        "/home/u/.cache/ghidra-cli/projects"
    )));
    assert!(has_hidden_component(Path::new(
        "/home/u/.local/share/ghidra-cli"
    )));
    assert!(!has_hidden_component(Path::new(
        "/home/u/ghidra-cli/projects"
    )));
    assert!(!has_hidden_component(Path::new(
        "/Users/u/Library/Caches/ghidra-cli/projects"
    )));
}
