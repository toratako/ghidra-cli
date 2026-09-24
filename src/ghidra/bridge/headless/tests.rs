use super::*;
use std::path::PathBuf;

fn installation(path: PathBuf, kind: InstallationKind) -> Installation {
    Installation {
        path,
        kind,
        version: "12.1.4".into(),
        source: "test".into(),
        min_java: 21,
    }
}

#[test]
fn jar_launch_uses_selected_java_and_heap_limits() {
    let root = tempfile::Builder::new()
        .prefix("Ghidra launch's #日本語 ")
        .tempdir()
        .unwrap();
    let install = installation(root.path().join("standalone.jar"), InstallationKind::Jar);
    let jdk = JdkInfo {
        home: root.path().join("jdk home"),
        major: 21,
        source: "test".into(),
    };
    let command =
        command_with_jdk(&install, Some(&jdk), Some("4G".into()), Some("1G".into())).unwrap();
    assert_eq!(
        command.get_program(),
        jdk.home
            .join("bin")
            .join(if cfg!(windows) { "java.exe" } else { "java" })
    );
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args[0], "-Xmx4G");
    assert!(command
        .get_envs()
        .any(|(key, value)| key == "JAVA_HOME" && value == Some(jdk.home.as_os_str())));
    assert!(command_with_jdk(&install, None, None, None).is_err());
    for (specific, general, expected) in [
        (Some(""), Some("768M"), "-Xmx768M"),
        (None, Some(""), "-Xmx2G"),
    ] {
        let cmd = command_with_jdk(
            &install,
            Some(&jdk),
            specific.map(Into::into),
            general.map(Into::into),
        )
        .unwrap();
        assert_eq!(cmd.get_args().next().unwrap(), expected);
    }
}

#[test]
fn directory_launch_keeps_the_official_wrapper_and_its_java_fallback() {
    let install = installation(
        PathBuf::from("distribution root"),
        InstallationKind::Directory,
    );
    let command = command_with_jdk(&install, None, None, None).unwrap();
    assert_eq!(command.get_program(), install.launcher().unwrap());
    assert_eq!(command.get_args().count(), 0);
    assert_eq!(command.get_envs().count(), 0);
}

#[test]
fn directory_launch_rejects_an_invalid_explicit_jdk() {
    let root = tempfile::tempdir().unwrap();
    let install = installation(
        root.path().join("distribution"),
        InstallationKind::Directory,
    );
    let missing = root.path().join("missing-jdk");
    let error = resolve_launch_jdk(&install, Some(missing.clone())).unwrap_err();
    assert!(error.to_string().contains(&missing.display().to_string()));
}

#[test]
fn jar_compilation_cannot_pick_up_libraries_from_its_parent_directory() {
    let root = tempfile::tempdir().unwrap();
    let jar = root.path().join("selected.jar");
    let unrelated = root.path().join("other-version.jar");
    std::fs::write(&jar, []).unwrap();
    std::fs::write(unrelated, []).unwrap();
    let install = installation(jar.clone(), InstallationKind::Jar);
    let classpath = compile_classpath(&install).unwrap();
    assert_eq!(std::env::split_paths(&classpath).collect::<Vec<_>>(), [jar]);
}

#[cfg(unix)]
#[test]
fn directory_compilation_includes_package_manager_library_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("distribution");
    std::fs::create_dir(&directory).unwrap();
    let actual = root.path().join("package-store.jar");
    std::fs::write(&actual, []).unwrap();
    let linked = directory.join("library.jar");
    std::os::unix::fs::symlink(actual, &linked).unwrap();
    let install = installation(directory, InstallationKind::Directory);
    let classpath = compile_classpath(&install).unwrap();
    assert_eq!(
        std::env::split_paths(&classpath).collect::<Vec<_>>(),
        [linked]
    );
}
