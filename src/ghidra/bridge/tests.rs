use super::*;
use std::cell::Cell;

#[test]
fn stopped_project_remains_locked_through_the_deletion_callback() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("delete-project");
    std::fs::create_dir(project.with_added_extension("rep")).unwrap();
    stop_bridge_then(&project, Some(Duration::from_secs(1)), || {
        assert!(
            acquire_lifecycle_lock(
                &project,
                Some(std::time::Instant::now() + Duration::from_millis(30))
            )
            .is_err(),
            "startup must not race deletion after the bridge exits"
        );
        Ok(())
    })
    .unwrap();
    let _released = acquire_lifecycle_lock(
        &project,
        Some(std::time::Instant::now() + Duration::from_secs(1)),
    )
    .unwrap();
}

#[test]
fn shutdown_deadline_includes_lifecycle_lock_wait_and_retains_timeout_type() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("locked-project");
    let _holder = acquire_startup_lock(&project).unwrap();
    let started = std::time::Instant::now();
    let error = stop_bridge_with_timeout(&project, Some(Duration::from_millis(30))).unwrap_err();
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
        .is_some());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn shutdown_drain_deadline_preserves_live_discovery_and_timeout_type() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("draining-project");
    let pid = std::process::id();
    let port = 12345;
    let pid_path = pid_file_path(&project).unwrap();
    let port_path = port_file_path(&project).unwrap();
    std::fs::write(&pid_path, pid.to_string()).unwrap();
    std::fs::write(&port_path, port.to_string()).unwrap();

    let started = std::time::Instant::now();
    let elapsed = Cell::new(Duration::ZERO);
    let timeout = Duration::from_millis(250);
    let acknowledged = Cell::new(false);
    let mut waits = Vec::new();
    let error = stop_bridge_with(
        &project,
        Some(timeout),
        |observed_pid| {
            assert_eq!(observed_pid, pid);
            true // The bridge remains alive after acknowledging shutdown.
        },
        |observed_port, deadline| {
            assert_eq!(observed_port, port);
            assert_eq!(deadline, Some(started + timeout));
            assert!(!acknowledged.replace(true), "shutdown must not be replayed");
            elapsed.set(Duration::from_millis(25));
            Ok(())
        },
        || started + elapsed.get(),
        |wait| {
            assert!(acknowledged.get());
            assert!(!wait.is_zero(), "shutdown must stop at the deadline");
            assert!(elapsed.get() + wait <= timeout);
            waits.push(wait);
            elapsed.set(elapsed.get() + wait);
        },
        || Ok(()),
    )
    .unwrap_err();
    assert!(acknowledged.get());
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
        .is_some());
    assert_eq!(elapsed.get(), timeout);
    assert_eq!(
        waits,
        [
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(25),
        ]
    );
    assert_eq!(read_pid_file(&project).unwrap(), Some(pid));
    assert_eq!(read_port_file(&project).unwrap(), Some(port));
    std::fs::remove_file(pid_path).unwrap();
    std::fs::remove_file(port_path).unwrap();
}

#[test]
fn shutdown_deadline_expiring_during_pid_check_preserves_discovery_and_timeout_type() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("slow-pid-check-project");
    let pid = std::process::id();
    let port = 12345;
    let pid_path = pid_file_path(&project).unwrap();
    let port_path = port_file_path(&project).unwrap();
    std::fs::write(&pid_path, pid.to_string()).unwrap();
    std::fs::write(&port_path, port.to_string()).unwrap();

    let started = std::time::Instant::now();
    let elapsed = Cell::new(Duration::ZERO);
    let timeout = Duration::from_millis(100);
    let mut attempted = false;
    let error = stop_bridge_with(
        &project,
        Some(timeout),
        |observed_pid| {
            assert_eq!(observed_pid, pid);
            // Model a Windows tasklist invocation outlasting the budget.
            elapsed.set(elapsed.get() + Duration::from_millis(150));
            true
        },
        |observed_port, deadline| {
            assert_eq!(observed_port, port);
            assert_eq!(deadline, Some(started + timeout));
            assert!(started + elapsed.get() >= deadline.unwrap());
            attempted = true;
            // The transport rejects an expired deadline before connecting.
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
        },
        || started + elapsed.get(),
        |_| panic!("an expired shutdown must return without sleeping"),
        || Ok(()),
    )
    .unwrap_err();
    assert!(attempted);
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
        .is_some());
    assert_eq!(read_pid_file(&project).unwrap(), Some(pid));
    assert_eq!(read_port_file(&project).unwrap(), Some(port));
    std::fs::remove_file(pid_path).unwrap();
    std::fs::remove_file(port_path).unwrap();
}

#[test]
fn lifecycle_lock_recovers_empty_file_and_excludes_waiters() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bridge.starting");
    std::fs::write(&path, []).unwrap();
    let holder = acquire_file_lock(&path, Duration::from_millis(50)).unwrap();
    assert!(acquire_file_lock(&path, Duration::from_millis(30)).is_err());
    drop(holder);
    assert!(
        path.exists(),
        "the inode must remain stable for waiting callers"
    );
    let _next = acquire_file_lock(&path, Duration::from_millis(50)).unwrap();
}

#[test]
fn cleanup_preserves_live_process_discovery_and_unknown_project_locks() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("Project.v1");
    let pid_path = pid_file_path(&project).unwrap();
    let port_path = port_file_path(&project).unwrap();
    let lock_path = project.with_added_extension("lock");
    std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
    std::fs::write(&port_path, "1").unwrap();
    std::fs::write(&lock_path, "held").unwrap();
    assert!(cleanup_stale_files(&project).is_err());
    assert!(pid_path.exists() && port_path.exists() && lock_path.exists());
    std::fs::remove_file(pid_path).unwrap();
    cleanup_stale_files(&project).unwrap();
    assert!(
        lock_path.exists(),
        "missing discovery does not prove project lock ownership"
    );
    assert!(!port_path.exists());
}

#[test]
fn discovery_keys_normalize_missing_project_paths() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("missing/project");
    let alias = root.path().join("missing/./project");
    assert_eq!(
        project_hash(&project).unwrap(),
        project_hash(&alias).unwrap()
    );
    assert_eq!(
        project_hash(Path::new("missing/./project")).unwrap(),
        project_hash(&std::env::current_dir().unwrap().join("missing/project")).unwrap()
    );
}

#[test]
fn discovery_keys_preserve_dotted_names_and_resolve_repository_paths() {
    let root = tempfile::tempdir().unwrap();
    let directory = dunce::canonicalize(root.path()).unwrap();
    let project = directory.join("Project.v1");
    let repository = directory.join("Project.v1.rep");
    std::fs::create_dir(&repository).unwrap();
    let original_hash = project_hash(&project).unwrap();
    assert_eq!(
        project_hash(&directory.join("./Project.v1")).unwrap(),
        original_hash
    );
    #[cfg(windows)]
    assert_eq!(
        project_hash(Path::new(&project.to_string_lossy().replace('\\', "/"))).unwrap(),
        original_hash
    );
    std::fs::write(directory.join("Project.v1.gpr"), []).unwrap();
    assert_eq!(project_hash(&project).unwrap(), original_hash);
    std::fs::create_dir(directory.join("Project.v2.rep")).unwrap();
    assert_ne!(
        project_hash(&directory.join("Project.v2")).unwrap(),
        original_hash
    );
}

#[test]
fn discovery_keys_respect_filesystem_case_sensitivity() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("Project");
    let alias = root.path().join("project");
    std::fs::create_dir(root.path().join("Project.rep")).unwrap();
    if root.path().join("project.rep").exists() {
        assert_eq!(
            project_hash(&project).unwrap(),
            project_hash(&alias).unwrap()
        );
    } else {
        std::fs::create_dir(root.path().join("project.rep")).unwrap();
        assert_ne!(
            project_hash(&project).unwrap(),
            project_hash(&alias).unwrap()
        );
    }
}

#[cfg(unix)]
#[test]
fn discovery_keys_resolve_directory_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("projects");
    std::fs::create_dir_all(directory.join("project.rep")).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&directory, &alias).unwrap();
    assert_eq!(
        project_hash(&directory.join("project")).unwrap(),
        project_hash(&alias.join("project")).unwrap()
    );

    // Repository symlink targets need not themselves end in .rep.
    for name in ["store.v1", "store.v2", "store.rep"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
    }
    std::os::unix::fs::symlink(root.path().join("store.v1"), root.path().join("first.rep"))
        .unwrap();
    std::os::unix::fs::symlink(root.path().join("store.v2"), root.path().join("second.rep"))
        .unwrap();
    let first_hash = project_hash(&root.path().join("first")).unwrap();
    assert_ne!(
        first_hash,
        project_hash(&root.path().join("second")).unwrap()
    );
    assert_ne!(
        first_hash,
        project_hash(&root.path().join("store")).unwrap()
    );
}

#[test]
fn shutdown_timeout_defaults_and_supports_unbounded_wait() {
    assert_eq!(
        parse_shutdown_timeout(None),
        Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
    );
    assert_eq!(
        parse_shutdown_timeout(Some(" 45 ")),
        Some(Duration::from_secs(45))
    );
    assert_eq!(parse_shutdown_timeout(Some("0")), None);
    assert_eq!(
        parse_shutdown_timeout(Some("invalid")),
        Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
    );
}
