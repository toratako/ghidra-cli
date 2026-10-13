fn main() {
    // launch.bat probes java.exe -version before using it for LaunchSupport.
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("-version")) {
        return;
    }
    std::fs::write(std::env::var_os("GHIDRA_CLI_TEST_PATH_JAVA_MARKER").unwrap(), b"called").unwrap();
    std::process::exit(1);
}
