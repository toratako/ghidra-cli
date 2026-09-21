//! File layout for tests that validate routing without starting a real JVM.

pub fn write(path: &std::path::Path) {
    let launcher = if cfg!(windows) {
        "support/analyzeHeadless.bat"
    } else {
        "support/analyzeHeadless"
    };
    for (name, content) in [
        (launcher, "Test fixture: must not be executed"),
        (
            "Ghidra/application.properties",
            "application.version=12.1.3\napplication.java.min=21\napplication.release.name=DEV\n",
        ),
        (
            "Ghidra/Framework/Utility/lib/Utility.jar",
            "fixture runtime",
        ),
        ("support/LaunchSupport.jar", "fixture runtime"),
    ] {
        let file = path.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }
}
