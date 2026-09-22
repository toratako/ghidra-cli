"""Build the native Ghidra tools missing from the macOS release archive."""

import json
import os
from pathlib import Path
import platform
import subprocess


def main():
    install = Path(json.loads(subprocess.check_output(
        ["cargo", "run", "--quiet", "--", "config", "get", "ghidra_install_dir", "--json"],
        text=True,
    ))["data"])
    native_platform = {"arm64": "mac_arm_64", "x86_64": "mac_x86_64"}[platform.machine()]
    required = [
        ("Ghidra/Features/Decompiler", "decompile"),
        ("GPL/DemanglerGnu", "demangler_gnu_v2_24"),
        ("GPL/DemanglerGnu", "demangler_gnu_v2_41"),
    ]

    def missing_tools():
        return [name for module, name in required if not any(
            (path := install / module / directory / native_platform / name).is_file()
            and os.access(path, os.X_OK)
            for directory in ["build/os", "os"]
        )]

    if not missing_tools():
        print(f"Ghidra native tools already installed for {native_platform}")
        return

    subprocess.run(
        ["bash", "./gradlew", "--no-daemon", "buildNatives"],
        cwd=install / "support/gradle",
        check=True,
    )
    if missing := missing_tools():
        raise SystemExit(f"Ghidra native build did not install: {', '.join(missing)}")


if __name__ == "__main__":
    main()
