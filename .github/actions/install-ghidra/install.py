"""Install the pinned CI distribution into the runner's temporary directory."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def extract_archive(archive, destination, expected_sha256):
    with archive.open("rb") as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise RuntimeError("Ghidra archive SHA-256 mismatch")

    # Native extractors preserve modification times and executable permissions.
    # Ghidra compares .sla files with their language sources to decide on rebuilds.
    if os.name == "nt":
        # Use Windows' bsdtar, not a GNU tar earlier on PATH (which cannot read ZIP).
        tar = Path(os.environ["SystemRoot"]) / "System32/tar.exe"
        command = [str(tar), "-xf", str(archive), "-C", str(destination)]
    else:
        command = ["unzip", "-q", str(archive), "-d", str(destination)]
    subprocess.run(command, check=True)


def main():
    release = json.loads(Path(__file__).with_name("release.json").read_text())
    install = Path(os.environ["GHIDRA_INSTALL_DIR"])
    install.parent.mkdir(parents=True, exist_ok=True)
    url = (
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
        f"Ghidra_{release['version']}_build/{release['archive']}"
    )
    # Failed downloads/extractions never become a cached installation.
    with tempfile.TemporaryDirectory(prefix="ghidra-download-", dir=install.parent) as directory:
        staging = Path(directory)
        archive = staging / release["archive"]
        subprocess.run(
            ["curl", "--fail", "--location", "--retry", "3", "--output", str(archive), url],
            check=True,
        )
        extract_archive(archive, staging, release["sha256"])
        (staging / f"ghidra_{release['version']}_PUBLIC").rename(install)


if __name__ == "__main__":
    main()
