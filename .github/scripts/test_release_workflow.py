"""Run release archive steps locally without publishing or credentials."""

import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
import zipfile


def archive_script(name, target, tag):
    workflow = Path(__file__).parents[1] / "workflows/release.yml"
    step = workflow.read_text().split(f"      - name: {name}\n", 1)[1]
    step = step.split("\n      - ", 1)[0]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    script = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        script.append(line)
    return textwrap.dedent("\n".join(script)).replace(
        "${{ matrix.target }}", target
    ).replace("${{ github.ref_name }}", tag)


class ReleaseArchiveTests(unittest.TestCase):
    def test_tag_is_preserved_as_literal_archive_filename(self):
        windows = os.name == "nt"
        target = "x86_64-pc-windows-msvc" if windows else "x86_64-unknown-linux-gnu"
        binary = "ghidra-cli.exe" if windows else "ghidra-cli"
        extension = "zip" if windows else "tar.gz"
        step = "Create archive (Windows)" if windows else "Create archive (Unix)"
        shell = ["pwsh", "-NoProfile", "-Command"] if windows else ["bash", "-e", "-c"]
        for tag in ["v1.2.3-$(whoami)", "v1.2.3-quote's"]:
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                release = root / "target" / target / "release"
                release.mkdir(parents=True)
                (release / binary).write_bytes(b"release binary")
                result = subprocess.run(
                    [*shell, archive_script(step, target, tag)],
                    cwd=root,
                    env={**os.environ, "GITHUB_REF_NAME": tag},
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                archive = root / f"ghidra-cli-{tag}-{target}.{extension}"
                self.assertTrue(archive.is_file(), list(root.iterdir()))
                if windows:
                    with zipfile.ZipFile(archive) as output:
                        self.assertEqual(output.read(binary), b"release binary")
                else:
                    with tarfile.open(archive) as output:
                        self.assertEqual(output.extractfile(binary).read(), b"release binary")


if __name__ == "__main__":
    unittest.main()
