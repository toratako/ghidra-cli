"""Exercise archive integrity and metadata on each native CI platform."""

from datetime import datetime
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from install import extract_archive


class ExtractionTests(unittest.TestCase):
    def test_preserves_language_freshness_and_launcher_permissions(self):
        with tempfile.TemporaryDirectory(prefix="Ghidra CI's ") as directory:
            root = Path(directory)
            archive = root / "distribution.zip"
            destination = root / "extracted files"
            destination.mkdir()
            source_time = (2026, 1, 2, 3, 4, 0)
            compiled_time = (2026, 1, 2, 3, 5, 0)
            with zipfile.ZipFile(archive, "w") as output:
                # Extraction order must not make unchanged sources newer.
                for name, modified, mode in [
                    ("languages/test.sla", compiled_time, 0o644),
                    ("languages/test.slaspec", source_time, 0o644),
                    ("support/analyzeHeadless", source_time, 0o755),
                ]:
                    info = zipfile.ZipInfo(f"ghidra/{name}", modified)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | mode) << 16
                    output.writestr(info, name.encode())

            extract_archive(archive, destination, hashlib.sha256(archive.read_bytes()).hexdigest())
            installed = destination / "ghidra"
            compiled = installed / "languages/test.sla"
            source = installed / "languages/test.slaspec"
            self.assertEqual(compiled.read_bytes(), b"languages/test.sla")
            self.assertEqual(compiled.stat().st_mtime, datetime(*compiled_time).timestamp())
            self.assertEqual(source.stat().st_mtime, datetime(*source_time).timestamp())
            self.assertGreater(compiled.stat().st_mtime, source.stat().st_mtime)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((installed / "support/analyzeHeadless").stat().st_mode), 0o755)

    def test_checksum_mismatch_does_not_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "distribution.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("ghidra/support/analyzeHeadless", b"launcher")
            destination = root / "extracted"
            destination.mkdir()
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                extract_archive(archive, destination, "0" * 64)
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
