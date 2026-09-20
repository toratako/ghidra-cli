"""Collect only this disposable Windows runner's new Ghidra log output."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys


def log_files():
    local = Path(os.environ["LOCALAPPDATA"])
    roaming = Path(os.environ["APPDATA"])
    return sorted(
        list((local / "ghidra-cli").glob("ghidra-cli.log.*"))
        + list((roaming / "ghidra").glob("ghidra_*/application.log*"))
    )


def languages():
    root = Path(os.environ["LOCALAPPDATA"]) / "ghidra-cli" / "ghidra"
    return {
        str(path.relative_to(root)): {
            "size": path.stat().st_size,
            "mtime_ns": path.stat().st_mtime_ns,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.glob("*/Ghidra/Processors/x86/data/languages/*"))
        if path.is_file() and path.suffix in (".sla", ".slaspec", ".sinc")
    }


def redact(text):
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN"):
        token = os.environ.get(key)
        if token:
            text = text.replace(token, "[REDACTED]")
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)",
                  "[REDACTED]", text)
    return re.sub(r"(?im)(authorization\s*[:=]\s*)([^\r\n]+)",
                  r"\1[REDACTED]", text)


def main():
    state = Path(os.environ["RUNNER_TEMP"]) / "ghidra-diagnostics-baseline.json"
    output = Path("diagnostics")
    output.mkdir(exist_ok=True)
    if sys.argv[1] == "begin":
        state.write_text(json.dumps({str(p): p.stat().st_size for p in log_files()}))
        (output / "languages-before.json").write_text(json.dumps(languages(), indent=2))
    elif sys.argv[1] == "finish":
        # Without a baseline, do not upload potentially historical cached logs.
        if not state.exists():
            print("No diagnostic baseline; not collecting logs")
            return
        baseline = json.loads(state.read_text())
        for index, path in enumerate(log_files()):
            offset = baseline.get(str(path), 0)
            # A truncated/rotated file contains new output from this run.
            if path.stat().st_size < offset:
                offset = 0
            with path.open("rb") as stream:
                stream.seek(offset)
                data = stream.read()
            if data:
                (output / f"{index}-{path.name}.txt").write_text(
                    redact(data.decode("utf-8", errors="replace")), encoding="utf-8"
                )
        (output / "languages-after.json").write_text(json.dumps(languages(), indent=2))
        print("Collected current-run logs and x86 language metadata")
    else:
        raise SystemExit("Expected begin or finish")


if __name__ == "__main__":
    main()
