"""Guard draft uploads and publish only a complete, byte-matching release."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def api(path, *, body=None, paginate=False):
    command = ["gh", "api", "--method", "PATCH" if body is not None else "GET"]
    if paginate:
        command += ["--paginate", "--slurp"]
    if body is not None:
        command += ["--input", "-"]
    command.append(f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}")
    result = subprocess.run(
        command,
        input=json.dumps(body) if body is not None else None,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def check_unpublished(tag):
    matches = [
        release
        for page in api("releases?per_page=100", paginate=True)
        for release in page
        if release["tag_name"] == tag
    ]
    if any(release["draft"] is not True for release in matches):
        raise ValueError(f"{tag} is already published; use a new tag, not a release rerun")
    if len(matches) > 1:
        raise ValueError(f"Multiple drafts exist for {tag}; resolve them before retrying")


def publish(release_id, tag, artifacts=Path("artifacts")):
    if not release_id.isdecimal():
        raise ValueError("Missing or invalid release ID from the draft upload step")
    path = f"releases/{release_id}"
    release = api(path)
    if release["tag_name"] != tag or release["draft"] is not True:
        raise ValueError("Refusing to publish: the release ID is not the expected draft")

    expected = {}
    for artifact in sorted(artifacts.rglob("*")):
        if artifact.is_file():
            if artifact.name in expected:
                raise ValueError(f"Duplicate local asset filename: {artifact.name}")
            with artifact.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            expected[artifact.name] = (artifact.stat().st_size, f"sha256:{digest}")
    if not expected:
        raise ValueError("No local release assets found")

    assets = [asset for page in api(f"{path}/assets?per_page=100", paginate=True) for asset in page]
    if len(assets) != len(expected) or {asset["name"] for asset in assets} != set(expected):
        raise ValueError("Uploaded release assets do not exactly match local assets")
    for asset in assets:
        actual = (asset["size"], asset.get("digest"))
        if asset["state"] != "uploaded" or actual != expected[asset["name"]]:
            raise ValueError(f"Incomplete or mismatched uploaded asset: {asset['name']}")

    published = api(path, body={"draft": False})
    if published["tag_name"] != tag or published["draft"] is not False:
        raise ValueError("GitHub did not confirm publication of the expected release")
    print(f"Published {published['html_url']}")


if __name__ == "__main__":
    try:
        mode = sys.argv[1] if len(sys.argv) == 2 else ""
        tag = os.environ["GITHUB_REF_NAME"]
        if mode == "check":
            check_unpublished(tag)
        elif mode == "publish":
            publish(os.environ["RELEASE_ID"], tag)
        else:
            raise ValueError("Usage: release.py check|publish")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
