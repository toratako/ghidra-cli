import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifacts = Path(self.temp.name)
        self.artifact = self.artifacts / "ghidra-cli-v1.2.3-skill.zip"
        self.artifact.write_bytes(b"release asset")
        self.asset = {
            "name": self.artifact.name,
            "size": self.artifact.stat().st_size,
            "digest": "sha256:" + hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
            "state": "uploaded",
        }
        self.draft = {"tag_name": "v1.2.3", "draft": True}
        self.published = {
            **self.draft,
            "draft": False,
            "html_url": "https://github.com/owner/repo/releases/tag/v1.2.3",
        }

    def test_absent_release_and_existing_draft_can_continue(self):
        for pages in [[], [[]], [[], [self.draft]]]:
            with self.subTest(pages=pages), patch.object(release, "api", return_value=pages) as api:
                release.check_unpublished("v1.2.3")
                api.assert_called_once_with("releases?per_page=100", paginate=True)

    def test_published_release_is_not_modified_on_rerun(self):
        with patch.object(release, "api", return_value=[[self.published]]) as api:
            with self.assertRaisesRegex(ValueError, "already published"):
                release.check_unpublished("v1.2.3")
            self.assertEqual(api.call_count, 1)

    def test_duplicate_drafts_stop(self):
        with patch.object(release, "api", return_value=[[self.draft], [self.draft]]):
            with self.assertRaisesRegex(ValueError, "Multiple drafts"):
                release.check_unpublished("v1.2.3")

    def test_other_tags_do_not_block(self):
        with patch.object(release, "api", return_value=[[self.published]]):
            release.check_unpublished("v1.2.4")

    def test_lookup_failure_is_not_treated_as_absence(self):
        error = subprocess.CalledProcessError(1, ["gh", "api"])
        with patch.object(release, "api", side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                release.check_unpublished("v1.2.3")

    def test_stable_and_prerelease_publish_after_asset_verification(self):
        for tag in ["v1.2.3", "v1.2.3-rc.1"]:
            with self.subTest(tag=tag), patch.object(
                release, "api", side_effect=[
                    {**self.draft, "tag_name": tag},
                    [[], [self.asset]],
                    {**self.published, "tag_name": tag},
                ]
            ) as api:
                release.publish("123", tag, self.artifacts)
                self.assertEqual(api.call_count, 3)
                self.assertEqual(api.call_args_list[0].args, ("releases/123",))
                self.assertEqual(api.call_args_list[1].args, ("releases/123/assets?per_page=100",))
                api.assert_called_with("releases/123", body={"draft": False})

    def test_invalid_release_id_never_calls_api(self):
        for release_id in ["", "wrong", "123/other"]:
            with self.subTest(release_id=release_id), patch.object(release, "api") as api:
                with self.assertRaisesRegex(ValueError, "release ID"):
                    release.publish(release_id, "v1.2.3", self.artifacts)
                api.assert_not_called()

    def test_wrong_or_published_release_is_not_patched(self):
        for wrong in [self.published, {**self.draft, "tag_name": "v9.9.9"}]:
            with self.subTest(release=wrong), patch.object(release, "api", return_value=wrong) as api:
                with self.assertRaisesRegex(ValueError, "expected draft"):
                    release.publish("123", "v1.2.3", self.artifacts)
                self.assertEqual(api.call_count, 1)

    def test_missing_extra_or_duplicate_remote_assets_block_publication(self):
        for assets in [[], [self.asset, {**self.asset, "name": "stale.zip"}], [self.asset, self.asset]]:
            with self.subTest(assets=assets), patch.object(
                release, "api", side_effect=[self.draft, [assets]]
            ) as api:
                with self.assertRaisesRegex(ValueError, "exactly match"):
                    release.publish("123", "v1.2.3", self.artifacts)
                self.assertEqual(api.call_count, 2)

    def test_failed_upload_size_or_digest_mismatch_blocks_publication(self):
        for change in [{"state": "starter"}, {"size": 1}, {"digest": "sha256:wrong"}, {"digest": None}]:
            with self.subTest(change=change), patch.object(
                release, "api", side_effect=[self.draft, [[{**self.asset, **change}]]]
            ) as api:
                with self.assertRaisesRegex(ValueError, "mismatched"):
                    release.publish("123", "v1.2.3", self.artifacts)
                self.assertEqual(api.call_count, 2)

    def test_empty_local_assets_block_publication(self):
        self.artifact.unlink()
        with patch.object(release, "api", return_value=self.draft) as api:
            with self.assertRaisesRegex(ValueError, "No local"):
                release.publish("123", "v1.2.3", self.artifacts)
            self.assertEqual(api.call_count, 1)

    def test_duplicate_local_names_block_publication(self):
        duplicate = self.artifacts / "other" / self.artifact.name
        duplicate.parent.mkdir()
        duplicate.write_bytes(b"different content")
        with patch.object(release, "api", return_value=self.draft) as api:
            with self.assertRaisesRegex(ValueError, "Duplicate local"):
                release.publish("123", "v1.2.3", self.artifacts)
            self.assertEqual(api.call_count, 1)

    def test_publication_failure_is_not_retried_blindly(self):
        error = subprocess.CalledProcessError(1, ["gh", "api"])
        with patch.object(release, "api", side_effect=[self.draft, [[self.asset]], error]) as api:
            with self.assertRaises(subprocess.CalledProcessError):
                release.publish("123", "v1.2.3", self.artifacts)
            self.assertEqual(api.call_count, 3)

    def test_publication_response_must_confirm_expected_release(self):
        for response in [self.draft, {**self.published, "tag_name": "v9.9.9"}]:
            with self.subTest(response=response), patch.object(
                release, "api", side_effect=[self.draft, [[self.asset]], response]
            ):
                with self.assertRaisesRegex(ValueError, "did not confirm"):
                    release.publish("123", "v1.2.3", self.artifacts)

    def test_cli_api_uses_pagination_and_explicit_patch_body(self):
        with patch.dict(release.os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), patch.object(
            release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "[]")
        ) as run:
            release.api("releases?per_page=100", paginate=True)
            self.assertEqual(run.call_args.args[0], [
                "gh", "api", "--method", "GET", "--paginate", "--slurp",
                "repos/owner/repo/releases?per_page=100",
            ])
            release.api("releases/123", body={"draft": False})
            self.assertEqual(run.call_args.args[0], [
                "gh", "api", "--method", "PATCH", "--input", "-", "repos/owner/repo/releases/123",
            ])
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"draft": False})


if __name__ == "__main__":
    unittest.main()
