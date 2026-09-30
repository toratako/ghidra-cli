# Release publication

Pushing a `v*` tag runs the release workflow. Tags containing `-` remain
prereleases. Both stable releases and prereleases follow the same order:

1. Complete the release's test/build gates and package the assets.
2. Refuse to modify an already-published release for the tag.
3. Create or reuse a draft, and upload all binary archives and skill ZIPs.
4. Check that the draft's uploaded assets exactly match the local filenames,
   sizes, and SHA-256 digests, with no missing, duplicate, or unexpected assets.
5. Publish that exact draft release ID. With release immutability enabled,
   publication locks the tag and assets.

The `release` job is serialized per tag without cancelling an upload in progress.
Do not manually edit or publish a draft while the workflow is using it.

## Recovering a failed run

If packaging, upload, or verification fails, publication is not attempted. A
draft may remain. Inspect the failure and rerun the failed job to reuse that
draft and replace incomplete uploads. Unexpected extra assets or duplicate
drafts need maintainer review before a retry; the workflow does not silently
delete them.

If publication succeeded but the runner lost its response, inspect the release
on GitHub first. A rerun refuses an already-published release rather than trying
to replace locked assets. Corrections to a published immutable release require
a new tag/release.

## Enabling immutable releases

Merging the workflow change does not enable the repository setting. After the
flow is reviewed, a repository administrator can enable **Settings → General →
Releases → Enable release immutability**. It applies to future releases only.
See [GitHub's setup instructions](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
and [immutable release behavior](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

The workflow uses its existing `contents: write` job permission and the runner's
GitHub CLI; no new repository setting, secret, or long-lived credential is needed.
Publishing from a draft uses the `release.published` event semantics, including
prereleases. Events generated with the workflow's `GITHUB_TOKEN` generally do not
trigger other workflows; do not rely on a downstream `release.prereleased` run.

## Checks

Run `python -m unittest discover -s .github/scripts -v` for the offline API/asset
guard tests, and actionlint for the workflow syntax. CI runs the offline tests
for changes to release workflows or helper scripts. These tests do not create a
GitHub release; end-to-end publication requires an authorized release tag.
