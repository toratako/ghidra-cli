# Verify release downloads

The release workflow creates GitHub Artifact Attestations for the final Linux
and macOS `.tar.gz` archives, the Windows `.zip` archive, and each `*-skill.zip`.
Verify the downloaded archive **before** extracting, running, or installing it.
The attestation covers the archive bytes, not an extracted executable or the ZIP
wrapper used internally by GitHub Actions to transfer build artifacts.

Use a current [GitHub CLI](https://cli.github.com/) with `gh attestation verify`
and the options below. Authenticate with `gh auth login` if requested. The CLI
retrieves attestations from GitHub; no project-specific GPG key is needed.
Attestations are available only for releases built after this workflow was
introduced. Older releases and GitHub's automatic **Source code** archives do
not have these build attestations.

## Download and verify

Choose a release tag containing this workflow from the
[releases page](https://github.com/toratako/ghidra-cli/releases), and replace
`vX.Y.Z` below. This Bash example downloads and verifies the Linux binary archive
and the skill ZIP:

```bash
tag='vX.Y.Z'
binary="ghidra-cli-${tag}-x86_64-unknown-linux-gnu.tar.gz"
skill="ghidra-cli-${tag}-skill.zip"

gh release download "$tag" --repo toratako/ghidra-cli \
  --pattern "$binary" --pattern "$skill" || exit 1

for archive in "$binary" "$skill"; do
  gh attestation verify "$archive" \
    --repo toratako/ghidra-cli \
    --signer-workflow toratako/ghidra-cli/.github/workflows/release.yml \
    --source-ref "refs/tags/$tag" \
    --deny-self-hosted-runners || exit 1
done
```

For macOS, use `x86_64-apple-darwin.tar.gz` (Intel) or
`aarch64-apple-darwin.tar.gz` (Apple Silicon) in the binary filename. On Windows,
the equivalent PowerShell commands are:

```powershell
$tag = 'vX.Y.Z'
$binary = "ghidra-cli-${tag}-x86_64-pc-windows-msvc.zip"
$skill = "ghidra-cli-${tag}-skill.zip"

gh release download $tag --repo toratako/ghidra-cli --pattern $binary --pattern $skill
if ($LASTEXITCODE -ne 0) { throw 'Release download failed' }

foreach ($archive in @($binary, $skill)) {
  gh attestation verify $archive `
    --repo toratako/ghidra-cli `
    --signer-workflow toratako/ghidra-cli/.github/workflows/release.yml `
    --source-ref "refs/tags/$tag" `
    --deny-self-hosted-runners
  if ($LASTEXITCODE -ne 0) { throw "Attestation verification failed: $archive" }
}
```

A successful check validates the archive digest and the signing workflow's
repository, workflow path, source tag ref, and GitHub-hosted runner identity.
The default predicate is SLSA build provenance v1. To pin the source commit as
well, add `--source-digest FULL_COMMIT_SHA` using a commit SHA you trust; a tag
name alone does not pin a commit. Add `--format json` to inspect the verified
certificate and provenance. See the [CLI verification reference](https://cli.github.com/manual/gh_attestation_verify).

If verification fails or no attestation is found, do not use the archive. Check
the selected tag, exact asset filename, and CLI version; for an attested release,
report the failure to the maintainers rather than bypassing verification.

## What this establishes

GitHub Actions OIDC and short-lived Sigstore certificates bind the archive's
digest to the release workflow identity. Each binary archive is attested in its
build job; skills are attested after packaging in the release job. A failed
attestation prevents the GitHub release from being created by that workflow run.
Only those two jobs receive `id-token: write` and `attestations: write`.

Provenance lets you check where an artifact came from. It does not establish that
the code is free of vulnerabilities or malicious behavior, or by itself establish
SLSA Build Level 3. See [GitHub's artifact attestation documentation](https://docs.github.com/en/actions/how-tos/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).
