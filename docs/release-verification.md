# Release verification

SecureFlow releases publish two deliberately different archives for one exact Git commit:

- `secureflow-<version>-<commit>-source.tar.gz` contains the distribution paths emitted from the exact commit by an isolated `git archive`. Tracked `.gitattributes` remains authoritative, including `export-ignore`; worktree-only files, repository-local info attributes, global or system Git attributes and configuration, replacement refs, and ambient `tar.umask` do not influence it.
- `secureflow-<version>-<commit>.tar.gz` is the host-specific Linux bundle. Its tests, build, documentation, schemas, SBOM, and bundled source are produced from fresh raw materializations of the exact commit outside the original worktree. The raw materialization intentionally includes supported tracked paths that the distribution archive may omit through `export-ignore`.

Each archive has an adjacent `.sha256` file. The tag workflow creates a GitHub artifact attestation for each archive and retains exactly those four files for 30 days, but it has no publication permission. A separate manually dispatched workflow receives `actions: read`, `attestations: read`, and `contents: write`; it accepts only an explicit stable tag, build run ID, run attempt, artifact ID, and GitHub-reported artifact digest, then rebinds that complete approved identity to the exact commit, workflow, successful tag-triggered run, four files, adjacent checksums, both attestations, and staged draft uploads before publication. Release-note prose and list items must each occupy one physical Markdown source line; CI and the release script enforce that presentation rule with `scripts/lint_release_notes.py`. Every release-note file also declares exactly one hidden `secureflow-release-state` marker, and tag-mode packaging rejects any selected note that is not explicitly `final`.

The release script captures an exact 40-character commit only after verifying the index and tracked worktree against that commit. It performs tests and assembly in a temporary exact-tree materialization, copies package inputs only from a fresh exact-tree materialization, and repeats the identity and tracked-state gate both immediately before packaging and immediately before exposing output files. Ignored and untracked worktree files cannot enter either artifact; tracked mutations fail closed even when an index flag such as `assume-unchanged` would hide them from normal status output.

Local operators may set `TMPDIR` to an existing writable directory with sufficient build space. The script creates a private uniquely named staging directory there and removes it on success or failure; no partial release output is exposed before all gates and archive checks complete.

## Review a tagged build before publication

Creating the approved tag starts construction and attestation only. After the tag workflow succeeds, record the complete build identity and download the exact retained artifact into a new directory. The following procedure rejects paginated or ambiguous artifact metadata, binds the artifact to the approved attempt, verifies the downloaded artifact ZIP against GitHub's SHA-256, and then verifies both adjacent checksums:

```bash
release_tag=v0.3.0
build_run_id=<approved-successful-release-run-id>
review_root="$(mktemp -d)"
review_dir="$review_root/assets"
run_json="$review_root/run.json"
artifacts_json="$review_root/artifacts.json"
mkdir "$review_dir"
gh api \
  --header "Accept: application/vnd.github+json" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  "repos/danielcadev/secureflow/actions/runs/$build_run_id" \
  > "$run_json"
gh api \
  --header "Accept: application/vnd.github+json" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  "repos/danielcadev/secureflow/actions/runs/$build_run_id/artifacts?per_page=100" \
  > "$artifacts_json"
jq -e '.total_count == (.artifacts | length)' "$artifacts_json" >/dev/null
release_commit="$(jq -er '.head_sha | select(type == "string" and test("^[0-9a-f]{40}$"))' "$run_json")"
build_run_attempt="$(jq -er '.run_attempt | select(type == "number" and . >= 1) | tostring' "$run_json")"
artifact_name="secureflow-release-assets-${build_run_id}-${build_run_attempt}-${release_commit}"
artifact_count="$(jq -er --arg name "$artifact_name" '[.artifacts[] | select(.name == $name and .expired == false)] | length' "$artifacts_json")"
test "$artifact_count" = 1
artifact_id="$(jq -er --arg name "$artifact_name" '.artifacts[] | select(.name == $name and .expired == false) | .id | select(type == "number" and . >= 1) | tostring' "$artifacts_json")"
artifact_digest="$(jq -er --arg name "$artifact_name" '.artifacts[] | select(.name == $name and .expired == false) | .digest | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))' "$artifacts_json")"
jq -e --arg tag "$release_tag" --arg commit "$release_commit" --argjson run_id "$build_run_id" '.id == $run_id and .name == "release" and .path == ".github/workflows/release.yml" and .event == "push" and .status == "completed" and .conclusion == "success" and .head_branch == $tag and .head_sha == $commit' "$run_json" >/dev/null
jq -e --arg name "$artifact_name" --arg tag "$release_tag" --arg commit "$release_commit" --argjson run_id "$build_run_id" '[.artifacts[] | select(.name == $name and .expired == false)][0] | .workflow_run.id == $run_id and .workflow_run.head_branch == $tag and .workflow_run.head_sha == $commit' "$artifacts_json" >/dev/null
gh run view "$build_run_id" \
  --repo danielcadev/secureflow \
  --json attempt,name,event,headBranch,headSha,status,conclusion,url
artifact_zip="$review_root/artifact.zip"
gh api "repos/danielcadev/secureflow/actions/artifacts/$artifact_id/zip" > "$artifact_zip"
test "sha256:$(sha256sum "$artifact_zip" | cut -d ' ' -f 1)" = "$artifact_digest"
unzip -q "$artifact_zip" -d "$review_dir"
release_version="${release_tag#v}"
release_name="secureflow-${release_version}-${release_commit:0:12}"
for asset in "$release_name.tar.gz" "$release_name.tar.gz.sha256" "$release_name-source.tar.gz" "$release_name-source.tar.gz.sha256"; do
  test -f "$review_dir/$asset" && test ! -L "$review_dir/$asset"
done
test "$(find "$review_dir" -mindepth 1 -maxdepth 1 | wc -l)" = 4
(cd "$review_dir" && sha256sum --check --strict ./*.sha256)
```

Verify both GitHub/Sigstore attestations against the exact tag workflow and expected release commit before requesting publication approval:

```bash
for archive in "$review_dir"/*.tar.gz; do
  gh attestation verify "$archive" \
    --repo danielcadev/secureflow \
    --signer-workflow danielcadev/secureflow/.github/workflows/release.yml \
    --source-ref "refs/tags/$release_tag" \
    --source-digest "$release_commit" \
    --deny-self-hosted-runners
done
```

Only after a human has reviewed the exact tag target, build run ID, run attempt, artifact ID and digest, four files, checksums, SBOM, license declarations, attestations, and final release text may publication be dispatched from the default branch:

```bash
gh workflow run publish-release.yml \
  --repo danielcadev/secureflow \
  --ref main \
  -f tag="$release_tag" \
  -f build_run_id="$build_run_id" \
  -f build_run_attempt="$build_run_attempt" \
  -f artifact_id="$artifact_id" \
  -f artifact_digest="$artifact_digest"
```

Any rerun increments the attempt and creates a different artifact identity. A changed attempt, artifact ID, or artifact digest requires a fresh download, verification, and human approval; the publisher never substitutes the latest attempt or selects an artifact by name. The publisher refuses an existing release, materializes the approved release notes from the exact regular Git blob, creates a private draft with four explicit files, compares its title, body, prerelease state, uploaded sizes, and SHA-256 digests with the verified local evidence, refreshes the remote tag and build metadata again, and only then publishes the draft. A failure after draft creation intentionally leaves a non-public draft for human inspection instead of exposing a partial release.

## Verify a published release

Set the exact release tag, download only the workflow-produced assets into a new directory, and verify both adjacent checksums:

```bash
release_tag=v0.3.0
release_dir="$(mktemp -d)"
gh release download "$release_tag" \
  --repo danielcadev/secureflow \
  --pattern 'secureflow-*.tar.gz' \
  --pattern 'secureflow-*.tar.gz.sha256' \
  --dir "$release_dir"
(cd "$release_dir" && sha256sum --check ./*.sha256)
```

Then verify the Sigstore-backed GitHub provenance for each archive. Pinning the repository, signer workflow, source tag, and GitHub-hosted runner policy is stronger than checking the repository alone:

```bash
for archive in "$release_dir"/*.tar.gz; do
  gh attestation verify "$archive" \
    --repo danielcadev/secureflow \
    --signer-workflow danielcadev/secureflow/.github/workflows/release.yml \
    --source-ref "refs/tags/$release_tag" \
    --deny-self-hosted-runners
done
```

For a fixed release, add `--source-digest <full-release-commit-sha>` to bind verification to the expected commit independently of the tag name. `gh attestation verify` checks SLSA provenance by default. A successful verification binds the downloaded bytes to the identified GitHub Actions workflow and source revision; it does not prove that the source is safe, that dependencies are trustworthy, or that the workflow itself is free of defects.

Inspect archive paths before extraction and extract into a new directory:

```bash
tar -tzf "$release_dir"/secureflow-*-source.tar.gz
extract_dir="$(mktemp -d)"
tar -xzf "$release_dir"/secureflow-*-source.tar.gz -C "$extract_dir"
```

## Reproduce the source-only archive locally

Use the script from the detached release commit, an exact full commit SHA, the published filename without `.tar.gz` as the prefix, and a new output path:

```bash
git clone https://github.com/danielcadev/secureflow.git secureflow-verify
cd secureflow-verify
git switch --detach "$release_tag"
release_commit="$(git rev-parse --verify HEAD)"
release_version="${release_tag#v}"
source_name="secureflow-${release_version}-${release_commit:0:12}-source"
mkdir local-source
python3 scripts/create_source_archive.py \
  --repository . \
  --revision "$release_commit" \
  --prefix "$source_name" \
  --output "local-source/$source_name.tar.gz"
cmp --silent \
  "local-source/$source_name.tar.gz" \
  "$release_dir/$source_name.tar.gz"
```

The helper refuses symbolic revisions, unsafe prefixes, non-root repository paths, pre-existing outputs, tracked symlinks, and gitlinks. It preserves tracked `.gitattributes` while isolating repository-local info attributes, global and system Git configuration and attributes, replacement refs, caller `PATH`, and ambient archive umask settings. Release packaging additionally fails when tracked export attributes omit a required manifest, lockfile, license, README, security policy, changelog, citation, or selected release note. Regression tests cover deterministic bytes, exact distribution member sets, executable modes, external-attribute isolation, replacement refs, and omission of untracked files and Git metadata.

## Honest reproducibility boundary

The source-only archive is designed to be deterministic from one exact Git commit. A successful `cmp` demonstrates equality for the two artifacts actually compared; it is not a universal guarantee across every Git, Python, filesystem, or future archive implementation.

The distribution archive and the raw exact-tree build input are deliberately different contracts: the former applies tracked export attributes, while the latter represents every supported tracked regular blob needed for tests, compilation, and package assembly. Both boundaries reject symlinks and gitlinks rather than relying on safe extraction behavior.

The Linux bundle is intentionally described as host-specific. Its provenance records the compiler, Cargo version, platform, commit, and source epoch, but compiled bytes may differ across runner images, linkers, system libraries, paths, or toolchain packaging. Checksums and attestations establish integrity and workflow provenance, not cross-host binary reproducibility. A cross-host claim requires independently rebuilding the same commit, comparing the resulting archive and nested binary, recording both environments, and publishing negative results when they differ.

The release tag itself may remain unsigned. The tag workflow proves that its checkout, local tag, and freshly fetched remote tag peel to the triggering `GITHUB_SHA`. The separate publisher requires the default-branch publication controls to be byte-identical to the copies in the tag, binds the selected successful tag-build run, exact attempt, artifact ID, and artifact digest to the same commit, refreshes the remote tag and GitHub metadata before each material gate, and repeats equality immediately before making the verified draft public. These controls detect deletion or movement before each gate but are not an atomic lock against a tag changing after the final fetch. Protect `v*` tags against update or deletion and keep published releases immutable. The GitHub artifact attestation signs an archive identity through the build workflow's short-lived OIDC/Sigstore identity; it binds bytes to the workflow source revision, does not retroactively sign the Git tag, and does not replace normal review of the tag target, workflow, dependencies, or claim boundaries.
