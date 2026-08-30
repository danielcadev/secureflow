# Release verification

Future SecureFlow releases publish two deliberately different archives for one exact Git commit:

- `secureflow-<version>-<commit>-source.tar.gz` contains the distribution paths emitted from the exact commit by an isolated `git archive`. Tracked `.gitattributes` remains authoritative, including `export-ignore`; worktree-only files, repository-local info attributes, global or system Git attributes and configuration, replacement refs, and ambient `tar.umask` do not influence it.
- `secureflow-<version>-<commit>.tar.gz` is the host-specific Linux bundle. Its tests, build, documentation, schemas, SBOM, and bundled source are produced from fresh raw materializations of the exact commit outside the original worktree. The raw materialization intentionally includes supported tracked paths that the distribution archive may omit through `export-ignore`.

Each archive has an adjacent `.sha256` file. The tag workflow also creates a GitHub artifact attestation for each archive before a separate, contents-write-only job publishes the same retained files. Release-note prose and list items must each occupy one physical Markdown source line; CI and the release script enforce that presentation rule with `scripts/lint_release_notes.py`. Every release-note file also declares exactly one hidden `secureflow-release-state` marker, and tag-mode packaging rejects any selected note that is not explicitly `final`.

The release script captures an exact 40-character commit only after verifying the index and tracked worktree against that commit. It performs tests and assembly in a temporary exact-tree materialization, copies package inputs only from a fresh exact-tree materialization, and repeats the identity and tracked-state gate both immediately before packaging and immediately before exposing output files. Ignored and untracked worktree files cannot enter either artifact; tracked mutations fail closed even when an index flag such as `assume-unchanged` would hide them from normal status output.

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

The release tag itself may remain unsigned. Both workflow jobs refresh the remote tag into a dedicated verification ref and prove that the checked-out commit, local tag, and freshly fetched remote tag peel to the triggering `GITHUB_SHA`; the publish command repeats the remote fetch and equality immediately before creating the release. This detects deletion or movement before each gate but is not an atomic lock against a tag changing after the final fetch. Protect `v*` tags against update or deletion and keep published releases immutable. The GitHub artifact attestation signs an archive identity through the workflow's short-lived OIDC/Sigstore identity; it binds bytes to the workflow source revision, does not retroactively sign the Git tag, and does not replace normal review of the tag target, workflow, and dependencies.
