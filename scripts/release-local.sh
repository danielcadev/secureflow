#!/usr/bin/env bash
set -euo pipefail

required_toolchain=1.92.0
export PYTHONDONTWRITEBYTECODE=1

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_worktree=$(pwd -P)
release_output=$(realpath -m -- "$1")
if [[ -e "$release_output" ]]; then
  echo "refusing to overwrite existing output directory: $release_output" >&2
  exit 1
fi

verify_args=(--repository "$release_worktree" --print-epoch)
if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  if [[ -z "${GITHUB_REF_NAME:-}" ]]; then
    echo "tag-mode release requires GITHUB_REF_NAME" >&2
    exit 1
  fi
  verify_args+=(--tag "$GITHUB_REF_NAME")
  if [[ -n "${GITHUB_SHA:-}" ]]; then
    verify_args+=(--event-revision "$GITHUB_SHA")
  fi
fi
release_identity=$(python3 scripts/verify_release_worktree.py "${verify_args[@]}")
read -r release_commit release_epoch extra_identity <<<"$release_identity"
if [[ ! "$release_commit" =~ ^[0-9a-f]{40}$ || ! "$release_epoch" =~ ^[0-9]+$ || -n "${extra_identity:-}" ]]; then
  echo "release worktree verifier returned malformed identity" >&2
  exit 1
fi

# `RUSTUP_TOOLCHAIN` has no effect for a distribution Cargo binary. A release
# therefore requires rustup and invokes the pinned toolchain explicitly.
if ! command -v rustup >/dev/null 2>&1; then
  echo "release requires rustup with toolchain ${required_toolchain}; refusing host Cargo" >&2
  exit 1
fi
if ! rustup run "$required_toolchain" rustc --version >/dev/null 2>&1; then
  echo "release requires installed Rust toolchain ${required_toolchain}" >&2
  exit 1
fi
cargo_cmd=(rustup run "$required_toolchain" cargo)
rustc_cmd=(rustup run "$required_toolchain" rustc)
actual_rustc=$("${rustc_cmd[@]}" --version | awk '{print $2}')
actual_cargo=$("${cargo_cmd[@]}" --version | awk '{print $2}')
if [[ "$actual_rustc" != "$required_toolchain" || "$actual_cargo" != "$required_toolchain" ]]; then
  echo "release toolchain mismatch: rustc=$actual_rustc cargo=$actual_cargo expected=$required_toolchain" >&2
  exit 1
fi

release_temp_parent=${TMPDIR:-/tmp}
if [[ ! -d "$release_temp_parent" || ! -w "$release_temp_parent" || ! -x "$release_temp_parent" ]]; then
  echo "release temporary directory must be an accessible writable directory: $release_temp_parent" >&2
  exit 1
fi
release_temp_parent=$(realpath -e -- "$release_temp_parent")
release_stage=$(mktemp -d "$release_temp_parent/secureflow-release-stage.XXXXXX")
trap 'if [[ -n "${release_stage:-}" && -d "$release_stage" ]]; then chmod -R u+w "$release_stage" 2>/dev/null || true; find "$release_stage" -depth -delete 2>/dev/null || true; fi' EXIT
gate_source="$release_stage/gate-source"
python3 scripts/materialize_exact_tree.py \
  --repository "$release_worktree" \
  --revision "$release_commit" \
  --destination "$gate_source"
find "$gate_source" -type d -exec chmod a-w {} +
find "$gate_source" -type f -exec chmod a-w {} +

release_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$gate_source/Cargo.toml" | head -n 1)
if [[ -z "$release_version" ]]; then
  echo "Cargo.toml does not declare the release package version" >&2
  exit 1
fi
if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" != "v${release_version}" ]]; then
  echo "release tag ${GITHUB_REF_NAME:-<missing>} does not match package version v${release_version}" >&2
  exit 1
fi

notes_file=
(
  cd "$gate_source"
  python3 scripts/lint_release_notes.py docs/releases
  if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
    citation_version=$(sed -n 's/^version: "\([^"]*\)"/\1/p' CITATION.cff | head -n 1)
    if [[ "$citation_version" != "$release_version" ]]; then
      echo "CITATION.cff version ${citation_version:-<missing>} does not match package version ${release_version}" >&2
      exit 1
    fi
    if grep -Fq "## ${release_version} — Unreleased" CHANGELOG.md; then
      echo "CHANGELOG still marks ${release_version} as Unreleased" >&2
      exit 1
    fi
    selected_notes="docs/releases/${GITHUB_REF_NAME}.md"
    if [[ ! -s "$selected_notes" ]]; then
      echo "missing tracked release notes: $selected_notes" >&2
      exit 1
    fi
    python3 scripts/lint_release_notes.py --require-final "$selected_notes"
  fi
)
if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  notes_file="docs/releases/${GITHUB_REF_NAME}.md"
fi

release_name="secureflow-${release_version}-${release_commit:0:12}"
source_name="${release_name}-source"
export CARGO_TARGET_DIR="$release_stage/cargo-target"
export SOURCE_DATE_EPOCH="$release_epoch"

(
  cd "$gate_source"
  python3 -m unittest discover -s scripts/tests -p 'test_*.py'
  "${cargo_cmd[@]}" fmt --all -- --check
  "${cargo_cmd[@]}" clippy --workspace --all-targets --locked -- -D warnings
  "${cargo_cmd[@]}" test --workspace --locked
  "${cargo_cmd[@]}" build --release --locked -p secureflow
  "${cargo_cmd[@]}" fetch --locked
)

packaging_source="$release_stage/packaging-source"
python3 "$gate_source/scripts/materialize_exact_tree.py" \
  --repository "$release_worktree" \
  --revision "$release_commit" \
  --destination "$packaging_source"
if ! diff --no-dereference --brief --recursive "$gate_source" "$packaging_source"; then
  echo "exact gate source changed while release checks were running" >&2
  exit 1
fi
find "$packaging_source" -type d -exec chmod a-w {} +
find "$packaging_source" -type f -exec chmod a-w {} +

post_verify_args=(
  --repository "$release_worktree"
  --expected-revision "$release_commit"
)
if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  post_verify_args+=(--tag "$GITHUB_REF_NAME")
  if [[ -n "${GITHUB_SHA:-}" ]]; then
    post_verify_args+=(--event-revision "$GITHUB_SHA")
  fi
fi
python3 "$packaging_source/scripts/verify_release_worktree.py" "${post_verify_args[@]}" >/dev/null

bundle_root="$release_stage/$release_name"
mkdir -p "$bundle_root/bin" "$bundle_root/evidence"
install -m 0755 "$CARGO_TARGET_DIR/release/secureflow" "$bundle_root/bin/secureflow"

(
  cd "$packaging_source"
  python3 scripts/generate-sbom.py \
    --output "$bundle_root/evidence/sbom.cdx.json" \
    --attribution-output "$bundle_root/evidence/dependency-license-declarations.md"
)

python3 "$packaging_source/scripts/materialize_exact_tree.py" \
  --repository "$release_worktree" \
  --revision "$release_commit" \
  --destination "$bundle_root/source"
cp -a \
  "$bundle_root/source/README.md" \
  "$bundle_root/source/CHANGELOG.md" \
  "$bundle_root/source/SECURITY.md" \
  "$bundle_root/source/CONTRIBUTING.md" \
  "$bundle_root/source/CITATION.cff" \
  "$bundle_root/source/LICENSE-MIT" \
  "$bundle_root/source/LICENSE-APACHE" \
  "$bundle_root/source/THIRD_PARTY_NOTICES.md" \
  "$bundle_root/source/docs" \
  "$bundle_root/source/schemas" \
  "$bundle_root/"

source_archive="$release_stage/$source_name.tar.gz"
source_archive_args=(
  --repository "$release_worktree"
  --revision "$release_commit"
  --prefix "$source_name"
  --output "$source_archive"
  --require-path Cargo.toml
  --require-path Cargo.lock
  --require-path README.md
  --require-path LICENSE-MIT
  --require-path LICENSE-APACHE
  --require-path CHANGELOG.md
  --require-path SECURITY.md
  --require-path CITATION.cff
)
if [[ -n "$notes_file" ]]; then
  source_archive_args+=(--require-path "$notes_file")
fi
python3 "$packaging_source/scripts/create_source_archive.py" "${source_archive_args[@]}"

python3 - "$bundle_root/evidence/build-provenance.json" "$release_commit" "$release_epoch" "$required_toolchain" <<'PY'
import json
import pathlib
import platform
import subprocess
import sys

output, commit, epoch, toolchain = sys.argv[1:]
data = {
    "contract_version": "secureflow-build-provenance-v1",
    "git_commit": commit,
    "source_date_epoch": int(epoch),
    "rustc": subprocess.check_output(
        ["rustup", "run", toolchain, "rustc", "--version", "--verbose"],
        text=True,
    ),
    "cargo": subprocess.check_output(
        ["rustup", "run", toolchain, "cargo", "--version", "--verbose"],
        text=True,
    ),
    "platform": platform.platform(),
    "network_used_by_secureflow": False,
}
pathlib.Path(output).write_text(
    json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
  cd "$bundle_root"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
bundle_archive="$release_stage/$release_name.tar.gz"
tar --sort=name --mtime="@$release_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$release_stage" -cf - "$release_name" | gzip -n > "$bundle_archive"
(
  cd "$release_stage"
  sha256sum "$release_name.tar.gz" > "$release_name.tar.gz.sha256"
  sha256sum "$source_name.tar.gz" > "$source_name.tar.gz.sha256"
)

# Repeat the exact identity and tracked-state gate after all archive bytes exist
# and immediately before exposing output files to the caller.
python3 "$packaging_source/scripts/verify_release_worktree.py" "${post_verify_args[@]}" >/dev/null

release_parent=$(dirname -- "$release_output")
mkdir -p "$release_parent"
if ! mkdir "$release_output"; then
  echo "refusing to overwrite output directory created during release: $release_output" >&2
  exit 1
fi
install -m 0644 \
  "$bundle_archive" \
  "$release_stage/$release_name.tar.gz.sha256" \
  "$source_archive" \
  "$release_stage/$source_name.tar.gz.sha256" \
  "$release_output/"

printf 'release bundle: %s\n' "$release_output/$release_name.tar.gz"
printf 'release checksum: %s\n' "$release_output/$release_name.tar.gz.sha256"
printf 'source archive: %s\n' "$release_output/$source_name.tar.gz"
printf 'source checksum: %s\n' "$release_output/$source_name.tar.gz.sha256"
