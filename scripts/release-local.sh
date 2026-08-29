#!/usr/bin/env bash
set -euo pipefail

required_toolchain=1.92.0

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

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_output=$1
if [[ -e "$release_output" ]]; then
  echo "refusing to overwrite existing output directory: $release_output" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "release requires a clean Git worktree and index" >&2
  exit 1
fi

release_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" != "v${release_version}" ]]; then
  echo "release tag ${GITHUB_REF_NAME:-<missing>} does not match package version v${release_version}" >&2
  exit 1
fi
release_commit=$(git rev-parse --verify HEAD)
release_epoch=$(git show -s --format=%ct HEAD)
release_name="secureflow-${release_version}-${release_commit:0:12}"
release_parent=$(dirname "$release_output")
mkdir -p "$release_parent"
release_stage=$(mktemp -d "$release_parent/.secureflow-release.XXXXXX")
trap 'if [[ -n "${release_stage:-}" && -d "$release_stage" ]]; then find "$release_stage" -type f -delete; find "$release_stage" -depth -type d -empty -delete; fi' EXIT

python3 -m unittest discover -s scripts/tests -p 'test_*.py'
"${cargo_cmd[@]}" fmt --all -- --check
"${cargo_cmd[@]}" clippy --workspace --all-targets --locked -- -D warnings
"${cargo_cmd[@]}" test --workspace --locked
"${cargo_cmd[@]}" build --release --locked -p secureflow

mkdir -p "$release_stage/$release_name/bin" "$release_stage/$release_name/evidence"
install -m 0755 target/release/secureflow "$release_stage/$release_name/bin/secureflow"
cp -a README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md CITATION.cff LICENSE-MIT LICENSE-APACHE \
  THIRD_PARTY_NOTICES.md docs schemas "$release_stage/$release_name/"
python3 scripts/generate-sbom.py \
  --output "$release_stage/$release_name/evidence/sbom.cdx.json" \
  --attribution-output "$release_stage/$release_name/evidence/dependency-license-declarations.md"
git archive --format=tar --prefix="$release_name/source/" HEAD > "$release_stage/source.tar"
tar -xf "$release_stage/source.tar" -C "$release_stage"

python3 - "$release_stage/$release_name/evidence/build-provenance.json" "$release_commit" "$release_epoch" "$required_toolchain" <<'PY'
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
    "rustc": subprocess.check_output(["rustup", "run", toolchain, "rustc", "--version", "--verbose"], text=True),
    "cargo": subprocess.check_output(["rustup", "run", toolchain, "cargo", "--version", "--verbose"], text=True),
    "platform": platform.platform(),
    "network_used_by_secureflow": False,
}
pathlib.Path(output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
  cd "$release_stage/$release_name"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
mkdir "$release_output"
tar --sort=name --mtime="@$release_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$release_stage" -cf - "$release_name" | gzip -n > "$release_output/$release_name.tar.gz"
(
  cd "$release_output"
  sha256sum "$release_name.tar.gz" > "$release_name.tar.gz.sha256"
)
printf 'release bundle: %s\n' "$release_output/$release_name.tar.gz"
printf 'release checksum: %s\n' "$release_output/$release_name.tar.gz.sha256"
