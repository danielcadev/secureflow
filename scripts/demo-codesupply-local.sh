#!/usr/bin/env bash
set -euo pipefail
umask 077

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="${workspace_root}/tests/fixtures/codesupply-ready"
osv="${workspace_root}/tests/fixtures/osv-source"

# A prebuilt binary avoids nested Cargo builds in integration tests and CI.
secureflow_bin=""
if [[ $# -eq 2 && $1 == --binary ]]; then
  secureflow_bin="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--binary /absolute/path/to/secureflow]" >&2
  exit 2
fi
for prerequisite in python3 mktemp sha256sum cat dirname; do
  command -v "${prerequisite}" >/dev/null || { echo "missing prerequisite: ${prerequisite}" >&2; exit 1; }
done
[[ -x /usr/bin/bwrap ]] || { echo "requires Linux /usr/bin/bwrap and enabled user namespaces" >&2; exit 1; }
for input in "${workspace_root}/scripts/verify-codesupply-demo.py" "${fixture}/engine.sh" "${fixture}/engine-report.json" \
  "${fixture}/target/Cargo.toml" "${fixture}/target/src/lib.rs" \
  "${osv}/LICENSE" "${osv}/advisories/GHSA-aaaa-bbbb-cccc.json" "${osv}/advisories/CVE-2026-0001.json"; do
  [[ -r "${input}" ]] || { echo "missing fixture: ${input}" >&2; exit 1; }
done
[[ -x "${fixture}/engine.sh" ]] || { echo "synthetic engine must be executable" >&2; exit 1; }
if [[ -z "${secureflow_bin}" ]]; then
  command -v cargo >/dev/null || { echo "missing prerequisite: cargo" >&2; exit 1; }
  # Never download dependencies during the demo; preparation is documented separately.
  cargo build --manifest-path "${workspace_root}/Cargo.toml" --target-dir "${workspace_root}/target" --offline --locked -q -p secureflow
  secureflow_bin="${workspace_root}/target/debug/secureflow"
fi
[[ -x "${secureflow_bin}" ]] || { echo "missing executable: ${secureflow_bin}" >&2; exit 1; }

demo_dir="$(mktemp -d /tmp/secureflow-codesupply.XXXXXX)"
trap 'echo "incomplete demo artifacts retained at: ${demo_dir}" >&2' ERR
cd "${demo_dir}"
# Shell redirections also refuse existing files; all outputs live in this new 0700 directory.
set -o noclobber
python3 - "${workspace_root}" <<'PY'
import hashlib, json, pathlib, zipfile
root = pathlib.Path(__import__('sys').argv[1])
inputs = sorted(p for directory in ('codesupply-ready', 'osv-source')
                for p in (root / 'tests/fixtures' / directory).rglob('*') if p.is_file())
hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
pathlib.Path('fixture-inputs.json').write_text(json.dumps(hashes, indent=2, sort_keys=True) + '\n')
# Fixed entry metadata and uncompressed entries make ZIP bytes reproducible.
with zipfile.ZipFile('synthetic-osv.zip', 'x') as archive:
    for p in sorted((root / 'tests/fixtures/osv-source/advisories').glob('*.json')):
        info = zipfile.ZipInfo(p.name, date_time=(2026, 8, 23, 0, 0, 0))
        info.external_attr = 0o100600 << 16
        archive.writestr(info, p.read_bytes())
PY
"${secureflow_bin}" scan --binary "${fixture}/engine.sh" \
  --authorized --authorization-reviewer codesupply-demo-operator \
  --authorization-reference 'repository-contained synthetic fixture; tests/fixtures/codesupply-ready/README.md' \
  --target-revision-kind snapshot --target-revision codesupply-synthetic-v1 \
  --sandbox required --output engine-report.json --manifest-output run.json "${fixture}/target"
"${secureflow_bin}" validate-run run.json
"${secureflow_bin}" snapshot-prepare-osv --archive synthetic-osv.zip --output snapshot \
  --artifact-locator urn:secureflow:codesupply:synthetic-osv:v1 \
  --artifact-revision codesupply-synthetic-v1 --expected-ecosystem crates.io \
  --acquired-at 2026-08-23T00:00:00Z --github-license-evidence "${osv}/LICENSE"
"${secureflow_bin}" snapshot-validate snapshot/manifest.json --archive synthetic-osv.zip
"${secureflow_bin}" catalog-import-snapshot --database catalog.sqlite3 \
  --manifest snapshot/manifest.json --archive synthetic-osv.zip
"${secureflow_bin}" catalog-bundle-create --database catalog.sqlite3 --profile core \
  --output catalog.core.sqlite3.zst --manifest-output catalog.core.manifest.json
# Hash the separate manifest bytes locally; this is NOT publisher authentication.
manifest_sha256="$(sha256sum catalog.core.manifest.json)"
manifest_sha256="${manifest_sha256%% *}"
printf '%s\n' "${manifest_sha256}" > expected-manifest-sha256.txt
"${secureflow_bin}" catalog-bundle-verify --bundle catalog.core.sqlite3.zst \
  --manifest catalog.core.manifest.json --required-profile core \
  --expected-manifest-sha256 "${manifest_sha256}" > bundle-verification.json
"${secureflow_bin}" catalog-bundle-install --bundle catalog.core.sqlite3.zst \
  --manifest catalog.core.manifest.json --required-profile core \
  --expected-manifest-sha256 "${manifest_sha256}" --output installed.core.sqlite3
# Core projections intentionally omit snapshot history. Preserve the byte-exact
# installation, then restore provenance in a separate working copy using the
# validated snapshot; no snapshot ID is invented or copied into SQLite by hand.
python3 - <<'PY_COPY'
from pathlib import Path
with open('installed.sqlite3', 'xb') as output:
    output.write(Path('installed.core.sqlite3').read_bytes())
PY_COPY
"${secureflow_bin}" catalog-import-snapshot --database installed.sqlite3 \
  --manifest snapshot/manifest.json --archive synthetic-osv.zip
"${secureflow_bin}" catalog-check installed.sqlite3 > installed-check.json
finding_id="$(python3 -c 'import json; print(json.load(open("run.json"))["findings"][0]["finding_id"])')"
"${secureflow_bin}" correlate-package --manifest run.json --finding-id "${finding_id}" \
  --database installed.sqlite3 --ecosystem crates.io --package secureflow-fixture --version 1.0.0 \
  --output correlation.json
"${secureflow_bin}" correlation-validate correlation.json
"${secureflow_bin}" orchestrate-plan --manifest run.json --correlation correlation.json --output orchestration.json
"${secureflow_bin}" orchestration-validate orchestration.json
python3 "${workspace_root}/scripts/verify-codesupply-demo.py" "${workspace_root}" "${demo_dir}"
python3 - <<'PY'
import hashlib, pathlib
files = sorted(p for p in pathlib.Path('.').rglob('*') if p.is_file())
with open('SHA256SUMS', 'x') as output:
    for path in files:
        output.write(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.as_posix()}\n')
PY
sha256sum --check SHA256SUMS
cat SHA256SUMS
printf 'demo artifacts retained at: %s\n' "${demo_dir}"
printf 'No network request, active scan, exploit, AI transmission, or human decision was created.\n'
