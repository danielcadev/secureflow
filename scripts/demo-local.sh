#!/usr/bin/env bash
set -euo pipefail
umask 077

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
projects_root="$(cd "${workspace_root}/.." && pwd)"

engine_binary="${SECUREFLOW_ENGINE_BINARY:-${projects_root}/secure-engine/target/release/secure}"
engine_target="${SECUREFLOW_ENGINE_TARGET:-${projects_root}/secure-engine/fixtures/phase3-rules}"
secure_skill_root="${SECUREFLOW_SKILL_ROOT:-${projects_root}/secure-skill}"
secure_bench_root="${SECUREFLOW_BENCH_ROOT:-${projects_root}/secure-bench}"

for required in \
  "${engine_binary}" \
  "${engine_target}" \
  "${secure_skill_root}/skills/secure/SKILL.md" \
  "${secure_bench_root}/baselines/phase-1-secure-engine-phase6/result.json" \
  "${workspace_root}/tests/fixtures/osv-source/LICENSE" \
  "${workspace_root}/tests/fixtures/osv-source/advisories/GHSA-aaaa-bbbb-cccc.json"
do
  if [[ ! -e "${required}" ]]; then
    echo "demo prerequisite missing: ${required}" >&2
    exit 1
  fi
done

demo_dir="$(mktemp -d /tmp/secureflow-demo.XXXXXX)"
secure_skill_revision="$(git -C "${secure_skill_root}" rev-parse HEAD)"
secure_bench_revision="$(git -C "${secure_bench_root}" rev-parse HEAD)"
engine_revision="$(git -C "${projects_root}/secure-engine" rev-parse HEAD)"

cd "${workspace_root}"
cargo build -q -p secureflow
secureflow_bin="${workspace_root}/target/debug/secureflow"

"${secureflow_bin}" scan \
  --binary "${engine_binary}" \
  --authorized \
  --authorization-reviewer "local-demo-operator" \
  --authorization-reference "Secure Engine bundled local fixture" \
  --target-revision-kind git \
  --target-revision "${engine_revision}" \
  --output "${demo_dir}/engine-report.json" \
  --manifest-output "${demo_dir}/run.json" \
  "${engine_target}"

"${secureflow_bin}" validate-run "${demo_dir}/run.json"
"${secureflow_bin}" list-findings "${demo_dir}/run.json" --format text
"${secureflow_bin}" export-report \
  --manifest "${demo_dir}/run.json" \
  --output "${demo_dir}/report.md"

first_finding_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["findings"][0]["finding_id"])' "${demo_dir}/run.json")"
"${secureflow_bin}" ai-prepare \
  --manifest "${demo_dir}/run.json" \
  --finding-id "${first_finding_id}" \
  --enable-ai \
  --consent-redacted-export \
  --output "${demo_dir}/ai-request.json"
"${secureflow_bin}" ai-validate-request "${demo_dir}/ai-request.json"

# This is a synthetic OSV fixture. It demonstrates local ingestion,
# provenance, exact alias reconciliation and query paths without downloading a
# third-party feed or treating an advisory as a validated finding.
"${secureflow_bin}" catalog-import-osv \
  --database "${demo_dir}/advisories.sqlite3" \
  --input "${workspace_root}/tests/fixtures/osv-source/advisories" \
  --source-name "secureflow-synthetic-osv-fixture" \
  --source-license-expression "CC-BY-4.0" \
  --source-license-evidence "${workspace_root}/tests/fixtures/osv-source/LICENSE" \
  --source-locator "urn:secureflow:synthetic-osv-fixture:v1"
"${secureflow_bin}" catalog-stats "${demo_dir}/advisories.sqlite3"
"${secureflow_bin}" catalog-check "${demo_dir}/advisories.sqlite3"
"${secureflow_bin}" catalog-lookup \
  --database "${demo_dir}/advisories.sqlite3" \
  "CVE-2026-0001" --format json

# This is a synthetic adapter-contract example. It is deliberately linked to
# the canonical fixture manifest rather than represented as a review of the
# engine target scanned above.
"${secureflow_bin}" secure-review-import \
  --review "${workspace_root}/tests/fixtures/minimal-secure-review.json" \
  --manifest "${workspace_root}/tests/fixtures/minimal-run.json" \
  --secure-skill-root "${secure_skill_root}" \
  --secure-skill-revision "${secure_skill_revision}" \
  --output "${demo_dir}/contextual-review.json"
"${secureflow_bin}" secure-review-validate "${demo_dir}/contextual-review.json"

# This imports committed historical evidence; it does not rerun a scanner.
"${secureflow_bin}" benchmark-import \
  --result "${secure_bench_root}/baselines/phase-1-secure-engine-phase6/result.json" \
  --run-manifest "${secure_bench_root}/baselines/phase-1-secure-engine-phase6/run.json" \
  --suite "${secure_bench_root}/fixtures/corpus-v1.toml" \
  --secure-bench-root "${secure_bench_root}" \
  --secure-bench-revision "${secure_bench_revision}" \
  --study-kind historical-public-diagnostic \
  --output "${demo_dir}/benchmark.json"
"${secureflow_bin}" benchmark-validate "${demo_dir}/benchmark.json"
"${secureflow_bin}" benchmark-summary "${demo_dir}/benchmark.json" --format text

echo "demo artifacts retained at: ${demo_dir}"
echo "no AI request was transmitted, no external advisory feed was downloaded, and no human finding decision was synthesized"
