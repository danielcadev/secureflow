#!/usr/bin/env bash
set -euo pipefail
umask 077

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
projects_root="$(cd "${workspace_root}/.." && pwd)"

bench_root="${SECUREFLOW_BENCH_ROOT:-${projects_root}/secure-bench}"
bench_binary="${SECUREFLOW_BENCH_BINARY:-${bench_root}/target/debug/secure-bench}"
engine_binary="${SECUREFLOW_ENGINE_BINARY:-${projects_root}/secure-engine/target/release/secure}"
suite="${SECUREFLOW_BENCH_SUITE:-${bench_root}/fixtures/corpus-v1.toml}"

for required in \
  "${bench_binary}" \
  "${engine_binary}" \
  "${suite}" \
  "${bench_root}/schemas/result-v2.schema.json" \
  "${bench_root}/LICENSE"
do
  if [[ ! -f "${required}" ]]; then
    echo "evaluation prerequisite missing or not a regular file: ${required}" >&2
    exit 1
  fi
done

evaluation_dir="$(mktemp -d /tmp/secureflow-eval.XXXXXX)"
live_run="${evaluation_dir}/live-run"
result="${evaluation_dir}/result.json"
envelope="${evaluation_dir}/secureflow-benchmark.json"
bench_revision="$(git -C "${bench_root}" rev-parse HEAD)"

(
  cd "${bench_root}"
  "${bench_binary}" corpus validate "${suite}"
)

"${bench_binary}" run "${suite}" \
  --tool secure-engine \
  --binary "${engine_binary}" \
  --repository-root "${bench_root}" \
  --output "${live_run}" \
  --run-id secureflow-local-development

"${bench_binary}" evaluate "${suite}" "${live_run}" --output "${result}"

cd "${workspace_root}"
cargo build -q -p secureflow
secureflow_binary="${workspace_root}/target/debug/secureflow"

"${secureflow_binary}" benchmark-import \
  --result "${result}" \
  --run-manifest "${live_run}/run.json" \
  --suite "${suite}" \
  --secure-bench-root "${bench_root}" \
  --secure-bench-revision "${bench_revision}" \
  --study-kind local-development-diagnostic \
  --output "${envelope}"

"${secureflow_binary}" benchmark-validate "${envelope}"
"${secureflow_binary}" benchmark-summary "${envelope}" --format text

echo "local development evaluation retained at: ${evaluation_dir}"
echo "14 synthetic cases were evaluated; no ranking or superiority claim is allowed"
echo "the runner clears its environment but this script does not claim kernel network/filesystem isolation"
