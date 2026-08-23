# Reproducible local demo

## What it demonstrates

The demo connects five verticals without modifying the original repositories:

1. runs Secure Engine against its explicitly authorized local fixture;
2. validates, prioritizes, lists candidates, and exports a Markdown report;
3. prepares a redacted Luna request without transmitting it;
4. imports two synthetic OSV records, reconciles CVE/GHSA aliases, and queries
   the local SQLite catalog;
5. separately imports a synthetic Secure Skill example and a retained
   historical Secure Bench result.

It does not automate a human decision, call an API, execute an exploit, or
present the historical result as a current capability.

## Execution

From a local checkout:

```bash
cd /path/to/secureflow
bash scripts/demo-local.sh
```

The explicit dependencies can be overridden:

```bash
SECUREFLOW_ENGINE_BINARY=/path/to/secure \
SECUREFLOW_ENGINE_TARGET=/path/to/authorized-target \
SECUREFLOW_SKILL_ROOT=/path/to/secure-skill \
SECUREFLOW_BENCH_ROOT=/path/to/secure-bench \
bash scripts/demo-local.sh
```

The script uses `mktemp` and retains the artifacts in a new directory under
`/tmp/secureflow-demo.*`. It never overwrites inputs. The person running the
demo must be explicitly authorized to analyze the target.

## Evidence separation

- `run.json` and `engine-report.json` correspond to the real local scan.
- `report.md` is a readable view of the same run; it preserves candidates as
  candidates and omits human rationales by default.
- `ai-request.json` corresponds to the first candidate in that run, but records
  `transmitted=false`.
- `advisories.sqlite3` contains two synthetic source records joined into one
  canonical entity through a CVE/GHSA alias; it is not a real feed and does not
  validate findings.
- `contextual-review.json` uses a synthetic contract payload and the canonical
  fixture manifest. It is not presented as a review of the scanned target.
- `benchmark.json` summarizes an already-retained public historical result. It
  does not rerun Secure Bench or Secure Engine.

## Deliberately absent human step

The demo does not call `review-run` because it must not fabricate a human
identity or decision. After inspecting a finding, a person can run:

```bash
cargo run -p secureflow -- review-run \
  --manifest /tmp/secureflow-demo.XXXXXX/run.json \
  --finding-id sf_finding_<id> \
  --decision validated|rejected|abstained \
  --reviewer "Real name" \
  --rationale "Verifiable evidence" \
  --output /tmp/secureflow-demo.XXXXXX/run-reviewed.json
```

Only that derived manifest is eligible for `knowledge-import`.
