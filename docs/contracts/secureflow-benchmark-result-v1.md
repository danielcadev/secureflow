# `secureflow-benchmark-result-v1` contract

## Purpose

This contract summarizes a retained `secure-bench-result-v2` without running
the benchmark or any scanner. Secure Bench remains outside the path that
decides whether a production finding is valid.

The normative schema is
[`schemas/secureflow-benchmark-result-v1.schema.json`](../../schemas/secureflow-benchmark-result-v1.schema.json).

## Input verification

Import requires four explicit inputs:

1. the `secure-bench-result-v2` result;
2. the exact run manifest referenced by the result;
3. the exact suite referenced by the result;
4. the exact Secure Bench root and commit.

The adapter loads `schemas/result-v2.schema.json` from that root, validates the
result against the upstream schema, and checks that computed suite and run
SHA-256 values match `provenance.suite_fingerprint` and
`provenance.run_manifest_fingerprint`. It also retains hashes for the result,
schema, license, and evaluated binary. If the root contains `.git`, the
declared commit must match `HEAD`. In a snapshot without `.git`, the revision
is an operator declaration bound to content hashes.

Import runs neither Cargo, Secure Bench, Secure Engine, nor corpus code.

## Separate metrics

SecureFlow does not invent a composite score. It preserves Secure Bench's ten
quality ratios, counts, failures, and performance measurements. TP/FP/TN/FN
projection makes the distinct units explicit:

- TP: detected vulnerable expectations;
- FN: eligible vulnerable expectations without detection credit;
- FP: safe-control cases with at least one alert;
- TN: completed safe-control cases without an alert.

TP/FN use `vulnerable-expectation`; FP/TN use `safe-control-case`. They must not
be blindly summed into global accuracy. A crash, timeout, missing result,
unsupported case, or parse failure never becomes a clean control. On the
vulnerable side, an eligible case without detection receives no credit.

## Claim boundary

Every envelope fixes:

```json
{
  "claims": {
    "evaluation_only": true,
    "ranking_allowed": false,
    "superiority_claim_allowed": false,
    "production_readiness_claim_allowed": false
  }
}
```

`study_kind` is an operator-declared classification, not an adapter inference.
It must be checked against the original study methodology and limitations
before publishing results.

`local-development-diagnostic` identifies iterative runs visible to developers.
It is not a preregistration, holdout, or publishable superiority evidence.

## Verified historical baseline

On 2026-08-23, the public Secure Engine 0.1.0 Phase 1 baseline was imported
without rerunning it:

| Field | Retained value |
| --- | ---: |
| Suite | `phase-1-javascript-typescript` |
| Vulnerable cases / safe controls | 7 / 7 |
| TP expectations | 0 |
| FN expectations | 7 |
| FP safe controls | 3 |
| TN safe controls | 4 |
| Vulnerable recall | 0/7 (0.00%) |
| FP rate over attempted controls | 3/7 (42.85%) |
| Clean coverage of eligible controls | 4/7 (57.14%) |
| Operational failures | 0 |
| Total cold duration | 70 ms / 14 samples |

The result is synthetic, historical, and public. It does not measure the
current Secure Engine, support a general superiority or inferiority claim, or
establish production readiness. Its value is demonstrating neutral,
reproducible import even when the result is unfavorable.

Verification provenance:

- Secure Bench commit `485402e099f7e99577203e56604bbaadec0623fa`;
- result SHA-256 `b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099`;
- run SHA-256 `21d707e281109630aa2cc2172d8664dad3d55439811578aa65943cb00e2f6c41`;
- suite SHA-256 `57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b`;
- result schema SHA-256 `b16fc0667b870c2639e677d3de1daa847d41669ca4a05cef041b6cfe3a064eb7`.

## CLI

```bash
cargo run -p secureflow -- benchmark-import \
  --result /path/result.json \
  --run-manifest /path/run.json \
  --suite /path/suite.toml \
  --secure-bench-root /path/secure-bench \
  --secure-bench-revision <full-commit> \
  --study-kind historical-public-diagnostic \
  --output /path/benchmark-envelope.json

cargo run -p secureflow -- benchmark-validate \
  /path/benchmark-envelope.json

cargo run -p secureflow -- benchmark-summary \
  /path/benchmark-envelope.json --format text
```
