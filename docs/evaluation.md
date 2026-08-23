# Local evaluation separated from production

## Purpose

`scripts/eval-local.sh` runs the synthetic Secure Bench Phase 1 corpus against
an explicitly selected Secure Engine binary. This path never participates in a
human decision about a production target and never injects benchmark answers
into the scanner.

## Execution

```bash
cd /path/to/secureflow
bash scripts/eval-local.sh
```

The script:

1. validates the corpus from the Secure Bench root;
2. separately copies and scans 7 vulnerable cases and 7 safe controls;
3. generates a raw bundle and a `secure-bench-result-v2` under `/tmp`;
4. imports it as a `local-development-diagnostic` with suite, run, schema,
   license, and commit hashes;
5. prints TP/FN per vulnerable expectation and FP/TN per safe control.

The original repositories are not modified. Binaries and paths can be
overridden with `SECUREFLOW_BENCH_ROOT`, `SECUREFLOW_BENCH_BINARY`,
`SECUREFLOW_ENGINE_BINARY`, and `SECUREFLOW_BENCH_SUITE`.

## Result observed on August 23, 2026

With Secure Engine reporting version 0.1.6 and the public 14-case suite:

| Metric | Result |
| --- | ---: |
| TP per vulnerable expectation | 0 |
| FN per vulnerable expectation | 7 |
| FP per safe control | 2 |
| TN per safe control | 5 |
| Vulnerable recall | 0/7 (0.00%) |
| FP rate on controls | 2/7 (28.57%) |
| Clean control rate | 5/7 (71.42%) |
| Operational failures | 0 |
| Normalized findings | 6 |
| Aggregate duration | 70 ms / 14 samples |

These numbers are a development diagnostic, not a publishable comparison. Six
normalized findings alongside zero matches means that the matcher credited no
expectation under its exact contract; it does not justify saying that the
scanner simply "detected nothing." Four vulnerable cases (`001`, `009`, `011`,
and `013`) produced findings. In `001`, `011`, and `013`, the source, sink, and
evidence path matched, but the exact Phase 1 matcher category/invariant strings
did not. In `009`, the source also differed. Vulnerable cases `003`, `005`, and
`007` produced no normalized findings. Controls `010` and `014` produced the
two false positives.

This may simultaneously reflect missing coverage and drift between the legacy
Phase 1 contract and the taxonomy reported by the current Engine. It must be
evaluated through a taxonomy-compatible prospective path without rewriting the
corpus answers after observing the results.

## Limitations

- The suite is small, synthetic, and known to the developers.
- There was no preregistration, new holdout, or blind human evaluation.
- The runner cleans the environment, but this script adds no kernel-level
  network or filesystem isolation.
- One execution cannot support uncertainty intervals or general claims.
- The results do not demonstrate superiority, production readiness, or
  performance on real repositories.

## Separate SecureFlow Web diagnostic

The Web vertical has a second, entirely local diagnostic. Its Next.js fixture
labels six routes and 24 assertions covering inventory, artifact correlation,
decoy exclusion, and safe semantics. The retained August 23, 2026 run produced:

| Measure | Result |
| --- | ---: |
| Expected/reported routes | 6 / 6 |
| Route precision/recall/F1 | 1.00 / 1.00 / 1.00 |
| Local candidates | 11 |
| Correlated/review/abstain | 4 / 5 / 2 |
| Development assertions | 24 / 24 |
| Network or target execution | no / no |

The result contracts set `independent_holdout=false`,
`superiority_claim_allowed=false`, and
`production_safety_claim_allowed=false`. The corpus was built alongside the
parser and may contain development leakage, so it is not combined with the
historical Secure Bench metrics or a future human study. Evidence:
[`web-route-lab-2026-08-23.json`](./evidence/web-route-lab-2026-08-23.json) and
[`web-development-corpus-2026-08-23.json`](./evidence/web-development-corpus-2026-08-23.json).

## Next prospective study

`benchmark-protocol-seal` validates and seals the
`secureflow-prospective-protocol-v1` contract before results are observed. It
requires at least 20 cases, 10 vulnerable cases and 10 controls, an unseen
holdout, hidden labels, SecureFlow and a human cohort, two adjudicators,
blinding, a leakage audit, time/cost accounting, abstentions, and publication
of negative results.

`tests/fixtures/prospective-protocol-draft.json` tests only the contract with
synthetic hashes. It is not a preregistration, contains no real corpus, and does
not yet authorize any claim of outperforming humans.

`benchmark-protocol-preflight` adds the real-study step: it recalculates the
hashes of the public corpus manifest, provenance, licenses, and environment
before sealing. It does not receive the ground truth. The cohort,
randomization, time capture, label opening, and adjudication remain pending.
See [`prospective-study-runbook.md`](./prospective-study-runbook.md).
