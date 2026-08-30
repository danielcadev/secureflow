# npm CLI M0.3 evidence protocol

Status: **fresh local run recorded; historical baseline retained; no external claim**.

## Purpose

This pilot preserves a bounded, reproducible lineage for npm CLI analysis. It binds the authorized detached checkout at `b888cc9a9ff34a8b023ff47b784692396635397b`, the historical compact Engine evidence, the fresh Engine observation, the three source-reviewed abstentions, and the resource budget fixed before the fresh execution.

The immutable historical baseline is [`npm-cli-m0.3-pilot-2026-08-30.json`](../evidence/npm-cli-m0.3-pilot-2026-08-30.json). The current fresh observation is [`npm-cli-m0.3-fresh-scan-2026-08-30.json`](../evidence/npm-cli-m0.3-fresh-scan-2026-08-30.json). The previous detailed source review remains in [`npm-cli-engine-triage-2026-08-29.json`](../evidence/npm-cli-engine-triage-2026-08-29.json). The fresh artifact supersedes the baseline only for statements about the current Engine revision; it does not delete, rewrite, or retroactively change historical evidence.

## Frozen execution configuration

- Read only the exact detached Git revision; do not modify or execute npm CLI.
- Exclude `.git` and root or nested `node_modules` trees.
- Run at most one compact deterministic Engine pass with no optional AI command.
- Do not request a full graph. The previous full report was about 539 MB and did not change the compact candidate or abstention accounting.
- Stop after 300 seconds or 16 MiB of aggregate Engine output.
- Admit at most 20 leads to manual triage, with at most 45 active minutes per lead.
- Permit zero model calls and zero remote requests in this baseline lane.
- Retain every operational error and abstention separately; neither may become `no-finding`.

If the exact target revision, Engine binary hash, exclusions, limits, or authorization changes, create a new versioned pilot artifact instead of editing the result after observation.

## Historical triage baseline

The retained compact run reported zero findings and three deterministic Engine abstentions. Manual source review did not establish all five exploitability gates for any of them:

1. A test-only fixed process expectation lacked production reachability, lower-privilege input control, and reproducible impact.
2. The GitHub Actions OIDC URL and token came from the same CI authority; no separate lower-privilege destination controller or privilege gain was established.
3. The lifecycle-script exception was documented for owner-managed workspaces while `ignoreScripts` still dominated execution; no supported attacker-controlled workspace insertion path was established.

Their state is `abstained-after-source-review`, not `validated`, `rejected`, or `safe`. A future run must preserve the old artifact and record any changed disposition as a new review event with source evidence.

## Fresh Engine observation

The fresh compact run binds evaluated Engine source commit `c3aa5f7ee54139eac2e0398d6e4bc09969488cef`, evidence commit `adf92157366251538946d4707de643ba05700c05`, and binary SHA-256 `eb1bdc4c0b79855d85cc39feabba1ac79b43ba8bab3687e95103ef670cbb3913`. It scanned 4,847 of 4,859 candidate files, extracted 57,748 facts, and evaluated three candidate paths. It retained 14 facts and a seven-node/four-edge evidence graph, producing zero findings, three explicit abstentions, zero diagnostics, zero errors, and no truncation.

The three dispositions remain source-reviewed abstentions. SE1004 records `actor-authority-equivalence`; SE1013 records `independent-policy-bypass`; and the test-only SE1001 evidence records `test-context-reachability-unresolved`. No disposition is a validated vulnerability, rejected finding, false negative, or safe control. Zero findings is not a clean verdict.

The 13.03-second wall time and 737,204 KiB peak RSS are descriptive values from one local execution. Cache state, run order, and filesystem contention were not controlled, so these values cannot support a performance or superiority claim.

## Completion gate

The fresh pilot may be called recorded because the exact revision and Engine identity are present, execution stayed inside the frozen budget, raw evidence hashes were recorded, every lead has one mutually exclusive triage state, and all unresolved categories are named. This is evidence completion, not security-audit completion. It must publish zero clean-repository, performance, product-superiority, or vulnerability claims without independent validation and the separate external-publication approval gate.
