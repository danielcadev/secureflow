# npm CLI M0.3 frozen pilot

Status: **frozen local baseline; no new scan and no external claim**.

## Purpose

This pilot preserves a bounded, reproducible starting point for the next npm CLI analysis. It binds the authorized detached checkout at `b888cc9a9ff34a8b023ff47b784692396635397b`, the historical compact Engine evidence, the three source-reviewed abstentions, and a resource budget before another execution occurs.

The tracked evidence is [`npm-cli-m0.3-pilot-2026-08-30.json`](../evidence/npm-cli-m0.3-pilot-2026-08-30.json). The previous detailed source review remains in [`npm-cli-engine-triage-2026-08-29.json`](../evidence/npm-cli-engine-triage-2026-08-29.json).

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

## Existing triage baseline

The retained compact run reported zero candidates and three deterministic Engine abstentions. Manual source review did not establish all five exploitability gates for any of them:

1. A test-only fixed process expectation lacked production reachability, lower-privilege input control, and reproducible impact.
2. The GitHub Actions OIDC URL and token came from the same CI authority; no separate lower-privilege destination controller or privilege gain was established.
3. The lifecycle-script exception was documented for owner-managed workspaces while `ignoreScripts` still dominated execution; no supported attacker-controlled workspace insertion path was established.

Their state is `abstained-after-source-review`, not `validated`, `rejected`, or `safe`. A future run must preserve the old artifact and record any changed disposition as a new review event with source evidence.

## Completion gate

The next pilot may be called complete only when the exact revision and Engine identity are recorded, execution stayed inside the frozen budget, raw evidence hashes validate, every lead has one mutually exclusive triage state, and all unresolved categories are named. It must publish zero clean-repository, product-superiority, or vulnerability claims without independent validation and the separate external-publication approval gate.
