# npm CLI M0.3 evidence protocol

Status: **local observations recorded; historical baseline retained; no vulnerability, clean-target, performance, or superiority claim**.

## Purpose

This pilot preserves a bounded, reproducible lineage for npm CLI analysis. It binds the authorized detached checkout at `b888cc9a9ff34a8b023ff47b784692396635397b`, the historical compact Engine evidence, the fresh Engine observation, the three source-reviewed abstentions, and the resource budget fixed before the fresh execution.

The immutable historical baseline is [`npm-cli-m0.3-pilot-2026-08-30.json`](../evidence/npm-cli-m0.3-pilot-2026-08-30.json). The pre-merge fresh observation is [`npm-cli-m0.3-fresh-scan-2026-08-30.json`](../evidence/npm-cli-m0.3-fresh-scan-2026-08-30.json), and the current merged-main observation is [`npm-cli-m0.3-post-merge-scan-2026-08-30.json`](../evidence/npm-cli-m0.3-post-merge-scan-2026-08-30.json). The previous detailed source review remains in [`npm-cli-engine-triage-2026-08-29.json`](../evidence/npm-cli-engine-triage-2026-08-29.json). Each newer artifact supersedes its predecessor only for statements about the recorded Engine identity; none deletes, rewrites, or retroactively changes historical evidence.

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

## Post-merge Engine observation

Engine PR [#5](https://github.com/usesecure/secure-engine/pull/5) was merged as `ffc724d4b0aeb872542f5d683de15850ca0c6c38`. That commit and approved pre-merge evidence commit `adf92157366251538946d4707de643ba05700c05` share Git tree `fa829a635b976c42f5bfdd4995f71990304c013c`; hosted `main` CI [run 33335959253](https://github.com/usesecure/secure-engine/actions/runs/33335959253) passed. A clean Rust 1.92 release rebuild from the merged commit produced binary SHA-256 `9dc96a691e9379624cf1d109cab48fb2540e2b473a674534ef0b18cb2b667f2d`. Its different pre-merge binary hash is recorded without a bit-reproducibility claim.

The first post-merge scan still excluded all 69 `node_modules` entries through the automatic vendor-directory policy, but it omitted the two frozen explicit globs. It is retained as a configuration-mismatch event and excluded from the primary comparison. The second scan repeated the same frozen scanner inputs, including both explicit globs, and produced raw report SHA-256 `903922f52262799046bfbbab4dbf8de56cde4e3366efbd95113a18ee372bba1b`, report fingerprint `91b75fdacd4caecb2610d86afdcd855cc9dc5446060ec61aea9ae33fd3159a89`, 12.09-second wall time, and 737,408 KiB peak RSS. Stable normalization used jq 1.8.1 with exact command template `jq -S 'del(.scan.started_at,.scan.finished_at,.scan.duration_ms,.parsing.duration_ms,.analysis.duration_ms,.report_fingerprint)' INPUT`; stdout is jq pretty-printed UTF-8 JSON with sorted object keys, two-space indentation, LF line endings, and one trailing LF, without compact output. Both the pre-merge and scanner-input-matched post-merge normalized reports have SHA-256 `d4feba70755b2ddf280789f36721c51469947580db7329785df640acbd5a65e9`.

The exact accounting and all three abstention fingerprints are unchanged. Running two post-merge passes exceeds the frozen one-pass limit and is an explicit protocol deviation even though attempt 2 matches the frozen scanner inputs. This retry record prevents a performance comparison, and the zero-finding result remains neither a clean verdict nor a vulnerability finding.

## Completion gate

The pre-merge fresh pilot may be called recorded because the exact revision and Engine identity are present, that pre-merge execution stayed inside its frozen budget, raw evidence hashes were recorded, every lead has one mutually exclusive triage state, and all unresolved categories are named. The post-merge artifact is a separate lineage verification with one disclosed retry and an explicit one-pass protocol deviation; it does not satisfy the original resource lane and cannot support a performance comparison. Both states represent evidence completion, not security-audit completion. They must publish zero clean-repository, performance, product-superiority, or vulnerability claims without independent validation and the separate external-publication approval gate.
