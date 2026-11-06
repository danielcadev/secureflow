# Automatic local review — development qualification

Date: 2026-09-25, America/Bogota (retained execution timestamps use UTC).
Status: implemented and locally verified; not a release or production-readiness
claim. The installed plugin, original repository, hosted site, and WebMCP
Challenge submission were not changed.

## Scope and source

- Independent checkout: `/home/danielcastrillon/Proyectos/secureflow-signal-calibration`.
- Development branch: `codex/automatic-review`, based on
  `1103d5a52f60c8f36575192d4b289311bccf4f3f`; no configured remotes.
- Implementation is retained as local working-tree changes. No commit, push,
  tag, deployment, global installation, issue, or pull request was created.
- Exact changed-file hashes and local gate outputs are retained under
  `/home/danielcastrillon/.cache/secureflow-auto-review.9E0mhC`.

The CLI adds `review-plan`, `review-execute`, and `review-status`. The default
MCP bridge retains five tools; a hash-pinned, operator-selected startup grant
adds three narrowly scoped automatic-review tools. The presentation launcher
verifies the completed bundle and passes its cases to the existing local session
loader. Codex can present the printed URL in its integrated right-hand panel;
no external browser or file picker is required.

The packaged SecureFlow skill was updated with this opt-in workflow and validated
using the skill-creator validator. It preserves required isolation, explicit
authority, bounded summaries, separate contextual investigation, and human-only
verdicts. The installed skill cache was not edited.

## Verification gates

Rust commands used the local Rust 1.92.0 toolchain and locked offline dependency
resolution. Tests that require Bubblewrap were mandatory, not skipped.

| Gate | Result |
| --- | --- |
| `SECUREFLOW_REQUIRE_SANDBOX_TESTS=1 cargo test --workspace --locked --offline` | 248 passed, 0 failed, 0 ignored before the final duplicate-case preflight guard. |
| `SECUREFLOW_REQUIRE_SANDBOX_TESTS=1 cargo test -p secureflow --locked --offline` | Final affected package: 59 passed, including all 16 automatic-review tests. |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Passed; affected CLI package rerun after the final guard, also passed. |
| `cargo fmt --all -- --check` | Passed on final Rust source. |
| `cargo build -p secureflow --locked --offline` | Passed on final Rust source. |
| `node --test scripts/tests/auto-review-launcher.test.mjs` | 3 passed, 0 skipped. |
| Existing release-workflow policy tests | 8 passed. |
| `WRANGLER_SEND_METRICS=false npm run build` in Review Room | Passed; generated locally from this checkout. |
| Packaged skill validation, Node/Bash syntax checks, `git diff --check` | Passed. |

The final preflight guard rejects identical component snapshots because the
existing Security Case contract assigns them the same identity and Review Room
rejects duplicate identities. It neither invents new identifiers nor silently
merges component coverage. Both plan preparation and manually altered-plan
loading have a regression assertion.

Other automatic-review coverage includes authorization, pinned plan/target/Engine
substitution, expiry, path and scope bounds, partial failure, malformed/truncated
reports, timeouts, symlink redirection, retained-artifact tampering, incomplete
runs, replay rejection, default MCP denial, opt-in MCP execution, source/sink
retrieval, operational tool errors, and live-target drift versus historical
verification. Structural plan and result schemas are exercised by real generated
test artifacts; semantic validation remains authoritative.

## Real-Engine synthetic walkthrough

Two source-only fixtures in `tests/fixtures/automatic-review` were scanned with
required Bubblewrap isolation and a full graph. Application code was never
executed. The Engine was the separately qualified RegExp calibration candidate
`9f873bf79e72c6780b33829eabc013961f0bb74d`, with binary SHA-256:

```text
9a04100438a9e619ddea1a04c6585fd49e90386b3687049c01faf21b412c943a
```

The pinned plan SHA-256 was:

```text
b9538c393fb25933a285df41327d8d1c48e6feb63cbabdecd275e6a47ba77740
```

The launcher executed the plan with `--no-serve`, retaining `demo-run/result.json`
and `demo-summary.json`. Result: two completed cases, one synthetic command-sink
candidate, zero Engine abstentions, zero staged recommendations, zero human
decisions, and zero AI calls. The local regex call in the mixed fixture did not
become a process-execution candidate. This is a fixture observation, not a
real-world vulnerability claim or universal false-positive guarantee.

The scan completed before the final duplicate-identity guard; the final binary
subsequently verified and reopened those exact retained artifacts, without
rescanning. Final MCP smoke checks exposed eight tools, verified the bundle, and
returned its one exact pending finding with bound evidence. The same unchanged
fixtures and plan remain suitable for reproducing a new run with a newly named
output directory and fresh authorization.

The rebuilt local panel served HTTP 200 and its token-bound session returned
exactly two cases and one candidate, with zero decisions. A wrong Origin was
rejected with 403 and an unknown token with 404. The native Codex panel-open
request was accepted as `queued`. No visual browser automation or pixel-level
UI verification is claimed. Session URLs/tokens are intentionally omitted here.

## Boundaries and remaining work

- The runner performs deterministic analysis and evidence preparation. It does
  not perform contextual AI research itself; the connected assistant can inspect
  scoped MCP work items and retain separate staged recommendations.
- It does not establish vulnerability novelty, exploitability, complete repository
  coverage, decompilation support, autonomous patching, or reduced model charges.
- No new provider transport, external-target traffic, crawling, exploitation,
  automatic verdict, or application execution was added.
- Required isolation is never downgraded. Failed or interrupted runs never become
  `ready-for-review`; partial evidence remains explicitly incomplete.
- Whole-run budgets are cooperative between phases, not hard deadlines for all
  filesystem operations. Trusted private ancestors, local account, clock, and
  immutable Engine are still assumptions; hashes are not signatures.
- Cross-platform qualification, current dependency-advisory audit, independent
  human security review, installer rollout, and release publication remain undone.
  Existing decisions and application changes were not touched.

See [Automatic local review](../automatic-review.md) for exact operator commands,
MCP configuration, artifact layout, scope limits, and failure behavior.
