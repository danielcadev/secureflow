# Automatic local review

Implemented in the isolated automatic-review branch and prepared as local
candidate `1.1.0-rc.5`. Check `secureflow --version` and `secureflow review-plan
--help` on the host: older installations and published releases may not include
these commands. Local installation does not publish a release or deployment.
See the [local qualification record](evidence/automatic-review-local-readiness-2026-09-25.md)
for completed checks and explicitly unclaimed release gates.

## One platform, three modes

| Mode | Operator experience | Authority |
| --- | --- | --- |
| Manual | Inspect local cases in CLI or Review Room. | Explicit human decisions. |
| Assisted | An MCP client investigates evidence and stages recommendations. | Recommendations are not verdicts. |
| Automatic preparation | A pinned plan scans explicit components and produces verified cases, then loads the panel. | All candidates remain pending; no patches. |

This is the first unattended **analysis-to-review** vertical slice, not a new
decompiler, universal binary analyzer, zero-day oracle, or embedded AI service.
The connected assistant may perform contextual research through MCP; the local
runner explicitly reports `contextual_investigation: not-performed-by-runner`.
No model call or bulk invented recommendation is substituted for that research.

## Prepare once, execute once

Use the candidate CLI on `PATH`. Required analysis runtime is Linux with working
Bubblewrap user namespaces. Review Room also requires Node.js, npm, and an
already-built local application. No dependency download is attempted by the
runner. The operator selects a trusted Engine binary outside the target trees.

```sh
REVIEW_ROOT=$(mktemp -d /tmp/secureflow-auto-review.XXXXXX)
secureflow review-plan \
  --binary /absolute/path/to/secure \
  --target /absolute/path/to/authorized/component-a \
  --target /absolute/path/to/authorized/component-b \
  --authorized \
  --authorization-reviewer 'Named operator' \
  --authorization-reference 'Explicit local scope approval' \
  --timeout-seconds 120 --total-budget-seconds 600 \
  --expires-after-seconds 3600 \
  --output-directory "$REVIEW_ROOT/run" \
  --plan-output "$REVIEW_ROOT/plan.json"
```

The JSON response contains `plan_path` and `plan_sha256`. Keep that exact hash;
it pins the approved bytes, not merely a pathname. The plan records component
snapshot hashes, Engine hash, authorization, expiry, and budgets. It performs
no scan and cannot authorize new paths via later tool arguments.

To execute and present in one invocation, use the returned hash:

```sh
node plugins/secureflow/scripts/run-auto-review.mjs \
  --plan "$REVIEW_ROOT/plan.json" --plan-sha256 PRINTED_PLAN_SHA256 \
  --port 3351 --session-port 3352
```

A source-bound local installation can expose the same launcher as
`secureflow-review`; use `secureflow-review --help` to check availability. The
entry point still requires the matching trusted checkout, built Review Room
and its installed Node dependencies. It is not a standalone UI distribution.

The launcher keeps local servers running and prints a session-bearing loopback
URL. In Codex desktop, open that URL with `open_in_codex`, `placement: right`.
No external browser, extension file access, Computer Use, or file-picker upload
is required. Treat the session token as a short-lived local capability; do not
publish it or include it in public receipts. Other clients can open the same
loopback URL manually on the host machine.

Presentation has the existing limits of 32 MiB per case and 128 MiB for the
combined case set. These are checked by the loader before starting the UI. The
session must bind successfully within ten seconds before its URL is announced;
loader failure also stops the owned UI runtime. A presentation error leaves the
verified analysis bundle available for `--no-serve` or smaller manual case sets.

For headless use, run the CLI directly:

```sh
secureflow review-execute --plan "$REVIEW_ROOT/plan.json" \
  --plan-sha256 PRINTED_PLAN_SHA256
secureflow review-status --directory "$REVIEW_ROOT/run" \
  --plan-sha256 PRINTED_PLAN_SHA256
```

To reopen without scanning again, pass `--directory "$REVIEW_ROOT/run"` instead
of `--plan` to the launcher. `--no-serve` verifies/prints the bundle without
starting Review Room. The underlying manual `scan` and `case-create` commands
remain available and retain their previous interfaces.

## Opt-in MCP execution

Configure the client to start this exact command after scope approval:

```sh
secureflow mcp --review-plan /absolute/path/to/plan.json \
  --review-plan-sha256 PRINTED_PLAN_SHA256
```

The default `secureflow mcp` still has the existing five case tools and no scan
authority. The pinned process adds:

| Tool | Input | Result |
| --- | --- | --- |
| `run_authorized_review` | Empty object | Executes that plan once; returns verified component summaries. |
| `authorized_review_status` | Empty object | Verifies retained files and reports ready, failed, or incomplete state. |
| `investigate_review_candidate` | Component index and exact candidate ID | Returns bound source/sink locations, invariant, evidence path, and limitations. |

These calls cannot choose an executable, shell command, replacement target,
network mode, output path, or sandbox downgrade. Final human-decision tools and
patch execution are not exposed. Invalid arguments produce protocol errors;
execution failures use MCP tool results with `isError: true`.
Work-item investigation also requires a still-live grant and an unchanged target
snapshot. Historical bundle verification remains available after source changes
or grant expiration; it does not silently authorize analysis of the new revision.

Execution is synchronous. Configure the client's tool timeout above the chosen
whole-run budget plus local hashing/verification overhead, or run the headless
CLI and connect MCP afterward. A transport timeout is not evidence that a run
completed or stopped: inspect its status before doing anything else. Never
silently extend permission or relaunch the scanner to recover a lost response.

Summaries include at most five candidate previews and ten repeated-signal groups
per component, with totals exposed. Use the existing filtered/paginated
`list_candidates` for more. Individual work items are capped at 128 KiB. The
runner does not set the connected model's token budget or claim measured token
savings; the host controls its own model usage and privacy policy.

## Artifact and failure contract

Each new private run directory retains:

```text
plan.json
started.json
component-00/
  engine-report.json
  run-manifest.json
  security-case.json
component-01/...
result.json
```

Normative structural schemas are
[`secureflow-auto-review-plan-v1`](../schemas/secureflow-auto-review-plan-v1.schema.json)
and [`secureflow-auto-review-result-v1`](../schemas/secureflow-auto-review-result-v1.schema.json).
Structural validation alone is insufficient: execution checks current input
hashes, authorization lifetime, scope boundaries and freshness; `review-status`
verifies retained hashes and exact case/manifest/plan relationships.

- Plans allow 1–16 non-overlapping component directories, up to 24 hours of
  validity, and per-process/whole-run budgets of 1–3600 seconds. Whole-run timing
  is cooperative between phases; filesystem reads are not a hard real-time timer.
- Identical component snapshots share a Security Case identity and cannot be
  loaded together in Review Room. The plan rejects these duplicates before
  scanning; use separate plans instead of silently merging their coverage.
- Every component uses the required sandbox and full-graph import. The existing
  adapter may negotiate a full graph from compact output within its same budget;
  it never disables isolation or imports truncated evidence.
- Changed target/Engine bytes, redirected paths, invalid plans and existing
  output directories fail before scanning. Output and plan files must stay
  outside all target trees. No untracked application files are removed.
- A component failure stops the run. Earlier successful components remain
  inspectable, but the overall status is `failed`, not repository-wide success.
- Missing final receipts report `incomplete-or-running`. There is no automatic
  crash recovery, overwrite, retry, or resume into the same directory.
- `ready-for-review` means verified static artifacts are available. It does not
  mean contextual research or human review is complete, nor that zero candidates
  proves security. Existing human decisions are neither copied nor invented.

Hashes establish identity, not code safety or cryptographic authorship. A
trusted local account, private ancestor directories, a trustworthy clock, and
an immutable trusted Engine remain assumptions. The existing adapter's
pathname/time-of-check limitations are not removed by this orchestration.

## Verification

```sh
SECUREFLOW_REQUIRE_SANDBOX_TESTS=1 cargo test -p secureflow --locked --test auto_review
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
node --test scripts/tests/auto-review-launcher.test.mjs
```

Tests use synthetic Engine outputs, never real vulnerability claims. They cover
explicit authority, plan/binary/target substitution, expiry, schema restrictions,
scope overlap, full and partial runs, timeouts, malformed/truncated reports,
symlink redirection, artifact tampering, overwrite rejection, default MCP denial,
opt-in MCP execution, exact evidence retrieval and the presentation launcher.

Protocol and local-preview references:
[MCP tool errors](https://modelcontextprotocol.io/specification/2024-11-05/server/tools#error-handling)
and [Wrangler local development](https://developers.cloudflare.com/workers/wrangler/commands/workers/#dev).
