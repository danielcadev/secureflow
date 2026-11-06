# Automatic review: local candidate installed and exercised

Date: 2026-10-02, America/Bogota. Local Linux candidate `1.1.0-rc.5` only.
No commit, tag, push, release, deployment, issue or pull request was created.
The original `/home/danielcastrillon/Proyectos/secureflow` checkout was not
modified; its unrelated untracked assets and gallery script remain untouched.

## Correction

The installed `1.1.0-rc.4` CLI did not expose the automatic workflow already
qualified in the isolated `codex/automatic-review` checkout. Workspace and plugin
versions now identify that local candidate as `1.1.0-rc.5`. The CLI on PATH and
the enabled plugin have that same version.

- CLI: `/home/danielcastrillon/.local/bin/secureflow`.
- Installed launcher: `/home/danielcastrillon/.local/bin/secureflow-review`.
- Frozen CLI and Engine copies, plugin marketplace and backup:
  `/home/danielcastrillon/.local/share/secureflow/local-rc5.HfuVeM`.
- Enabled plugin: `secureflow@secureflow-local`, cached at
  `/home/danielcastrillon/.codex/plugins/cache/secureflow-local/secureflow/1.1.0-rc.5`.
- Source: `/home/danielcastrillon/Proyectos/secureflow-signal-calibration`,
  working-tree candidate based on `1103d5a52f60c8f36575192d4b289311bccf4f3f`.

The previous `personal` marketplace points to a different checkout. Registering
this source under that same name failed without changing the marketplace.
Instead, a dedicated local candidate marketplace was installed and only the
old `secureflow@personal` plugin registration/cache was removed. The original
marketplace, worktree and all other plugins were preserved. The previous plugin
and CLI are recoverable from `backup/` in the candidate directory.

The installer now rejects CLI/plugin version mismatch before mutation and reads
its actual marketplace name. The launcher supports `--help` without scanning
or starting a server. The updated packaged skill prefers the installed launcher
while preserving scope, required isolation and human-only final authority.
Start a new Codex chat to discover the updated plugin; an already-running MCP
process or loaded skill is not claimed to have been hot-replaced.

The launcher is a **source-bound local entry point** into the matching checkout,
its built Review Room and existing Node dependencies. Keep that checkout
available. The CLI/Engine copies are retained separately; this installation is
not a self-contained UI distribution or a cross-platform release.

## Fresh verification

Rust commands used the pinned Rust 1.92.0 toolchain, locked offline dependencies
and mandatory Bubblewrap tests:

```sh
SECUREFLOW_REQUIRE_SANDBOX_TESTS=1 cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo build --release --locked --offline -p secureflow
node --test scripts/tests/auto-review-launcher.test.mjs
node --test scripts/tests/plugin-installation.test.mjs
```

Results: **249 Rust tests**, zero failures/ignored; **10 launcher tests** and
**4 installer tests**, zero failures/skips. Formatting, Clippy, release build,
installed skill validation and whitespace checks passed. Installer regressions
cover mismatch rejection without any Codex call, exact source reuse/registration,
and selection of a separate candidate marketplace. No dependency was upgraded
by the local workspace-version change.

Installed CLI SHA-256:

```text
b7f0627029fbd4818f23ed8bedad81dc5765f522dbda22c865dbd6e91f05c0b5
```

Selected calibrated Engine SHA-256:

```text
9a04100438a9e619ddea1a04c6585fd49e90386b3687049c01faf21b412c943a
```

Previous CLI SHA-256 retained in the backup:

```text
430d4df5a9a9a830988fd29d2acafe965de8b99b19d9f295241c58d23f43a408
```

## Installed end-to-end run

Evidence directory:
`/home/danielcastrillon/.cache/secureflow-local-rc5.r9BqQs`.

The installed CLI prepared a fresh, one-hour authorization grant with a
120-second per-process and 300-second cooperative overall budget. The installed
launcher executed it with `--no-serve`. All four explicit source snapshots used
required Bubblewrap, a full Engine graph and outputs outside the source trees.
No target program was executed and no target network request was made.

| Component | Type | Candidates | Human decisions |
| --- | --- | ---: | ---: |
| `apps/review-room/app` | Real SecureFlow source | 0 | 0 |
| `apps/review-room/lib` | Real SecureFlow source | 0 | 0 |
| `tests/fixtures/automatic-review/target-a` | Synthetic positive control | 1 pending | 0 |
| `tests/fixtures/automatic-review/target-b` | Synthetic negative control | 0 | 0 |

The one candidate is `sf_candidate_69aa0c88d08bfae81de155bbc75ace67`, an untrusted
input-to-command sink in the committed positive control. The mixed regex call
did not become another command-sink candidate. This is not a real-world finding
or evidence of complete scanner coverage. Zero candidates in the two real
components does not prove their security.

The run reports `ready-for-review`, four complete cases, zero AI calls and zero
human decisions. `contextual_investigation` remains `not-performed-by-runner`.
The exact plan SHA-256 is:

```text
16d447e8dfd3cd1d4ac6630af920617a001afbfbf82f426581ea2a14e7ecbeb2
```

Installed MCP checks passed: the default server exposes five tools and refuses
automatic execution without a startup grant; the pinned server exposes eight
tools, verifies the bundle, and retrieves the positive control's bound source
and sink without turning its pending state into a verdict. Re-run the retained
read-only checks using `mcp-smoke.mjs` only while the live grant is valid and
sources remain unchanged; historical `review-status` verification does not
require extending that grant.

The installed launcher reopened the four cases without rescanning. The UI and
token-bound session returned HTTP 200, all four cases and the single pending
candidate. A foreign Origin returned 403, and the URL was announced after loader
readiness. Codex accepted the native right-panel open request as `queued`.
No pixel-level browser verification is claimed. Session tokens are private and
not included in this document.

To verify/reopen the retained bundle:

```sh
secureflow review-status \
  --directory /home/danielcastrillon/.cache/secureflow-local-rc5.r9BqQs/review-run \
  --plan-sha256 16d447e8dfd3cd1d4ac6630af920617a001afbfbf82f426581ea2a14e7ecbeb2
secureflow-review \
  --directory /home/danielcastrillon/.cache/secureflow-local-rc5.r9BqQs/review-run \
  --plan-sha256 16d447e8dfd3cd1d4ac6630af920617a001afbfbf82f426581ea2a14e7ecbeb2 \
  --port 3371 --session-port 3372
```

Stop the current owned panel session or choose unused ports before reopening.
Do not reuse the existing output directory for execution or silently renew a
plan to analyze changed source.

## Recovery and limits

To restore the previous CLI, copy
`local-rc5.HfuVeM/backup/secureflow-1.1.0-rc.4` back to the exact CLI path.
The old `personal` marketplace still exists; `codex plugin add
secureflow@personal` restores that plugin. Remove only
`secureflow@secureflow-local` if switching back, to avoid two active SecureFlow
plugins. Existing cases and original application work are not rolled back.

Current dependency-advisory audit, independent human security review,
cross-platform qualification, real maintainer trials and detection-quality
benchmarks remain uncompleted. This correction establishes an installed,
working analysis/evidence/review pipeline, not guaranteed discovery of novel
vulnerabilities or superiority over another security product. No autonomous
patching or inferred human verdict was added.
