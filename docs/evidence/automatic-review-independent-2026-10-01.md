# Automatic review: independent source review and presentation corrections

Date: 2026-10-01, America/Bogota. Development-only qualification in
`/home/danielcastrillon/Proyectos/secureflow-signal-calibration`, branch
`codex/automatic-review`. No commits, installation, push, release, or deployment.

## Independent review

One separate `gpt-6.1-sol` worker at high reasoning effort reviewed a frozen
source snapshot against `1103d5a52f60c8f36575192d4b289311bccf4f3f`. This was an
independent AI source review, not an independent human audit or a new security
scan. The reviewer had no write permission in its assigned workflow and ran no
application code or repeated test suites.

Initial exact patch SHA-256:

```text
ec6d77ed244fdd1e0bc59f240cc1c1ccb9c302d853e9662d4850b1028e2a58b5
```

Review artifacts are retained at
`/home/danielcastrillon/.cache/secureflow-final-review.91ZCsz` with read-only
baseline/candidate snapshots and two bounded follow-up snapshots. Scope included
the automatic runner, extracted shared scan, MCP dispatch, schemas, presentation
launcher, tests, and the existing adapter/case/session boundaries they use.

The reviewer identified a P2 correctness gap: the launcher could announce a
session and run the UI while the background case loader had failed. Demonstrated
triggers were an occupied session port or a valid multi-component bundle larger
than the presentation layer's existing 128 MiB aggregate limit. No new security
bypass or shared-scan regression was identified within this review's limits.

## Corrected behavior

- The loader checks all file-size limits before allocating case payloads.
  Existing 32 MiB per-case and 128 MiB aggregate bounds are unchanged.
- `open-review-room.sh` uses a supervisor for loaded-case sessions. A private
  Node IPC message confirms successful loader initialization and port binding
  before starting the UI and announcing its session URL.
- Startup is bounded to ten seconds. Loader failure stops the owned runtime;
  UI failure preserves its exit status and stops the loader.
- The supervisor manages the owned POSIX process group even if the npm leader
  exits first. SIGKILL escalation remains active after two seconds; cleanup must
  be confirmed before successful exit. Unconfirmed cleanup returns failure
  within four seconds rather than leaving a running descendant silently.
- Headless `--no-serve` bundle verification remains usable for larger valid
  analysis sets. Presentation failure neither reruns analysis nor invalidates
  retained cases, and creates no human decisions.

A follow-up review caught the initial supervisor's leader-versus-descendant
cleanup mistake. After the bounded correction, the same reviewer checked the
final exact supervisor and tests and confirmed both P2 issues closed, with no
remaining actionable concern in that focused delta.

Final reviewed supervisor SHA-256:

```text
7b7b8fad5dd8ee9756a212b437121921625f31e47e644a2bc86c3c6e752f3cf3
```

Final reviewed launcher-test SHA-256:

```text
1b2c2bbdd753b0d40755630a08090a0a08ad5c34e1aefc2180b32ef89e66d851
```

## Verification

The occupied-port, oversized-session and premature-announcement tests all failed
on the previous launcher before the fix. Targeted launcher verification then
passed nine tests, zero failed and zero skipped on Linux. Coverage includes
literal path handling, invalid grants/summary rejection, all three presentation
regressions, unexpected loader exit, UI exit/port release, and a descendant that
ignores SIGTERM after its leader exits. Orphan zombies are distinguished from
running processes; unconfirmed disappearance cannot count as successful cleanup.

Node syntax, Bash syntax and `git diff --check` passed. Rust implementation was
unchanged from its previously verified qualification; Rust tests were not
repeated for these presentation-only changes. The final source inventory retains
hashes for the complete local development file set.

A smoke test reopened the two retained synthetic cases using the candidate CLI,
the rebuilt local Review Room and the corrected supervisor. No scan was repeated.
Page and session returned HTTP 200, two cases and one candidate were loaded,
human decisions remained zero, a foreign Origin returned 403, and the session URL
was announced after loader readiness. The native Codex panel request was accepted
as queued. No pixel-level UI verification is claimed. Private session tokens are
excluded from this receipt.

## Product follow-up

[Product validation alongside Codex Security](../plans/product-validation-2026-10-01.md)
records the current capability overlap and a bounded maintainer trial. It is a
working recommendation, not evidence of adoption or detection superiority.
The next experiment should use the existing SARIF importer and identify missing
investigation data before adding another adapter or broad scanner capability.
External trials, new target scans and publication remain separate actions.

Human security review, cross-platform qualification and a current dependency
advisory audit remain uncompleted release gates. The installed plugin and
original checkout were not modified by this work.
