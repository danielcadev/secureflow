# Dynamic local execution qualification

Date: 2026-10-02, America/Bogota. Source-only development slice based on
`1103d5a52f60c8f36575192d4b289311bccf4f3f` in the existing dirty
`codex/automatic-review` development clone. No commit, push, tag, release,
installation change, external target traffic, issue, or disclosure was created.

## Outcome and scope

SecureFlow's [product objective](../plans/autonomous-web-api.md) now includes
AI-directed web and API investigation without mandatory repository access.
The [repository scanner milestone](../milestones/repository-scanner.md) remains
available and unchanged. This slice implements only the approved loopback GET
execution boundary, not the whole autonomous researcher.

The connected host must supply reasoning. A separate opt-in Node stdio broker
allows four tools over immutable approved actions, identity probes, budgets,
private create-new evidence, and explicit finish. It adds no provider transport,
dynamic Security Case, human decision, patching, browser agent, or remote origin.

Detailed commands, snapshots, and artifact hashes are retained at:

`/home/danielcastrillon/.cache/secureflow-dynamic-qualification.bNc6vH`.

## Verification

Local runtime: Node `v22.23.1` on Linux. CI remains pinned to Node `22.19.0`;
the new hosted gates are configured but were not executed by this local work.

| Check | Status | Evidence |
| --- | --- | --- |
| Initial combined Node tests | Passed | 43 tests: 29 initial dynamic, ten existing launcher, four existing installer; external TAP retained |
| Affected post-fix dynamic suite | Passed | Implementation worker ran 34 tests with zero failures; unrelated launcher and installer suites were not repeated |
| Refreshed real stdio MCP demo | Passed | Five observations and ten owned-fixture GETs; two identities plus anonymous access; one intentional status mismatch, zero decisions |
| Artifact checksums | Passed | All 36 final demo inventory entries verify, including provisional and final result files |
| Structural schema validation | Passed | Existing Ajv 2020 and formats accepted final plan/result and rejected an unknown-field negative control |
| CI and documentation checks | Passed locally | YAML parsed; ten new-document relative links resolved; whitespace checked |
| Independent review and targeted repair verification | Passed for the slice | One finalization correctness blocker fixed; independent reproduction verified all three sync-fault phases; stdout backpressure corrected |
| Existing file preservation | Passed | 422 files outside the explicit change inventory retain their recorded hashes |

The initial 43-test run predates the finalization/backpressure corrections;
the 34-test run covers the affected final implementation. Counts are not a
claim that all Rust or UI tests were freshly run. No Rust crate, dependency,
installed plugin, or Review Room code changed in this slice, so their historical
249-test Rust qualification was not repeated. Full release gates remain separate.

The demo deliberately uses an owned synthetic application. A user-A baseline
returns 200; a correct user-B control returns 403; anonymous access returns 401;
an intentionally broken ownership guard returns 200 where 403 was expected;
the corrected negative control returns 403. Raw bodies and Bearer values are
absent from protocol and artifact canary checks. Status comparisons alone do not
prove unauthorized data exposure or establish an exploitable vulnerability.

## Independent review and correction

The first immutable 15-file review manifest hash was:

`45cd7f76945ac258dc4f900923d3b62de49333b8ccdd09c7431eb938ce6add86`.

The reviewer reproduced a file-sync failure after a result write: in-memory
state failed, while the on-disk result incorrectly remained completed. This was
a correctness and evidence-integrity defect, not a confirmed security exploit.

The corrected immutable manifest reviewed for affected changes was:

`a4ec5bb67c3ab6f3fe643f9d35d5b51001e5152116e60b901f3a4cd840ce8010`.

Independent tests injected provisional-file, provisional-directory, and
published-directory sync faults. All produced failed state and no final
`result.json`; the last preserved an unpublished hardlink. Evidence under
provisional/unpublished names is nonfinal. Arbitrary filesystem failures may
also prevent quarantine; physical power-loss durability is not established.

The reviewer also identified cooperative idle-time semantics and unchecked
stdout backpressure. The runner now awaits response writes before dispatching
another request. Documentation distinguishes an explicit MCP finish response
from deterministic CLI exit zero. Those final wording corrections occurred
after the corrected snapshot; implementation files are unchanged from it.

## Retained artifacts and preservation

- `demo-final/` retains the final successful demo with `SHA256SUMS`.
- `verification.json` records commands, counts, review scope, and limitations.
- `final-source-files.json` binds the 15 implementation and documentation files
  other than this qualification document.
- Read-only review snapshots retain the exact independent review inputs.
- `baseline.json` records the allowed change inventory and protected-file digest.

The demo's original plan paths, ephemeral port, and timestamps are preserved,
not rewritten to the retained copy location. The service is stopped and the
copied grant is historical evidence, not permission to replay a new target.
Source hashes bind this development state, not a release or attested binary.

The preserved-file inventory SHA-256 is:

`b7e37b457c9a4588b652597dc65e4af44e1bdadd8949775da061dd9c66042adb`.

The original `/home/danielcastrillon/Proyectos/secureflow` checkout remains
untouched, including its untracked assets and gallery script. Existing dirty
scanner work in the development clone was preserved. Installed
`1.1.0-rc.5`, default MCP and previous cases were not replaced.

## Remaining gates and residual risk

Useful minimized observations, actual host-model investigation, stateful
hypotheses, dynamic case linkage, native Review Room presentation, remote-domain
support and browser support remain future slices. No real-world efficacy,
unknown vulnerability, reward, novelty, human-superiority, or production-safety
claim follows from this demo.

The immediate parent directory, ancestors, local account, kernel, and runtime
remain trust assumptions. The identity endpoint is not attestation and has a
probe/action race. GET can have side effects. Body hashes can reveal equality or
low-entropy facts. Passive status reports the last recorded state; the execution
window prevents later I/O but does not terminate idle MCP connections.
