# Local RegExp.exec calibration — 2026-09-25

Status: implemented and verified in independent local clones. Not installed,
pushed, deployed, or published. The WebMCP Challenge submission is untouched.

## Result

A controlled comparison on the same historical `apps/web/src` snapshot removed
exactly two incorrect process-execution candidates. Both were calls to a local
regex literal's `exec` method, not a process API. All 25 other candidates and both
Engine abstentions were identical, including their retained evidence.

| Check | Parent Engine | Patched Engine |
| --- | --- | --- |
| Files scanned | 541 | 541 |
| Engine candidates | 27 | 25 |
| Incorrect RegExp process sinks | 2 | 0 |
| Engine abstentions | 2 | 2 |
| Parser diagnostics | 3 | 3 |
| Full graph, full facts, complete scan | Yes | Yes |
| Required Bubblewrap isolation | Yes | Yes |
| Valid Security Case | Yes | Yes |
| New human decisions | 0 | 0 |

This is a comparison of one component at an exact historical revision, not a
re-scan of today's monorepository or all nine original cases. The original case
set's 53 candidates are not the denominator of this experiment. The newer parent
Engine already differs from the old installed RC2; those pre-existing differences
are not attributed to this patch. Three unchanged parser diagnostics remain a
coverage limitation even though the runs completed without truncation.

## Source and authority

- Target: Mitiquete commit `beb4359c80da6dc2ffe3434524567176b5ee8978`, only
  `apps/web/src`, exported with `git archive` and parsed without executing it.
- Engine parent: `adf92157366251538946d4707de643ba05700c05`.
- Engine candidate: `9f873bf79e72c6780b33829eabc013961f0bb74d` on local branch
  `codex/regexp-exec-precision` in
  `/home/danielcastrillon/Proyectos/secure-engine-signal-calibration`.
- SecureFlow documentation branch: `codex/signal-calibration`, based on
  `753f91c950b0d7cacb492024f839c2fdf4ab0c54`, in
  `/home/danielcastrillon/Proyectos/secureflow-signal-calibration`.
- Both clones have no `origin` remote and do not share the submitted repository's
  Git metadata. SecureFlow production code is unchanged in this work.
- Scan authority: active user's local-project instruction, 2026-09-25.
  Existing cases and human verdicts were not rewritten. The SecureFlow skill's
  required sandbox, external evidence storage, and human-only authority were
  preserved. This modifies the detector, not the application under investigation.

The two removed SE1001 sinks are in `lib/crm/atlas/chat.ts` at lines 232 and 249
of that exact snapshot. Their original Security Case candidate IDs were
`sf_candidate_f6cff8430944f3a8fd6f11fd9cda2eb9` and
`sf_candidate_7ee8e790071c199039186bdca5dbacea`; this receipt does not change their
decisions or infer any new decision from scanner disappearance.

## Implementation and gates

Engine `crates/secure-engine/src/call_target.rs` shares a bounded syntactic
refinement between normalized facts and graph extraction. Only a direct local
`const` regex literal with restricted uses is refined. Unknown receivers,
mutation, escape, shadowing, recognized dynamic/prototype operations, parser
errors, and exhausted traversal budgets retain existing sink behavior. Generic
call evidence stays available. Cache namespace v24 prevents stale v23 results
from surviving the classification change; old cache directories are not deleted.

The implementation assumes standard built-ins; cross-module/obfuscated monkey
patches, arbitrary coercion effects, and ReDoS are not proven safe. There are no
repository-specific ignore rules or blanket suppressions for authorization,
redirect, configuration, or outbound-request candidates.

Rust 1.92.0 verification:

```sh
cargo test -p secure-engine -p secure-cli --locked --offline
cargo clippy -p secure-engine -p secure-cli --all-targets --locked --offline -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Results: 236 tests passed, zero failed or ignored; Clippy, format, and whitespace
checks passed. Seven new tests cover safe literals across JS/JSX/TS/TSX, actual
process imports/aliases and unknown receivers, mutation/escape/shadowing,
unrelated constructors, mixed real and false sinks, traversal budgets, and
cold/warm cache parity. Before implementation, the safe-literal and mixed-call
regressions failed. A Clippy documentation-format warning was corrected before
the passing final run. The desktop GUI crate, cross-platform builds, dependency
advisory audit, and independent human review are not claimed as completed gates.

## Retained reproduction evidence

Local evidence root:
`/home/danielcastrillon/.cache/secureflow-regexp-calibration-20260925.4VAm1q`.
It contains both exact binaries, full raw reports and run manifests, validated
Security Cases, test/Clippy/build logs, source patch, checksums, and the comparison
gate `compare-reports.jq`. Raw reports and source exports are private local
artifacts, not included in this documentation commit.

The scans used the same exported target, authorization, revision, configuration,
`--sandbox required --full-engine-graph --timeout-seconds 120`; only `--binary`
and external output paths differed. SecureFlow reported both complete with
`sandboxed=true`, `timed_out=false`. Engine exit status 1 denotes retained
candidates in these successful scans, not a failed scan. Cases were created
only after each completed manifest existed, then validated with `case-validate`.

From the evidence root, replay the exact comparison gate:

```sh
jq -n --slurpfile before baseline/raw-report.json \
  --slurpfile after candidate/raw-report.json \
  --slurpfile before_manifest baseline/run-manifest.json \
  --slurpfile after_manifest candidate/run-manifest.json \
  -f compare-reports.jq
sha256sum -c SHA256SUMS
```

The comparison checks completed untruncated full reports, identical target,
configuration, inventory/files, diagnostics, sandbox binary, and abstentions;
zero added findings; exactly the two expected regex sinks removed; and all
remaining finding objects identical. `comparison.json` retains the result.

Binary SHA-256:

- Parent: `3c22475ec0fdb73405e1c017577482c5702c13d69eb5e36fd277a65ed428904b`.
- Candidate: `9a04100438a9e619ddea1a04c6585fd49e90386b3687049c01faf21b412c943a`.

Both development binaries report package version 0.1.10; source commit and binary
hash distinguish them. These are host-specific test builds, not newly qualified
releases or a cross-host binary-reproducibility claim.

## Next boundary

The patch is ready for review and later integration after the submission freeze,
not an automatic global Engine replacement. The installed SecureFlow/Engine and
live Review Room remain unchanged. Subsequent runs must explicitly select the
new binary if testing this candidate.

Further false-positive reduction needs paired regression evidence for each
remaining rule family, especially authorization and outbound destination models.
Do not lower the candidate count by hiding unknown cases or transferring human
verdicts between similar candidates. This change avoids two unnecessary review
paths in the measured snapshot; no token, allowance, runtime, or real-world
vulnerability-detection improvement has been quantified.
