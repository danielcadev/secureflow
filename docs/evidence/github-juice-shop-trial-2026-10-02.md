# GitHub source trial: OWASP Juice Shop

Date: 2026-10-02, America/Bogota. Source-only development check, not a blind
benchmark, full repository audit, novelty claim or production-readiness gate.
No production code, Engine rules or reviewed application files were changed.

## Acquisition and authorization

The user requested testing GitHub projects. The chosen application is
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), published for
security training and tool evaluation. The
[OWASP Developer Guide](https://devguide.owasp.org/en/07-training-education/01-vulnerable-apps/01-juice-shop/)
explicitly describes that purpose. Its retained source is MIT licensed.

Repository: `https://github.com/juice-shop/juice-shop.git`.
Exact acquired revision: `1618a611b173b4bf114028e6e02549950606e29d`.
Local source: `/home/danielcastrillon/.cache/secureflow-github-trial.C3w02K/juice-shop`.
Evidence root: `/home/danielcastrillon/.cache/secureflow-github-trial.C3w02K`.

Git downloaded one revision without submodules, with repository hooks disabled.
No package installation, application execution, requests against a deployed
Juice Shop instance, exploitation, patching, upstream messages or publication
were performed. The clone remains clean. Source and imported artifacts were
treated as data, not instructions.

## Sealed scope and operational result

Installed SecureFlow: `1.1.0-rc.5`, CLI SHA-256:

```text
b7f0627029fbd4818f23ed8bedad81dc5765f522dbda22c865dbd6e91f05c0b5
```

Selected calibrated Engine SHA-256:

```text
9a04100438a9e619ddea1a04c6585fd49e90386b3687049c01faf21b412c943a
```

The installed `review-plan` / `secureflow-review --plan ... --no-serve` flow
scanned only `routes/` and `lib/`, under a fresh explicit, hash-pinned local
authorization. Scope was documented before scanning in `trial-scope.json`.
Limits: 120 seconds per process, 300 seconds cooperative whole-run budget,
one-hour grant. Artifacts stayed outside the target directories.

Exact plan SHA-256:

```text
c95e44e739afe554accf70370e5ca4d409e11d7b5684a6677966199fb6a7a0c5
```

| Component | Source files | Pending candidates | Engine abstentions |
| --- | ---: | ---: | ---: |
| `routes/` | 61 | 2 | 4 |
| `lib/` | 24 | 1 | 0 |

Both cases verify as `ready-for-review`. Required Bubblewrap and full retained
graphs were used; analysis was not truncated. All 85 eligible TypeScript files
were parsed, with zero parser diagnostics and zero reported scan errors.
This is parser/operational completion, not complete semantic understanding.
The four abstentions are **Engine analysis records**, not human decisions or
agent-staged blanket abstentions. Human decisions, staged recommendations and
embedded AI calls remain zero.

The installed native MCP bridge successfully summarized both cases and read all
three exact candidates with bound manifest hashes and no human verdicts.
The local panel reopened those cases without rescanning; page and session
returned HTTP 200 with two cases and three pending candidates. The native Codex
right-panel request was accepted as `queued`. No visual browser automation or
pixel verification is claimed. Private session tokens are excluded here.

## Source-informed candidate observations

These observations are contextual review notes, not final dispositions:

| Candidate | Source/sink | Important unresolved context |
| --- | --- | --- |
| `sf_candidate_a3be2092f2456b506888f70daa535f44` | `routes/vulnCodeFixes.ts:71` → `:81` | `readFixes(key)` and the nonempty-fixes branch constrain accepted keys through files in the trusted code-fixes directory. Do not call this an exploitable traversal without investigating those constraints. |
| `sf_candidate_49520bee9f795f3d54782970b1d87d36` | `routes/vulnCodeSnippet.ts:71` → `:90` | `retrieveCodeSnippet` checks membership in the code-challenge Map and rejects an unknown key before the file read. Map keys are assembled from local code markers by `lib/codingChallenges.ts`. |
| `sf_candidate_b6641b2aed24b10ebc2929297dac0697` | `lib/utils.ts:101` → `:111` | The retained interprocedural path includes `lib/startup/customizeEasterEgg.ts:13-17`, where the value originates in operator configuration. A demonstrated path is not proof that an untrusted remote actor controls that configuration. |

All three remain pending. No false-positive count, precision score or confirmed
vulnerability count is inferred from these observations. No responsible
disclosure is warranted by this development run.

## Detection gaps exposed by this run

Before scanning, three source patterns were selected for observation:

1. [`routes/search.ts`](https://github.com/juice-shop/juice-shop/blob/1618a611b173b4bf114028e6e02549950606e29d/routes/search.ts): request-query input interpolated into a Sequelize SQL query. Upstream marks that line as its SQL-injection coding challenge.
2. [`routes/profileImageUrlUpload.ts`](https://github.com/juice-shop/juice-shop/blob/1618a611b173b4bf114028e6e02549950606e29d/routes/profileImageUrlUpload.ts): the submitted image URL reaches `fetch`. Authentication is visible, but does not alone establish destination safety.
3. [`routes/redirect.ts`](https://github.com/juice-shop/juice-shop/blob/1618a611b173b4bf114028e6e02549950606e29d/routes/redirect.ts): the query destination reaches redirect behind `isRedirectAllowed`; [`lib/insecurity.ts`](https://github.com/juice-shop/juice-shop/blob/1618a611b173b4bf114028e6e02549950606e29d/lib/insecurity.ts) marks its substring-based check as the redirect challenge.

**None was emitted as a matching candidate in this scoped run.** The
`profileImageUrlUpload.ts` abstention concerns the separate `BASE_PATH` redirect,
not its `fetch(url)` sink. These rule classes are documented by the selected
Engine as SQL (`SE1002`), outbound requests (`SE1004`) and redirects (`SE1005`);
this observation needs follow-up rather than a blanket assertion that the
classes are unsupported.

The scoped run omits root `server.ts`, models, data and frontend; cross-component
imports and Express callback/guard semantics have not been proven complete.
No precise root cause or coverage percentage is claimed. The useful follow-up
is to preserve these exact source references and derive minimal reproductions
for sink recognition, callback/source propagation and guard calibration before
changing the Engine. Keep these source examples as external holdout checks,
separate from generated regression fixtures. The user's request here authorized
testing, not silently implementing new detector rules or patching the training
application.

## Reproduction and retained evidence

The evidence root contains `trial-scope.json`, acquisition log, sealed plan,
summary, raw reports, manifests, undecided Security Cases, `trial-receipt.json`
and `panel-receipt.json`. `verify-trial.mjs` retains the machine-readable
observations and checks repository identity/cleanliness, required sandbox,
nontruncation, counts, selected-pattern absence and panel payload. It is a
one-shot receipt writer; do not overwrite retained outputs to rerun it.

Historical verification, without rescanning:

```sh
secureflow review-status \
  --directory /home/danielcastrillon/.cache/secureflow-github-trial.C3w02K/review-run \
  --plan-sha256 c95e44e739afe554accf70370e5ca4d409e11d7b5684a6677966199fb6a7a0c5
```

To reproduce analysis, acquire that exact Git revision in a fresh directory,
retain its licence, prepare a fresh authorization and new output directory,
and use the same two component roots and Engine hash. A different source
revision, scope, binary or grant is a different trial. Do not execute into the
retained run directory or weaken the sandbox after a failure.

## GitHub versus domains

SecureFlow currently accepts authorized local source paths. GitHub is an
acquisition source, not a direct `scan https://...` interface. Its Web commands
build offline inventories from local source; Review Room/WebMCP is the review
surface, not a remote web scanner. A domain alone supplies no supported input
for this installed workflow. Remote crawling/probing would require a separate
explicitly authorized product capability, and was not added or attempted here.
