# Real-application source trial: Uptime Kuma

Date: 2026-10-02. Private source-only development evaluation, not a complete
security audit, vulnerability disclosure, benchmark score or release gate.

## Target and authority

The user clarified that GitHub testing should use real projects rather than
only intentionally vulnerable training applications. Selected
[Uptime Kuma](https://github.com/louislam/uptime-kuma), a self-hosted monitoring
application, and acquired a fresh public source copy without submodules or
repository hooks. Its retained licence is MIT.

Exact revision: `e7420f8fa546a8baa7ac4bf9d10a32545d4346e0`.
This is a pinned repository snapshot, not a claim about a stable release.

Evidence root:
`/home/danielcastrillon/.cache/secureflow-real-projects.pONhN9`.
Source copy: `uptime-kuma/` under that root; clean before and after scanning.

Local analysis was authorized by the user's GitHub testing request. This is
not authorization to test an installation belonging to another operator.
No target dependency installation, target execution, deployed-target requests,
exploitation, patches, upstream messages, issues or pull requests occurred.

The retained [security policy](https://github.com/louislam/uptime-kuma/security/policy)
excludes raw scanner reports and SSRF reports; none will be submitted. The
repository's contribution guidance cautions against unreviewed AI-generated
submissions; this private evaluation makes no contribution or public finding.

## Scope frozen before execution

`uptime-kuma-trial-scope.json` records the exact three non-overlapping roots,
27 eligible JS/TS files, context controls, exclusions and authority. Other
root server files, directories, dependencies and deployed instances were not
scanned. Imports outside component roots may limit semantic coverage.

| Component | Files scanned | Candidates | Engine abstentions |
| --- | ---: | ---: | ---: |
| `server/routers` | 3 | 0 | 0 |
| `server/socket-handlers` | 11 | 0 | 0 |
| `server/model` | 13 | 0 | 0 |

All three analyses completed without truncation, reported errors or parser
diagnostics; all three Security Cases validate. Required Bubblewrap was
retained. No human decisions, staged recommendations or embedded AI calls
were made. Native MCP summaries independently returned zero candidates for
each case. Operational `ready-for-review` does not mean the application is safe.

The preselected contextual controls are the HTTP push token's parameterized
query, imported `checkLogin(socket)` calls and administrator-configured
monitoring operations. These are review obligations, not evidence that every
control or route is correct. A monitoring feature is not automatically an
SSRF vulnerability simply because it sends a request.

Each report records zero `entry_points`, despite visible HTTP/Socket.IO
handler registrations in the source. This is a diagnostic observation to
investigate, not proof that all those handlers were ignored: the meaning and
completeness of that metadata and source propagation need targeted checks.
The reports explicitly limit callback/dynamic resolution and framework
middleware modeling. Parser completion alone does not establish semantic
coverage or absence of vulnerabilities.

## Reproducible evidence

Installed SecureFlow: `1.1.0-rc.5`.

- CLI SHA-256: `b7f0627029fbd4818f23ed8bedad81dc5765f522dbda22c865dbd6e91f05c0b5`.
- Engine SHA-256: `9a04100438a9e619ddea1a04c6585fd49e90386b3687049c01faf21b412c943a`.
- Plan SHA-256: `25ae223fdd0d4276321a7fe93fb543e6acb02194bb953012fee12ad8093d60a7`.

The external evidence root contains the frozen scope, original plan, run
directory with raw reports/manifests/undecided cases, and
`uptime-kuma-trial-receipt.json`. The receipt retains actual hashes, per-component
completion and counts, licence/policy hashes, original Git revision and
cleanliness. A read-only Node verifier checked these facts before saving it.

The plan grants one hour, 120 seconds per process and 300 seconds overall.
It was executed using the installed `secureflow-review --plan ... --no-serve`
entry point. Historical verification without reanalysis:

```sh
secureflow review-status \
  --directory /home/danielcastrillon/.cache/secureflow-real-projects.pONhN9/uptime-kuma-review-run \
  --plan-sha256 25ae223fdd0d4276321a7fe93fb543e6acb02194bb953012fee12ad8093d60a7
```

Review Room reopened those exact cases without rescanning on loopback ports
3391/3392. The page returned HTTP 200; opening in Codex's right browser panel
was accepted as `queued`. No pixel verification is claimed. Ephemeral session
tokens are excluded from retained evidence and this document.

## Interpretation and next acceptance test

This establishes an operational trial on a real application, not successful
vulnerability discovery. Zero candidates cannot establish zero false negatives,
correct suppression, precision or recall. There is no labelled vulnerability
ground truth for this current snapshot and scope.

To evaluate detection quality, use additional real repositories with published,
already-fixed security bugs. Freeze the vulnerable and fixed revisions and
expected source/control/sink tuples before executing the unchanged Engine;
compare both outputs and separately assess candidate context. Keep those
holdouts separate from detector regression fixtures and count misses honestly.
Never manufacture a confirmed issue from a scanner title or assume permission
for runtime exploitation or upstream reporting.

No Engine rules or SecureFlow production code were changed during this trial.
