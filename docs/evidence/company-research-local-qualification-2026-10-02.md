# Company research intake: local qualification

Date: 2026-10-02. Development checkout:
`/home/danielcastrillon/Proyectos/secureflow-signal-calibration`, branch
`codex/automatic-review`, base HEAD
`1103d5a52f60c8f36575192d4b289311bccf4f3f` plus the explicitly inventoried local
changes. This receipt qualifies the company intake slice, not a release or
complete autonomous company-security investigation.

## Implemented behavior

Company, URL and GitHub-organization seeds create a private local workspace.
Six stdio MCP tools import host-declared discovery evidence, preserve linked
domains/subdomains/repositories/origins/endpoints, expose compact queries, and
export a hashed inventory. CLI import pins its local input file by SHA-256.
Canonical hash-chained journals support checked replay and historical exports.
Capacity is validated before mutation; failed appends do not become clean state.

The graph always retains unverified ownership, unapproved scope, and disabled
execution. The broker has no provider fetcher, network transport, approval tool,
or human verdict. The existing source scanner and separate owned-loopback
executor keep their contracts. See [walkthrough](../company-research.md) and
[contract](../contracts/secureflow-company-research-v1.md).

## Verification

Runtime: Node `v22.23.1` on Linux. CI retains its existing pinned Node `22.19.0`;
that hosted workflow has been updated but was not run remotely in this turn.

| Gate | Result |
| --- | --- |
| `node --test scripts/tests/company-research.test.mjs` | 24 passed; implementation worker, final core |
| `node --test scripts/tests/company-research-mcp.test.mjs` | 7 passed; main, final core/launcher |
| `node scripts/demo-company-research-local.mjs --output-dir FRESH_EXTERNAL_DIR` | Passed through real stdio MCP and fresh-process replay |
| Demo SHA-256 inventory | 11/11 retained files matched |
| Ajv 2020 + formats | Request, discovery, inventory passed; unknown fields and enabled authority rejected |
| Advertised MCP discovery contract | Matches the standalone schema structurally |
| CI YAML / local documentation links / `git diff --check` | Passed |
| Independent immutable-snapshot review | No remaining blocker in the reviewed boundary |

The demo retains five synthetic assets, three synthetic source declarations and
one batch. It performs zero provider/target requests, repository scans, active
tests or human decisions. Actual host-model usage is unmeasured; no model took
part in the scripted demo. Fixture hashes identify locally retained synthetic
bytes and do not authenticate a real company's assets.

The independent review found one correctness mismatch: URL normalization could
accept a repository path containing literal or escaped `..` before the exact
owner/repository check. Raw repository paths now validate first. Regression
coverage rejects literal, escaped and mixed forms before append, while preserving
ordinary dotted repository names, default HTTPS ports, and endpoint/seed path
normalization. The reviewer independently passed the affected regression (1/1).
No security exploit or authority expansion was claimed for this mismatch.

## Retained evidence and identities

External qualification directory:
`/home/danielcastrillon/.cache/secureflow-company-research-qualification.D01lzd/`.
It retains `baseline.json`, `verification.json`, `mcp-tests-final.tap`,
`demo-qualified.log`, and `demo-qualified/` including its receipt and checksums.
`verification.json` records commands, final source-file hashes and the exact
demo inventory digest:

```text
2e84bcb522d118e5a405219b2baa007ec3493cd9a6ba81c4aa30f8d5917396a2
```

The read-only review snapshot contains eight new files and a nonempty,
byte-matched `candidate.patch`. Its manifest SHA-256 is
`dc27490a9e7849138f52bf05ba31c8eb4c2bad370a1de598b740d52a141d0da3`.
The two-file fixed overlay manifest is
`f6cce1204272ef756677abb92bd23b582dddf5eff8a9de858d8a7c7b10b50d98`.
Acceptance covers the original six unchanged files plus the two verified overlay
files. The main agent separately inspected and exercised the integration demo,
CLI tests, CI additions and documentation links.

Preservation checks matched all 433 files outside the declared edit set to the
baseline digest
`78d8d72fe0bfadfd81787405d4ff84dc236e5abc446773e55f683861e9c21043`.
The original `/home/danielcastrillon/Proyectos/secureflow` checkout remains at
`cb888ecf0b6294c3babe224593fedf80c7b26cda` with only its preexisting untracked
`docs/assets/` and `scripts/capture-review-room-gallery.mjs`.
Installed plugin/default MCP configuration was not changed. No commits, push,
tag, external issue or release was made.

## Remaining qualification

The company sidecar is available from source, not automatically registered in
the installed host. Public-provider collection, company disambiguation, exact
scope selection, an actual model-directed host session, approved remote/browser
execution, and dynamic Review Room evidence linkage remain separate product
gates in the [plan](../plans/autonomous-web-api.md).

The local storage boundary assumes a trusted UID, private ancestors, and one
writer. Cross-platform behavior, hostile same-account replacement, concurrent
writers, arbitrary filesystem failures and physical power-loss durability are
not qualified. Synthetic intake success establishes neither real vulnerability
detection nor complete environmental coverage. No token savings measurement,
security guarantee, bounty eligibility or production-readiness claim is made.
