# Final project handoff

Date: November 6, 2026, America/Bogota.

The owner has ended active feature development of SecureFlow. This handoff
preserves the implemented prototype, publishes the outstanding source changes,
and documents the limits of unfinished research. It does not archive or delete
repositories, revoke licenses, remove evidence, or promise ongoing support.

## Delivered

- Authorized local Engine analysis, source and binary provenance, bounded
  execution, Security Cases and human-only final decisions.
- Automatic local analysis plans, component cases, bounded candidate queries,
  and Review Room preloading in the Codex side panel.
- Explicit remediation handoffs and closure checks that preserve original
  candidate identities and human decisions.
- Local advisory catalogs, trusted catalog distribution, supply-chain
  correlation, backups and the offline CodeSupply demonstration.
- Secure Skill and Secure Bench imports as separate, versioned evidence lanes.
- A source-only company inventory server with six MCP tools, linked asset
  evidence, bounded queries, canonical journal replay and hashed exports.
- A separately approved owned-loopback GET broker with reproducible local
  controls, identity checks, budgets and minimized evidence.
- An experimental version 2 HTTPS transport with exact origin/public-IP scope,
  DNS pinning, certificate verification and redirect rejection. Its guard tests
  use mocked network dependencies; it is not a qualified remote scanner.

The bundled Security Case skill now routes these modes through one entry point
with a [research reference](../plugins/secureflow/skills/secureflow-security-case/references/research-modes.md).
The installed default case MCP server retains its local contract. Source
research tools require explicit startup and do not appear automatically in
existing chats.

## Final component identities

| Component | Published source |
| --- | --- |
| SecureFlow | [repository](https://github.com/danielcadev/secureflow), final handoff commit containing this document |
| Secure Engine | [67e9dd18439525aae21d4c796c0f8bee3ad290f6](https://github.com/usesecure/secure-engine/commit/67e9dd18439525aae21d4c796c0f8bee3ad290f6), including local RegExp/process sink calibration merged with upstream |
| Secure Bench | [485402e099f7e99577203e56604bbaadec0623fa](https://github.com/usesecure/secure-bench/commit/485402e099f7e99577203e56604bbaadec0623fa), frozen Phase 38 post-open scoring certification |
| Secure Skill | [b355462d279ce4393547cd28be3128153957d3ab](https://github.com/usesecure/secure-skill/commit/b355462d279ce4393547cd28be3128153957d3ab), validated canonical skills and handoff |

Repository visibility and old tags are preserved. Secure Skill remains private.
Source publication is not a new stable binary release or an installed-client
upgrade. Historical releases, benchmark results and synthetic fixtures retain
their original limitations.

## Verification

Local Rust verification uses the pinned 1.92.0 toolchain. Node verification uses
22.23.1. Affected checks and their final results are recorded in
[the closure receipt](evidence/project-handoff-2026-11-06.md).

Secure Skill completed `npm run validate`: 54 Python tests, seven benchmark
tests, ten language-fixture validations, both installation smoke checks, and
site build/link checks. Its documentation-only handoff also passed repository
validation. Secure Engine core, CLI and desktop tests, formatting and core/CLI
Clippy passed after merging current upstream. Secure Bench Phase 38 tamper tests
and its scanner-free verifier passed over 168 attempts, 168 raw reports, 168
adapted reports and 37 retained findings; no scanner was rerun or score changed.

Known-vulnerable benchmark dependency manifests are intentionally retained as
test inputs. GitHub dependency alerts on those fixtures must not be presented
as verified vulnerabilities in the Rust benchmark harness or silently repaired
by altering historical cases.

## Not delivered

The company-to-autonomous-research product remains unfinished. There is no
built-in public-provider collector, automatic company identity resolution,
inventory-to-approved-scope bridge, qualified model-driven research campaign,
browser executor, or dynamic-to-Security-Case conversion. An imported URL,
repository, company name or domain relationship never grants testing authority.

No claim of complete environmental coverage, automatic zero-day discovery,
guaranteed bounty payments, superiority over researchers, or production safety
is supported. [The old plan](plans/autonomous-web-api.md) is retained as design
history; it is not a queue of promised work after this handoff.

No private case bundles, session tokens, test credentials or advisory database
payloads are published by the handoff. Local installations and evidence remain
available at their existing paths. The original `secureflow` checkout's
untracked assets and gallery script are preserved.
