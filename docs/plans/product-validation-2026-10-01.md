# Product validation alongside Codex Security

Date: 2026-10-01. Working recommendation for the next milestone, not a claim of
market demand or an approved change to published product promises.

## Decision

Continue SecureFlow as an open-source local research workbench, while testing
whether it earns a place in a maintainer's existing security workflow. Competing
on general AI vulnerability reasoning is not supported by our evidence. Useful
engineering and portfolio value are separate from adoption or commercial viability.

Codex Security already documents repository/diff/deep scans, retained evidence,
findings workspaces, SARIF export, recurring-finding feedback, revision tracking,
patch assessment and fix verification. It also supports multiple providers in
its local plugin. Human review, portability, MCP, model choice and a dashboard
alone are therefore insufficient differentiation. Codex Security Cloud explicitly
describes its role as complementing deterministic SAST coverage.

Sources checked on this date:

- [Local plugin capabilities and changes](https://learn.chatgpt.com/docs/security/plugin/changelog).
- [Cloud FAQ and relationship to SAST](https://learn.chatgpt.com/docs/security/faq).
- [Evidence and focused remediation](https://learn.chatgpt.com/use-cases/remediate-vulnerability-backlog).

Cloud and the local plugin are distinct products. No claim is made that all Codex
Security workflows require a cloud repository scan, or that competitors lack
evidence retention and human review.

## Proposed user and value hypothesis

The first user is a maintainer with an authorized local source checkout who
already uses an assistant or scanner and needs to inspect findings, retain the
supporting artifacts, and produce a reviewable correction without repeatedly
rebuilding context.

Hypothesis: a locally executable deterministic scan, shared evidence bundle and
focused review interface can reduce the work required to investigate a small
set of findings and hand them to the maintainer's chosen assistant. Scanner
execution and artifact verification work without a model call; contextual AI
review depends on the connected client's transmission and privacy behavior.

This hypothesis needs user trials. No superiority, novel-vulnerability,
cross-provider equivalence, universal offline AI or token-savings claim follows
from having the architecture.

## What already supports that experiment

- Engine adapter, required sandbox, target authorization and snapshot hashing.
- Security Cases, human decisions, scoped remediation and closure contracts.
- Manual Review Room, MCP investigation/staging, and the implemented local
  automatic scan-to-case-to-panel flow, independently source-reviewed and still
  awaiting integration.
- SARIF import/export: `crates/secureflow-case/src/lib.rs` and CLI
  `case-import-sarif` / `case-export-sarif`. Do not build a duplicate importer.
- Narrow RegExp calibration: two false process sinks removed in one historical
  component, with the other 25 candidates and two abstentions unchanged. This
  does not establish broader detection superiority.
- Smaller summary/schema responses measured against our previous serialization.
  These measurements are neither a comparison with Codex Security nor model
  billing measurements.

## Next implementation and trial

1. The independent review and demonstrated presentation corrections are
   [complete](../evidence/automatic-review-independent-2026-10-01.md). Integrate
   the exact qualified implementation before installing a new candidate.
2. Qualify one real externally exported SARIF result in the existing importer.
   The current candidate projection keeps the message and severity but does not
   expose source locations, code flows or upstream fingerprints as structured
   investigation data; the retained document is hashed. Identify which evidence
   is necessary before implementing a narrowly scoped investigation projection.
   Imported validation labels must never create a SecureFlow human decision.
3. Reuse the same authorized revision, retained report and accepted findings in
   two walkthroughs: the maintainer's current workflow and SecureFlow-assisted
   review. Keep scan quality separate from review effort. A model-generated
   fixture or our own use is a development check, not external adoption evidence.
4. Ask three maintainers to complete the bounded workflow on source they are
   authorized to review. No new target scan is authorized by this plan. Retain
   their explicit permission and count observed behavior rather than interest.

Record time to inspect the first useful finding, hands-on setup/triage time,
missing source or reproduction evidence, scope/identity mistakes, and whether
the maintainer elects to use the workflow again on a later revision. Record model
input, cached input and output separately only when the provider supplies them;
do not infer charges from JSON byte size or missing measurements.

Proposed continuation gate: at least two of three maintainers independently
complete the workflow and choose to reuse it, with a concrete observed benefit
over their previous process. This is an exploratory product decision threshold,
not statistical proof. If the workflow only adds setup and clicks, simplify or
reduce SecureFlow to the useful components rather than expanding its platform.

## Defer

Decompilation, arbitrary binary formats, a competing general-purpose security
model, additional dashboards/providers, broad new vulnerability rules, remote
reconnaissance, automatic patch application and speculative enterprise features.
Only add a detector rule after a source-backed false-positive or missed-case
reproduction identifies a bounded need. Preserve the existing manual, assisted
and automatic modes over the same case contracts.
