# Unified Review Room milestone

## Outcome

SecureFlow now connects the review and remediation boundaries without making
either autonomous. A maintainer can load several component Security Cases,
review manually or with WebMCP assistance, select validated candidates, scope
allowed paths, export a remediation draft, and have SecureFlow authorize that
draft only against exact decided cases.

## End-to-end path

1. Produce and validate one or more authorized local Security Cases.
2. Load the component set in Review Room. Component coverage stays visible and
   never implies complete repository coverage.
3. Inspect manually or let WebMCP stage a provisional recommendation.
4. Save browser review drafts, then persist the chosen final decisions with
   `secureflow case-decide` and a named reviewer.
5. Select only validated candidates, list allowed repository-relative paths,
   and export a remediation handoff draft.
6. Run `secureflow remediation-authorize` with every exact decided case.
7. Give the authorized handoff to an agent. The SecureFlow skill limits edits
   to that selection, requires tests and re-scan evidence, and leaves merge and
   deployment to the user.

## Implemented slices

- Multi-case Review Room with collision-safe case/candidate identities.
- Manual and agent-assisted review modes with a visible authority distinction.
- Component-aware WebMCP tools for listing, evidence inspection, staging, and
  reading the human remediation selection.
- Versioned remediation handoff schema and semantic Rust validator.
- CLI authorization bound to exact case hashes, target identity, revision, and
  final human validation.
- Updated SecureFlow skill routing for bounded fix execution.

## Deliberately deferred

- autonomous verdicts, patching, merge, deploy, release, or publication;
- remote target traffic, crawling, exploitation, and provider transport;
- browser-side final decisions or browser-side remediation authorization;
- claims of full-monorepo coverage from component cases;
- automatic patch application inside Review Room.
