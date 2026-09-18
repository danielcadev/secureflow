# SecureFlow 1.0 execution plan

## Decision record

SecureFlow Core is an additive, local-first `secureflow-security-case-v1`
boundary. Existing `secureflow-run-v1` and `secureflow-run-v2` remain valid
run artifacts; adapters retain their current contracts. A Security Case binds
one authorized target and exact revision to source evidence, candidates, and
human-only decisions. It does not declare a scanner, imported heuristic, or
agent recommendation to be a vulnerability.

The v1 implementation intentionally has no provider transport, target-network
transport, crawling, exploitation, or patch execution. MCP is stdio JSON-RPC
only, and exposes no final-decision method.

## Gates and acceptance tests

1. **Universal Security Case** — Add a strict versioned structural schema and
   local semantic validator. A case must bind authorization, target hash,
   revision, source provenance, evidence hashes, candidate class, and decisions.
   Tests reject unknown fields, unbound sources, bad hashes, and non-human
   decisions. Schema conformance alone is not semantic acceptance.
2. **Manual-first workflow** — Add CLI create, inspect, import, list, decide,
   validate, and export commands. Tests prove a decision is derived from the
   input, requires a named human, and does not mutate it. Review Room loads
   the same JSON contract rather than a fixture.
3. **Secure Skill integration** — Import a validated contextual envelope into
   the case with its method/version/hash provenance. Tests retain contextual
   classification and reject an attempt to call it an engine rule or final
   finding.
4. **Agent bridge** — Provide a local stdio MCP server with `read_case`,
   `investigate_candidate`, and `stage_recommendation`; recommendations are
   separate staged records. Tests assert no tool definition or dispatch path
   can record a human decision.
5. **Ecosystem/CI** — Add minimal SARIF 2.1.0 import/export. Imported SARIF
   results are external-tool candidates, never validated findings. The CLI is
   non-interactive; CI must use `case-validate` for semantic acceptance, with
   JSON Schema validation limited to structural interoperability checks.
6. **Qualification** — Publish migration/compatibility notes, update the
   threat model, add a reproducible offline demo and RC readiness receipt.
   Run focused Rust tests, formatting, clippy, Review Room lint/build, and
   dependency audit where available. These are qualification evidence only,
   not publication or production-readiness approval.

## Implementation sequence

1. Define `schemas/secureflow-security-case-v1.schema.json` and a compact
   `secureflow-case` crate with fail-closed parsing, hashing, derivation, and
   SARIF conversion.
2. Wire the crate into the existing CLI and adapt Secure Skill envelopes via
   the existing validated importer.
3. Add the stdio bridge binary; its write capability is deliberately limited
   to a separate staging file.
4. Replace Review Room's synthetic candidate loading with local file import
   and exports that retain the original case contract.
5. Execute qualification, write `docs/evidence/secureflow-v1-rc-readiness.md`,
   and maintain `docs/evidence/secureflow-v1-checkpoint.md` as the continuation
   receipt.

## Compatibility and migration

No legacy artifact is rewritten. `case-create --run-manifest` creates an
additive Security Case referencing the validated run. Existing review commands
continue to write derived run manifests. A v1 case can hold run candidates,
Secure Skill contextual candidates, SARIF external-tool candidates, and staged
agent recommendations in distinct fields. Only `case-decide` can append a
final decision, and it requires an explicit human reviewer and rationale.
