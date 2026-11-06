# SecureFlow architecture

## Objective

SecureFlow is developing an AI-directed workbench for authorized web and API
security research, with source code optional. The intended agent loop is
observe, propose a scoped hypothesis, execute approved checks, compare controls,
and retain evidence for a person. This is a product objective, not an implemented
claim of autonomous vulnerability discovery.

A separate company-research intake accepts a company name, URL, or GitHub
organization. The MCP host supplies discovered metadata with source references
and declared hashes; the local broker canonicalizes asset identities, merges
provenance and relationships, and retains a replayable journal. Its six tools
prepare, register, summarize, list, inspect, and export. See the
[company contract](contracts/secureflow-company-research-v1.md).

The inventory connects domains, candidate subdomains, repositories, origins,
and endpoints. Relationships describe supplied evidence; neither ownership nor
test authorization follows from them. Company identity remains unresolved, and
the company broker has no executor or network client. Scope selection and a
qualified remote executor are separate remaining gates. The inventory cannot
be passed directly as the loopback broker's approved plan or a Security Case.

The first dynamic slice is a separate Node stdio MCP broker that permits only
preapproved GET actions against an owned literal `127.0.0.1` service. Its grant,
budgets, identity probes, and evidence are defined in the
[dynamic contract](contracts/secureflow-dynamic-v1.md). The connected MCP host
supplies reasoning; no AI provider transport is added. Network remains disabled
in the default scanner, case, catalog, and offline web profiles.

The completed repository scanner is retained as an optional input, not replaced
or reinterpreted as dynamic evidence. Its unattended analysis-to-review slice
is documented in [Automatic review](automatic-review.md) and its milestone in
[Repository scanner](milestones/repository-scanner.md).

SecureFlow lets maintainers investigate risks in software they are authorized
to examine using verifiable local data, then produce reproducible evidence for
a person to make an informed decision. It coordinates specialized tools without
turning them into one black box: every stage preserves its inputs, outputs,
hashes, limitations, and decisions.

Analysis tools and AI can propose candidates but never establish a
vulnerability or override the human decision. The durable responsibility of
SecureFlow is the trust boundary: explicit authorization and scope, reproducible
evidence and provenance, and a reviewable human handoff.

## Layers

```text
secureflow-cli
    ├── scope and authorization
    ├── local configuration
    ├── JSON/text queries for findings, ledger, and catalog
    └── review-run writes a derived manifest

secureflow-orchestrator
    ├── seven-phase state machine
    ├── hash links and a fail-closed next action
    └── optional AI, evaluation-only benchmark, and explicit abstention

secureflow-engine-adapter
    ├── Secure Engine as an external process
    ├── secure-json-v1
    ├── boundary projection for report fingerprint, graph accounting, and evidence state
    ├── timeout, process group, and bounded output
    ├── Linux memory/CPU/descriptor/core resource limits
    ├── Bubblewrap required by default: read-only root and private network
    └── binary and report provenance

secureflow-model
    ├── canonical findings
    ├── source/sink/evidence
    ├── deterministic ordering and exact per-run deduplication
    ├── human states
    └── export contracts

secureflow-secure-adapter
    ├── strict review-contract 1.1 import
    ├── Skill, contract, license, and payload hashes
    ├── link to an authorized run and target
    └── contextual candidates under human authority

secureflow-knowledge
    ├── v1-compatible JSONL v2 ledger
    ├── human decisions and repeated exact observations
    ├── separate SQLite v3 catalog for external security records
    ├── OSV snapshots, chained deltas, licensing, and quarantine
    ├── raw revisions, sources, licenses, and hashed provenance
    ├── conservative exact-alias joins; never text/AI joins
    ├── compact package ranges and query indexes
    ├── conservative finding-package-version-advisory correlation
    ├── FTS5, canonicalization, and reconstructible backups
    └── verified Zstandard distribution profiles kept outside app releases

secureflow-ai
    ├── local preparation with Luna as the logical family
    ├── minimized, redacted payloads
    ├── one call, budgets, and accounting
    ├── escalation only for ambiguity with human approval
    └── no network transport in the current MVP

secureflow-bench-adapter
    ├── Secure Bench separated from the production path
    ├── result-v2 and fingerprint validation
    ├── TP/FN by expectation and FP/TN by safe control
    ├── sealed prospective protocol with human cohort and blinding
    └── no ranking, global superiority, or production claims

secureflow-web
    ├── authorized, hashed, expiring repository scope
    ├── offline Next.js inventory without target-code execution
    ├── inference from client code, OpenAPI, manifests, tRPC, and GraphQL
    ├── control matrix with candidate and hardening observations
    ├── JSON/SARIF lab and 24-case synthetic development corpus
    └── no network, no automatic validation, and private outputs

secureflow-recon-network (proposed; not implemented)
    ├── verifiable allowlist and additional authorization before each request
    ├── DNS, redirect, and shared-asset revalidation
    ├── bounded passive acquisition and loopback-first safe checks
    └── rate limits, redaction, stop rules, and human review

dynamic-review-core.mjs (separate opt-in development broker)
    ├── exact-byte plan hash, expiring operator grant, approved action IDs
    ├── literal IPv4 loopback GET and identity probe before each action
    ├── request, response-size, cadence, timeout, and cooperative execution limits
    ├── create-new reservations, receipts, observations, and final result
    └── status/hash evidence only; no verdict, patch, provider, or remote traffic

run-dynamic-review.mjs
    ├── deterministic execution of the approved action list
    └── opt-in stdio MCP selection of the same actions by an external client
```

## Repository structure

```text
secureflow/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── mvp.md
│   ├── adr/
│   └── contracts/
├── schemas/
├── crates/
│   ├── secureflow-model/
│   ├── secureflow-engine-adapter/
│   ├── secureflow-secure-adapter/
│   ├── secureflow-bench-adapter/
│   ├── secureflow-ai/
│   ├── secureflow-knowledge/
│   ├── secureflow-orchestrator/
│   ├── secureflow-web/
│   └── secureflow-cli/
├── tests/
│   ├── contracts/
│   └── fixtures/
└── tools/
```

Additional crates should not be created until a responsibility boundary and a
test justify each one.

## Integration boundaries

- Secure Engine remains the owner of `secure-json-v1`.
- SecureFlow preserves selected Engine provenance and evidence metadata but
  does not reinterpret an Engine evidence state as human validation.
- SecureFlow alone owns the authorization scope and human-review decision in
  `secureflow-run-v2`; similarly named Engine report fields cannot override it.
- Secure Skill remains installable and usable without SecureFlow.
- Secure Skill output remains a separate contextual envelope; upstream
  `verified` is not SecureFlow human validation.
- Secure Bench does not participate in production decisions.
- The benchmark adapter only imports retained evidence; it runs no scanners and
  does not recompute historical results.
- Original projects are not copied into the monorepo.
- Initial integration uses external processes and versioned contracts.
- A future direct Rust dependency requires a separate compatibility, licensing,
  and release-cycle decision.

## Security invariants

- A target is authorized before any phase executes.
- Static analysis never executes target scripts.
- Network access is disabled by default. The separately approved dynamic
  broker permits bounded literal-loopback requests only.
- No exported path escapes the target's logical root.
- Secrets never enter an AI payload without redaction and consent.
- Human contextual judgment remains authoritative; only a human decision can
  validate a finding.
- Every retry is idempotent and preserves the previous attempt.
- An operational failure never equals a clean result.

The recon diagnosis and boundaries are documented in
[`diagnosis-recon-api-exposure.md`](./diagnosis-recon-api-exposure.md). The
offline phase already exists as `secureflow-web`. Remote traffic remains
disabled until an additional ADR, loopback tests, limits, and an independent
benchmark are approved.

SecureFlow's own assets, trust boundaries, controls, and residual risks are
maintained in [`threat-model.md`](./threat-model.md). Any new execution or
network boundary requires that document and the relevant ADR to be reviewed
before implementation. The first loopback boundary is recorded in the
[dynamic contract](contracts/secureflow-dynamic-v1.md); it does not authorize
the proposed remote recon layer.
