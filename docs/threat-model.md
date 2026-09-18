# SecureFlow threat model

Status: design baseline for SecureFlow v0.3.0.

## Security Case v1 boundary

`secureflow-security-case-v1` is local by default and binds its target hash,
authorization, revision, source provenance, evidence hashes, candidates, staged
agent recommendations, and human decisions. Inputs are untrusted until parsed
against the strict contract. References must resolve within the case; duplicate
identifiers and duplicate final decisions fail closed.

Secure Engine candidates, Secure Skill contextual candidates, and SARIF imports
remain distinct classes. Candidate authority is exhaustive and fail closed:
`secure-engine` may originate only `engine-candidate`,
`secure-skill-contextual` only `contextual-candidate`, and `external-sarif` only
`external-tool-candidate`. An `agent` source cannot originate a v1 candidate;
agent input remains a staged recommendation attached to an existing candidate.
In particular, a contextual signal, external-tool result, or agent recommendation
cannot become a Secure Engine rule or a vulnerability through import. The only
final decisions are `validated`, `rejected`, and `abstained`, recorded with a
human reviewer and rationale by `case-decide`. The MCP bridge deliberately
offers read, investigate, and stage only; it has no tool or dispatch route to
record a decision. It runs over local stdio and has no provider transport.

Review Room applies the same closed-world identifier, hash, enum, timestamp,
reference, uniqueness, decision, and candidate-authority checks before rendering
a local case. It rejects files larger than 32 MiB before reading their contents
and decodes accepted bytes as fatal UTF-8 rather than replacing malformed input.
All WebMCP tools that return or stage artifact-derived data mark that content as
untrusted. The browser audit remains a local UI artifact and is not a Core human
decision.

This document models threats to SecureFlow itself. It does not claim that
SecureFlow proves an analyzed target secure, and it does not authorize testing
of a third-party system.

## Security objectives

SecureFlow is designed to preserve these properties:

1. Analysis starts only after an operator records an authorized scope.
2. Static analysis and offline Web inventory do not execute target code or
   require network access.
3. A scanner, contextual reviewer, benchmark, catalog, or AI response cannot
   turn a candidate into a validated vulnerability. Only a recorded human
   decision can do so.
4. Failures, timeouts, malformed artifacts, unsupported data, and missing
   evidence fail closed or remain explicit unknowns; they never become a clean
   result.
5. Inputs, tool identities, outputs, configuration, limitations, and derived
   decisions remain traceable through versioned contracts and hashes.
6. Source code, secrets, private evidence, and human rationale are retained
   locally unless an operator makes a separate, explicit disclosure decision.
7. Benchmark evidence stays outside the production decision path, and
   development fixtures cannot authorize effectiveness or superiority claims.

## Protected assets

- target source, configuration, credentials, logs, and private evidence;
- authorization scope, expiry, reviewer, and target revision;
- scanner binaries, configuration, reports, and provenance;
- human decisions and the append-only reviewed-finding ledger;
- advisory snapshots, licenses, quarantine records, catalog state, and
  distribution manifests;
- benchmark labels, holdout separation, raw results, and study metadata;
- release source, dependencies, SBOM, checksums, and CI history.

## Actors and trust assumptions

| Actor or component | Assumption | Consequence if false |
| --- | --- | --- |
| Authorized operator | Controls the local account and records truthful authorization | Current CLI declarations do not cryptographically prove identity or consent |
| Target repository | May be malformed or intentionally hostile | Parsers, path handling, resource limits, and non-execution boundaries must fail closed |
| Secure Engine binary | Explicitly selected, but not intrinsically trusted by SecureFlow | It is isolated and hashed; its findings remain candidates, but a hostile binary still executes local native code inside the configured sandbox boundary |
| Imported Skill/Bench artifact | Untrusted structured input | Strict schemas, semantic validation, hashes, and separate authority domains are required |
| Advisory source | May be malformed, duplicated, withdrawn, mislabeled, or legally unusable | Source-specific license evidence, quarantine, exact aliases, and explicit unknowns are required |
| Local unprivileged user | May race or replace writable files available to that user | Private modes, no-overwrite writes, and before/after fingerprints reduce but do not eliminate local TOCTOU risk |
| AI provider | Not trusted with private source or final decisions | No transport exists in the MVP; preparation is minimized, redacted, budgeted, and disabled by default |
| Release/CI infrastructure | May be compromised or misconfigured | Pinned actions, a pinned toolchain, SBOM, and checksums improve traceability but unsigned releases do not authenticate a publisher |

The operating system kernel, the operator's account, and hardware are trusted.
Bubblewrap is defense in depth, not a virtual machine or protection from a
compromised kernel.

## Trust boundaries

### 1. Operator and authorization to orchestration

The CLI receives authorization declarations, target identity, expiry, and
reviewer identity. The current implementation validates structure and expiry,
but does not verify a legal mandate, organization identity, or signature.

### 2. Target filesystem to local parsers

Target names and bytes are attacker-controlled. SecureFlow rejects symlinks,
non-UTF-8 paths, ambiguous traversal, excessive depth, excessive file counts,
and configured size limits. Static analysis and Web inventory do not execute
package scripts, application code, build hooks, or framework loaders.

### 3. SecureFlow to Secure Engine process

SecureFlow invokes an explicit binary without a shell, clears its environment,
closes stdin, applies time and resource limits, bounds aggregate output, and on
Linux requires Bubblewrap by default with a read-only host root and private
network namespace. It validates exit semantics and the external JSON contract.
The binary and target are fingerprinted before and after execution.

These fingerprints detect observed changes but are not transactional snapshots:
a replacement that is restored between observations can evade the comparison,
and pathname execution is not equivalent to executing an already-open file
descriptor. A mutable or adversarial engine binary therefore remains a
residual local-code-execution risk. Enterprise use should select an
administrator-controlled, immutable, authenticated binary.

### 4. External artifacts to canonical contracts

Engine, Secure Skill, Secure Bench, Web, AI, snapshot, delta, backup, and bundle
artifacts cross strict JSON or SQLite boundaries. Parsers reject unknown or
incompatible fields where the contract promises closed-world validation.
Semantic checks bind identifiers, hashes, revisions, counts, states, and
authority. Raw upstream evidence remains separate when retaining it is
necessary for auditability.

### 5. Human decision to knowledge and reports

Review creates a derived manifest instead of mutating the original run. Only a
human decision can use `validated`; upstream or model terminology cannot
override it. Local artifacts use private permissions where supported, and
derived commands reject input/output aliasing, including Unix hardlinks.
There remains a local race between path validation and creation, so sensitive
enterprise deployments should use a private directory on a trusted local
filesystem.

### 6. Catalog acquisition to local knowledge

External records require declared provenance and source-specific license
evidence. Invalid records are quarantined and counted. Exact aliases merge
identities conservatively; text similarity and AI do not merge records.
Absence from an incremental feed never deletes an entry. Bundle hashes prove
internal consistency only; an authenticated channel or signature is still
needed to prove publisher identity.

### 7. Evaluation evidence to public claims

Benchmarks are imported through an evaluation-only adapter and cannot influence
a production verdict. A comparative claim requires a frozen prospective
protocol, hidden holdout labels, equivalent comparator conditions, a human
cohort, independent adjudication, uncertainty, costs, failures, and retained
raw evidence. Synthetic fixtures and capacity measurements are not efficacy
evidence.

## Primary abuse and failure cases

| Case | Current control | Residual risk or required next control |
| --- | --- | --- |
| Unauthorized target is analyzed | Mandatory recorded scope and explicit authorized-use policy | Operator assertion is not cryptographic proof; organizational deployments need signed approvals and policy enforcement |
| Malicious repository triggers code execution | Target code is not executed; network is disabled; paths and resources are bounded | Native parser defects and kernel/filesystem attacks remain possible; use sandboxing and isolated workers for hostile targets |
| Engine emits misleading or oversized output | Shared stdout/stderr cap, timeout, process group, rlimits, exit checks, strict import | A compromised engine can consume resources within limits or exploit host/kernel flaws |
| Compact evidence is mistaken for complete evidence | Graph scope and omitted counts are retained; explicit full-graph requests fail if the report is not full | Full graphs can be large and still reflect analyzer limitations |
| Tool output validates its own finding | Authority domains are separate; only human review validates | Reviewer quality and independence still determine final correctness |
| Secret reaches a report or model | Local-first defaults, minimized AI envelope, conservative redaction, no provider transport | Redaction is not a formal non-disclosure guarantee; future transport needs a separate security/privacy review |
| Advisory identities are over-merged | Exact alias union only; related/upstream links do not merge | Upstream aliases can still be wrong; rebuild and human correction remain necessary |
| Catalog or release artifact is substituted | SHA-256 pinning, deep verification, SBOM, clean-tree release, GitHub/Sigstore attestations for tagged release archives, and a separately dispatched publisher that rebinds the tag, build run and attempt, artifact ID and digest, and draft uploads | Artifact attestations bind workflow provenance but do not sign the Git tag, prove source safety, or establish cross-host binary reproducibility; catalog manifests still need separately authenticated publisher signatures and key rotation |
| Benchmark leakage creates a false superiority result | Prospective sealing, holdout fields, claim gates, separate metrics | No real blinded human study has been completed yet |
| Zero findings is presented as assurance | Reports explicitly state that zero candidates is not a security guarantee | Users can still misrepresent output outside the system; public claims require review |

## Validation evidence

Controls are expected to be backed by repository-native tests or retained
artifacts. The historical MVP evidence map is preserved in
[`completion-audit.md`](./completion-audit.md), the v0.3.0 evidence and claim boundary is
tracked in [`m0.3-milestone-status.md`](./m0.3-milestone-status.md), and
publishable and prohibited claims are separated in
[`evidence-and-claims.md`](./evidence-and-claims.md).
Changes that alter a trust boundary must update this model, the relevant
contract or ADR, positive and negative tests, and the applicable versioned
evidence status.

## Explicit non-goals for the current line

- proving that any repository or system is secure;
- autonomous exploitation, credential attacks, destructive validation, or
  unrestricted remote recon;
- replacing human authorization, adjudication, or responsible disclosure;
- protecting against a compromised kernel, administrator, or hardware;
- semantic deduplication of vulnerability records without labeled evidence;
- claiming superiority over humans or competing tools before a preregistered,
  independently adjudicated study;
- treating one million synthetic source records as one million real or
  validated vulnerabilities.

## Review triggers

Re-review this threat model before adding network transport, AI provider calls,
target-code execution, plugins, multi-user or remote services, automated
patching, signed authorization, catalog publication, or a new contract major
version. Those changes create new trust boundaries and are outside the current
stabilization scope.

## Offline catalog distribution

The [catalog trust contract](catalog-trust-contract.md) adds an explicit publisher
root boundary around untrusted transport bytes. Authenticated parent links bind
metadata, exact manifest bytes and the existing bounded database verifier. Role
separation/quorum prevents a single root or targets signer from authorizing a
release; consecutive dual-quorum root transitions preserve authority changes.
Retained role/parent/application floors and time reject known replay, equivocation
and expiry. Mutating imports retain valid conservative progress on later failure;
installation commits a pending journal before no-overwrite publication.

An attacker controlling media can still withhold updates or force refusal. A
trusted publisher can sign false advisory data or a very high sequence; signatures
do not establish truth or permit a hidden reset. Whole-store rollback, malicious
local account/administrator, incorrect operator time and storage that lies about
fsync are outside the local protocol's assurance. Historic receipts never become
permanent current acceptance. Real custody, independent review and physical
power-loss qualification remain separate from synthetic automated tests.
