# SecureFlow threat model

Status: historical v0.3.0 baseline with additive Security Case, automatic-review,
and opt-in loopback dynamic-research boundaries. Offline profile controls remain
unchanged; the dynamic boundary below does not enable remote-domain traffic.

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
human reviewer and rationale by `case-decide`. Both MCP entry points deliberately
offer validate/read, investigate, and stage only; neither has a tool or dispatch
route to record a decision. The install-once entry point accepts local case and
distinct staging paths per call, so the host must apply its normal local-tool
consent policy. Both run over local stdio and have no provider transport.

Review Room applies the same closed-world identifier, hash, enum, timestamp,
reference, uniqueness, decision, and candidate-authority checks before rendering
a local case. It rejects files larger than 32 MiB before reading their contents
and decodes accepted bytes as fatal UTF-8 rather than replacing malformed input.
All WebMCP tools that return or stage artifact-derived data mark that content as
untrusted. The browser audit remains a local UI artifact and is not a Core human
decision.

`secureflow-remediation-handoff-v1` adds a second, independent authority
boundary after review. A browser may export only a draft. CLI authorization
requires every exact source-case hash, target identity and revision to match,
and every selected candidate to have a final human `validated` decision.
Allowed paths must be normalized and repository-relative. The contract rejects
merge or deployment authority, so a request to patch cannot silently expand to
publication. The local operator identity is still declarative rather than
cryptographically authenticated, and an authorized coding agent can still make
an incorrect change inside the permitted path set; tests, re-scan, diff review,
and the user's separate merge decision remain required controls.

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

The development automatic-review runner adds an operator-pinned startup grant,
not ambient MCP execution permission. It fixes 1–16 explicit component roots,
their hashes, the selected Engine hash, a new external output directory,
expiration, and process/whole-run budgets. Unknown permissions, changed inputs,
path redirection, expired grants, overlapping roots, and output reuse are
rejected. The default MCP tool surface remains unchanged; the optional execution
tool accepts no replacement target, binary, command, sandbox, or output path.

Execution reuses the sandbox-required adapter. Cases are created only after
successful untruncated full-graph import. Failures preserve already completed
component artifacts but mark the run failed; interruption without a final
receipt is incomplete, never a clean result. Verification checks artifact hashes,
case/manifest/plan links, and absence of human verdicts. A hash pin is not a
signature or proof of a legal mandate. Trusted local storage and an immutable
Engine remain prerequisites; this does not solve same-account races or restored
between-check changes. Whole-run timing is cooperative across phases, not a
hard interruption deadline for filesystem reads.

No AI provider transport is added. A connected MCP client's own handling of tool
responses remains subject to that client's privacy and provider configuration.
Automatic preparation does not claim contextual investigation, vulnerability
validation, autonomous remediation, deployment, or publication.

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

## Company research intake boundary

The [company intake contract](contracts/secureflow-company-research-v1.md)
introduces metadata supplied by an MCP host. Company names, source URLs, source
hashes, and graph relationships are untrusted declarations. The broker performs
no provider lookup, DNS resolution, HTTP request, repository clone, or active
test. Every imported asset retains unverified ownership, unapproved scope, and
disabled execution. An imported scope policy cannot grant testing permission.

Closed inputs, bounded batches and graph size, canonical identities, exact
reference validation, and dot-boundary checks for candidate subdomains constrain
malformed graphs and lookalike suffixes. Public company names are not converted
into guessed domains. Query strings, fragments and URL userinfo are rejected;
plain metadata and path segments can still contain sensitive text, so callers
must supply public, minimized metadata and never credentials or raw responses.
The host must treat imported text as data and ignore embedded instructions.

Owned private POSIX directories, no-follow bounded reads, immutable hash-chained
batches, capacity preflight, and canonical replay detect malformed or changed
evidence within the documented local boundary. SHA-256 records byte identity;
it does not authenticate ownership or the declared upstream source. Trusted
ancestors and the local account remain assumptions. A same-account actor can
rewrite a complete workspace; concurrent writers and physical power loss are
not qualified. Failed appends require a new workspace rather than skipped state.

Summary and page tools limit repeated context. Full evidence exports stay local;
MCP export returns a path and digest. Limits are per workspace/process, not a
global storage or host-model token budget. Remote discovery providers, transport,
scope approval, and actual model sessions need separate qualification.

## Loopback dynamic research boundary

The [dynamic contract](contracts/secureflow-dynamic-v1.md) authorizes a separate
stdio subprocess, not the default scanner or MCP server. The operator approves
exact plan bytes, service identity, principal environment-variable names,
actions, output directory, expiry, and budgets before startup. An agent can
select an approved action ID, but cannot add paths, hosts, credentials, methods,
budgets, or evidence destinations through tool arguments.

Actors are the approving operator, the possibly mistaken or manipulated MCP
client, the owned but potentially misleading target service, and other local
processes. Protected assets are credentials, local files, action scope, request
capacity, and the distinction between observations and human decisions. The
host kernel, account, runtime, and filesystem ancestors are trusted.

| Abuse or failure | Preventive and detective controls | Residual risk |
| --- | --- | --- |
| Agent broadens network scope | Literal IPv4 loopback socket, fixed port and canonical preapproved GET paths; no DNS, proxy, redirect, or retry | Loopback is not proof of ownership; the operator must approve the specific service |
| Another service occupies the port | Anonymous identity-body hash checked before each action | Identity is an assertion, not TLS or attestation; a malicious same-account process can spoof it and there is a probe/action race |
| Target data instructs the agent to escape scope | Raw response bodies and headers are not returned; tool args cannot widen the grant | Future body observations require prompt-injection and privacy controls; client reasoning itself is outside the broker |
| Credentials leak into evidence or another host | Bearer values loaded from environment, restricted syntax, never intentionally persisted; no redirects | Environment/process memory and the trusted local service can access them; hashes reveal response equality and may disclose low-entropy facts |
| Client replays or overwhelms actions | One attempt per ID; serial dispatch; request reservations before I/O; bounded bytes, execution window, timeout, and cadence | The execution window is cooperative, not an idle-process lifetime timer; GET may have application side effects; only safe operator-approved fixture routes are qualified |
| Crash or storage failure loses execution accounting | Create-new reservations before I/O; provisional result synchronized before final publication; best-effort quarantine after publication failure; existing output rejects restart | Arbitrary disk errors can prevent quarantine; require explicit MCP finish response and matching final state, not exit zero; no resume, physical power-loss proof, or hostile same-account race protection |
| Transport failure looks like a clean review | Fatal failure closes execution; early finish is incomplete; mismatches are observations only | A completed action list does not establish coverage, exploitability, or a security verdict |

Positive and adversarial tests live in `scripts/tests/dynamic-review.test.mjs`.
The owned synthetic demo exercises a real MCP subprocess, not an actual host
model or a third-party application. Remote origin pinning, TLS, egress policy,
browser isolation, richer observations, and dynamic Security Case linkage are
separate unimplemented gates in the [execution plan](plans/autonomous-web-api.md).

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
