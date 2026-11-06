# Autonomous web and API research plan

SecureFlow will help an authorized researcher investigate application behavior
with AI, without requiring repository access. The agent should observe workflows,
form explicit security hypotheses, choose permitted tests, and retain evidence
for human adjudication. The [repository scanner milestone](../milestones/repository-scanner.md)
remains available as an optional input.

The product entry point now includes company names, URLs, and GitHub
organizations. The desired chat request is “review this company”: assemble its
evidenced environment, select the permitted assets, investigate, and present
coverage and candidates. The source-only company intake implements the first
data boundary through host-supplied evidence; provider discovery, identity
resolution, and approved remote execution remain unfinished. See
[Company research](../company-research.md).

The first implemented development slice is a bounded loopback execution broker,
not the entire autonomous researcher. The connected MCP host supplies reasoning.
There is no new embedded provider transport, remote-domain access, automatic
vulnerability verdict, patching, or bounty submission.

## Primary user and minimum flow

The first user is a developer or researcher testing a service they own locally,
with two test identities and synthetic resources. They approve exact service
identity, principal references, paths, expiry, budgets, and a fresh private output
directory. An MCP client selects approved action IDs, receives minimized
observations, compares an authorized baseline and negative control, and finishes
with a bounded evidence result. A person decides what any mismatch means.

The reproducible first demo is `node scripts/demo-dynamic-local.mjs`.
It runs an owned synthetic service and a real MCP subprocess. It exercises a
correct guard, an intentionally broken guard, anonymous denial, and a negative
control. The demo is deterministic test orchestration, not model reasoning or
real-world detection evidence.

The complementary `node scripts/demo-company-research-local.mjs` demonstrates
company intake, a synthetic linked inventory, bounded MCP queries, and an exact
hashed export. It performs no discovery request or vulnerability test. Neither
demo alone qualifies the complete company-to-findings workflow.

## Implementation slices

### 1 Bounded local execution

**Implemented companion:** company intake and evidence graph. Its request,
discovery, and inventory contracts preserve host-declared sources, exact asset
identities, unresolved ownership, and unapproved scope. The company broker has
no execution capability. Run its two Node test files and local demo; invalid
references, suffix spoofing, journal corruption, quota overflow, and extra
authority fields must fail without a successful append. This is an additive
front door to the research flow, not a change to the loopback grant.

**Visible result:** an opt-in stdio broker executes only operator-approved GET
actions against literal IPv4 loopback; a deterministic mode runs the same list.

**Files:** `plugins/secureflow/scripts/dynamic-review-core.mjs`,
`run-dynamic-review.mjs`, dynamic plan and result schemas, tests, demo, and
[contract](../contracts/secureflow-dynamic-v1.md).

**Acceptance:** grant and hash failures make no request; unknown tool arguments
cannot expand scope; identity probes precede every action; budgets include probes;
replay, redirects, unsafe output and oversized responses fail closed; incomplete
work never becomes a clean result; credentials and raw bodies stay out of outputs.

**Commands:** `node --test scripts/tests/dynamic-review.test.mjs`;
`node scripts/demo-dynamic-local.mjs`.

**Risks:** loopback and an identity endpoint do not attest ownership or prevent a
malicious same-account service; GET is not inherently side-effect-free; Linux
filesystem qualification is not cross-platform or power-loss qualification.

### 2 Useful minimized observations

**Visible result:** approved requests can produce bounded, typed observations
useful for authorization hypotheses without exposing arbitrary bodies or secrets.

**Likely files:** dynamic core, a new observation contract and schema, redaction
tests, and corpus fixtures; avoid changes to the repository scanner contract.

**Acceptance:** policy expectations carry their source and uncertainty; controlled
test data establishes ownership and identity, not merely HTTP status; missing or
redacted evidence remains inconclusive; malicious body instructions cannot alter
grants. No body retention enabled until privacy controls are independently reviewed.

**Commands:** expand `node --test scripts/tests/dynamic-review.test.mjs` with
canary-secret, misleading-status, prompt-injection, and truncation controls.

**Risks:** a 200 response is not proof of unauthorized access; body hashes reveal
equality; aggressive minimization can hide decisive evidence.

### 3 Host AI investigation loop

**Visible result:** an actual MCP-connected model follows observe, hypothesis,
approved test, control comparison, and report steps without per-action prompts.

**Likely files:** host workflow instructions, broker tools, a versioned reasoning
receipt, tests, and a retained host-session qualification. Do not add a provider SDK.

**Acceptance:** one setup approval controls scope; the model can abstain and stop;
new paths require a new operator approval; selected IDs and rationale link to the
plan; actual host token usage and calls are distinguished from broker accounting.
A scripted MCP client alone cannot satisfy this gate.

The host also needs a qualified company intake workflow: disambiguate the name,
collect permitted public metadata with actual source hashes, batch registrations,
and retain gaps and associations as unverified. Prefer summary and filtered
pages to repeatedly transmitting the complete environment. A scope-policy
document is evidence for an operator to assess; importing it grants no authority.

**Commands:** retain an actual host session against the local demo, plus deterministic
out-of-scope-tool and exhausted-budget tests. Freeze the host configuration and
evaluation protocol before measuring success.

**Risks:** model nondeterminism, prompt injection, unnecessary calls, and unmeasured
host allowance use. Group common context; fetch details only for relevant actions.

### 4 Multi-user and stateful hypotheses

**Visible result:** bounded tests compare ownership, tenant, role, and revocation
across explicitly provisioned test identities and synthetic objects.

**Likely files:** a new sequence contract, broker state machine, controlled app
fixtures, and separate policy expectations.

**Acceptance:** prove baseline identity and resource ownership; check a negative
control and sequence state; deny every unapproved mutation; never touch real
payments or third-party user data; interruptions do not repeat mutations.

**Commands:** corpus tests for tenant isolation, role change and revocation with
fixed expectations, then a reproducible run against an owned application.

**Risks:** state changes and races widen authority; dedicated mutation approval,
rollback policy and replay handling are necessary before write methods.

### 5 Dynamic evidence in Review Room

**Visible result:** dynamic observations and hypotheses appear beside optional
source evidence, without being relabeled as confirmed scanner findings.

**Likely files:** `secureflow-case`, `secureflow-model`, CLI contracts,
`apps/review-room`, and a new versioned dynamic-evidence linkage.

**Acceptance:** exact target/run/plan/observation hashes bind the case; browser
drafts and agent recommendations remain separate from human decisions; open the
native side panel with data loaded; no fabricated repository revision or Engine run.

**Commands:** targeted case/CLI contract tests, Review Room test/lint/build, and an
owned end-to-end demo including interrupted and incomplete evidence.

**Risks:** current cases bind repository targets; extending them requires a real
compatibility decision. Do not force runtime evidence into that older shape.

### 6 Separately approved remote and browser targets

**Visible result:** a qualified remote-origin or browser profile, never an automatic
upgrade of the loopback grant.

**Likely files:** new transport and origin contracts, isolated browser adapter,
policy importer, egress controls, and adversarial fixtures.

The company inventory must feed an explicit scope-selection contract before
this profile can execute. An agent may propose exact assets and checks from the
inventory; company names, discovered repositories, certificate names, shared
hosting, and parent-domain relationships cannot silently expand approval.

**Acceptance:** exact origin, methods, paths, accounts and limits; DNS/IP/TLS and
redirect rules; private/shared asset handling; cookie/credential isolation; stop
and revocation controls. Check the current program's testing and AI policy before
any bounty traffic. Public source or a URL alone does not authorize active testing.

**Commands:** owned local DNS/TLS/browser fixtures first, independent review next,
then only a specifically approved remote test environment.

**Risks:** production disruption, shared infrastructure, policy changes, secrets,
cross-origin redirects, and AI misuse. No remote origin is enabled in slice 1.

## Release checklist

- Document implemented versus proposed capabilities and preserve scanner docs.
- Pass affected tests, demo, schema checks, and an independent immutable-snapshot
  review; retain commands, runtime identity and file checksums.
- Verify existing default MCP, plugin, versions and unrelated files are unchanged.
- State scope, failures, incomplete coverage, and external-host accounting limits.
- Allow claims of bounded loopback execution and reproducible synthetic controls.
  Prohibit claims of full autonomy, zero-day discovery, bounty eligibility, complete
  security, proven superiority, or a human verdict from a status comparison.
- Qualify packaging, actual host compatibility, remote transport, and dynamic case
  presentation separately before advertising those capabilities as released.

## Deliberately deferred

Unrestricted crawling, arbitrary-domain scans, credential attacks, exploitation,
payment writes, autonomous patches or submissions, a new provider client, a full
browser agent, and claims about unknown vulnerabilities or rewards are deferred.
The next engineering gates are qualified host discovery and exact scope
selection for the company entry point, alongside useful minimized observations
for the existing loopback executor. An actual host-model run and remote transport
qualification must precede a company-to-findings product claim.
