# SecureFlow Web v1

## Purpose

SecureFlow Web v1 builds a deterministic web API inventory for explicitly
authorized targets and compares implemented, documented, observed, and
protected routes. The first vertical supports local Next.js App Router and
Pages Router conventions.

V1 does not execute target code, open network connections, or interpret a
hidden or undocumented route as protected.

## Contracts

- `secureflow-web-scope-v1`: current authorization, allowed repositories and
  assets, limits, and offline policy.
- `secureflow-web-inventory-v1`: licensed and provenance-bound sources, routes,
  parameters, known controls, evidence, limitations, and accounting.
- `secureflow-web-inference-v1`: correlated API candidates from client code,
  manifests, and local contracts, with confidence, provenance, abstention, and
  presence state.
- `secureflow-web-assessment-v1`: candidates, hardening observations,
  abstentions, and reproducible human validations.
- `secureflow-web-case-v1`: ground truth for a synthetic or licensed case.
- `secureflow-web-lab-result-v1`: route comparison with precision, recall, F1,
  missing routes, and unexpected reports.
- `secureflow-web-development-corpus-v1`: 20–40 licensed synthetic development
  assertions with provenance and an explicit split.
- `secureflow-web-corpus-result-v1`: per-case results that block holdout,
  superiority, and production-safety claims.
- `secureflow-web-api-risk-corpus-v1`: 200 deterministic risky API scenarios
  paired with 200 safe controls across 20 security families and 10 runtime
  profiles. Variants are generated on demand with lineage-preserving IDs.
- `secureflow-web-observation-pilot-v1`: content-bound authorization, exact
  host/method/path limits, readiness blockers, and claim boundaries for a
  future low-rate production observation pilot.

Normative schemas live in `schemas/` and reject unknown fields.

## Invariants

- Authorization exists and has a reference, reviewer, and future expiration.
- `network_execution` is `disabled`; every request budget is zero.
- A deterministic tree hash binds the root before and after inventory. A
  concurrent change invalidates the run.
- Symlinks are not followed and paths outside the root are not read.
- Unknown controls are never considered safe.
- An undocumented API produces hardening guidance, not an automatic
  vulnerability.
- An inferred route always retains `classification=candidate` and
  `vulnerability_status=not-assessed`; confidence does not replace validation.
- Only same-origin paths beginning with `/` are accepted. External URLs and
  traversal never become targets. Unresolved dynamic strings remain abstained
  candidates without an executable route.
- Only an observation with reproduction evidence and a human decision can use
  `human-validated-vulnerability`.
- Human review creates a derived assessment with `parent_assessment_id`,
  preserves the previous artifact, and binds retained evidence by SHA-256
  instead of overwriting the original decision.
- Zero observations does not prove safety.
- Source, case, and result identifiers are content-bound identities. They
  detect accidental inconsistency but are not signatures and do not establish
  who produced an artifact.

## Local lab

The `tests/fixtures/web-nextjs` fixture is synthetic, contains no private APIs,
and covers App Router, Pages Router, route groups, dynamic parameters,
middleware, server actions, client calls, a retained manifest, and
OpenAPI/GraphQL/tRPC artifacts.

Tests compare actual output with `expected.json`, validate contracts, check
determinism, and verify that the target hash does not change. The
`secureflow-web-lab` binary compares a retained inventory with a case and
writes JSON and SARIF through no-overwrite creation:

```bash
cargo run -p secureflow-web --bin secureflow-web-lab -- \
  inventory.json expected.json result.json result.sarif
```

The result is a development diagnostic. Its claim fields prohibit using it as
evidence of superiority or production readiness.

The main CLI exposes the workflow without depending on helper binaries:

```bash
cargo run -p secureflow -- web-scope-create --help
cargo run -p secureflow -- web-inventory-nextjs --help
cargo run -p secureflow -- web-infer --help
cargo run -p secureflow -- web-assess --help
cargo run -p secureflow -- web-review-assessment --help
cargo run -p secureflow -- web-lab --help
cargo run -p secureflow -- web-corpus-evaluate --help
```

The versioned corpus in `tests/fixtures/web-nextjs/corpus.json` contains 24
atomic assertions about inventory, correlation, decoys, and safe semantics.
The retained run passed 24/24. This corpus is known to developers; it is neither
an independent test nor a human study.

The broader corpus in `tests/fixtures/web-api-risk-corpus/corpus.json` contains
400 canonical synthetic scenarios. It is also a known development corpus. Its
5,200–20,000 deterministic variants are not retained as duplicate records and
inherit the canonical lineage for split and deduplication checks.

Local inference consumes a sealed scope and an existing inventory. Output must
remain outside the target to preserve the authorized tree:

```bash
cargo run -p secureflow-web --bin secureflow-web-infer -- \
  /authorized/target scope.json inventory.json /evidence/inference.json
```

## Current limitations

- App Router method detection recognizes named exports without executing
  TypeScript. Pages Router methods remain unknown.
- Middleware matchers and the effective scope of server actions need deeper
  analysis.
- V1 infers from OpenAPI JSON, GraphQL schemas, simple tRPC routers, literal
  `fetch`/Axios calls, and retained Next.js manifests. OpenAPI YAML, router
  composition, aliases, dynamic strings, and authorized traffic require later
  adapters.
- `.next` is excluded from the current hash and is not read directly. Manifests
  are analyzed only when retained inside the authorized, hashed tree.
- There is no real DNS or Certificate Transparency acquisition. Future tests
  use simulated responses before any passive network adapter is considered.
- `symlink_metadata`, reading, and before/after hashing reduce concurrent-change
  risk but do not create a transactional snapshot. A local attacker able to
  swap and restore files during reads retains a TOCTOU window. Hostile targets
  require stronger filesystem isolation.
