# Diagnosis: SecureFlow Recon / API Exposure

## Decision

Recon/API Exposure belongs in SecureFlow, but it **must not yet become a
general network scanner**. The first boundary is implemented as
`secureflow-web`: it produces a traceable inventory, local inference, and a
coverage matrix without turning a discovered route into a vulnerability.

The first offline increment exists. Passive subdomain discovery and HTTP checks
first require a verifiable authorization contract, protection against scope
escape, and a local benchmark. "The user supplied `--authorized`" is not enough
evidence to automate traffic against third parties.

## Implemented state on 2026-08-23

- `secureflow-web-scope-v1` with authorization, expiration, hashes, and network
  budgets fixed at zero;
- App Router and Pages Router inventory, middleware, and server actions;
- inference from literal `fetch`/Axios calls, OpenAPI JSON, retained Next.js
  manifests, GraphQL schemas, and simple tRPC routers;
- route comparison and a conservative control matrix;
- JSON/SARIF output, content-bound identifiers, and file/byte/route limits;
- a synthetic fixture with six routes and 24 reproducible development
  assertions explicitly marked as non-holdout;
- integration with the main CLI and hash-linked orchestration plan.

DNS/CT, crawling, HTTP traffic, OpenAPI YAML, complete AST analysis, real
HAR/logs, and automatic vulnerability validation are not implemented.

## Proposed workflow

```text
authorization + versioned allowlist
              │
              ▼
offline collectors ──► normalized inventory ──► coverage/auth matrix
  Next.js                 declared                 declared/documented/
  OpenAPI                 documented               observed/expected
  tRPC/GraphQL            observed                        │
  owner HAR/logs                                         ▼
                                                optional safe checks
                                                         │
Secure Engine ──► inventory/coverage ──► Secure Skill ──► human ──► Bench
```

The four classes are never silently merged:

- `declared`: extracted from code or configuration;
- `documented`: supplied OpenAPI, Swagger, or schema;
- `observed`: build manifests, HAR, or owner-provided logs;
- `expected-control`: expected method, authentication, role, tenant, cache, and
  response behavior.

Differences generate candidates such as `declared-not-documented`,
`observed-not-declared`, `missing-auth-expectation`, or
`inconsistent-tenant-control`. No difference proves exposure or exploitability.

## Scope and authorization

Before any network access, a versioned contract must fix and hash:

- owner or authorizer, authorization basis, and retained reference;
- start, expiration, and time zone;
- exact domains, allowed wildcards, IP/CIDR, ports, and protocols;
- repositories, commits, and environments (`local`, `staging`, and production
  only when explicitly included);
- allowed HTTP methods, synthetic identities, and test data;
- prohibited actions, maximum RPS, concurrency, bytes, and duration;
- redirect, DNS, proxy, and external-provider policy;
- emergency contact and stop rules.

Every DNS resolution and redirect must be revalidated against the allowlist to
prevent rebinding or transitions to out-of-scope SaaS. Wildcard DNS, shared
CDNs, and third-party subdomains are recorded as ambiguous and are not probed by
default. Expiration or missing evidence stops the phase. Initial mode is
`offline/passive`; network access requires a separate opt-in and per-request
logging.

## Next.js inventory

The local collector can analyze without executing the target:

- `app/**/page.*`, `layout.*`, `route.*`, `default.*`, and relevant metadata;
- `pages/**` and `pages/api/**`;
- dynamic and catch-all segments, route groups, parallel routes, and
  intercepting routes;
- `middleware.*`, matchers, rewrites, redirects, `basePath`, and i18n;
- method exports in route handlers and nearby authentication patterns;
- supplied build manifests (`routes-manifest`, pages/app build manifests) with
  the Next.js version retained;
- server actions as invocable capabilities, **not** as automatically inferred
  stable HTTP endpoints.

Internal manifests change across versions; a parser must abstain on an unknown
format. Inventory runs no builds, plugins, imports, or repository scripts.
Routes such as `/admin` only raise review priority; their names do not imply
privacy or vulnerability.

## API inventory

Separate adapters may import:

- OpenAPI/Swagger while retaining version, servers, security schemes, and
  operation;
- tRPC routers and middleware/procedures from AST or supplied metadata;
- GraphQL schemas and resolvers from code or already supplied introspection;
- Next.js handlers and other explicitly supported frameworks;
- owner-provided HAR/logs after redaction, size bounds, and license/privacy
  review.

Remote GraphQL introspection, crawling, and Certificate Transparency use the
network; they are not "offline passive." They must remain behind the scope gate,
respect terms, and be independently disabled per source. Cookies,
authorization headers, tokens, complete bodies, and secrets are never stored;
only minimized fields, hashes, and redacted evidence are retained.

## Future safe checks

MVP checks run only against loopback fixtures. A later remote environment may
consider:

- CORS/cache headers and content types;
- verbose errors with redacted patterns;
- responses exceeding a schema or field allowlist;
- status or schema differences between authorized synthetic identities;
- an endpoint expected to require authentication responding without identity;
- tenant isolation using owner-provided synthetic accounts and data.

Even a `GET` can have side effects. Methods, bodies, parameters, and credentials
that were not preauthorized will not be sent. Exploitation, credential
stuffing, mass enumeration, secret extraction, real-data downloads, active
bypass, and destructive tests are prohibited. Responses are bounded, redacted,
and hashed. A signal is validated only through human-reviewed evidence.

## Data and storage

Asset inventory must not be mixed with public advisories or the human-decision
ledger. It requires a separate local store with TTL and sensitivity level. An
API fixture should contain at least:

| Field | Purpose |
| --- | --- |
| framework/version | parser and expected compatibility |
| language, method, route pattern | declared identity |
| origin | code, build, specification, or owner traffic |
| auth, roles, tenant | expected controls |
| safe/vulnerable control | private benchmark label |
| request fixture | synthetic, bounded, and non-secret |
| expected status/schema/fields | predeclared oracle |
| evidence locations | lines, manifest, or redacted exchange |
| provenance/license | permitted use and redistribution |

Priority goes to original synthetic fixtures and clearly licensed projects.
Private endpoints, real HAR files, and third-party corpora must not be copied
into a public database.

## Realistic 2–4 week MVP

1. Authorization/allowlist contract and inventory schema without network use.
2. Next.js parser for a versioned subset: App Router, Pages Router, route
   handlers, middleware, and known manifests.
3. OpenAPI 3.x import and `route × method × auth × role × tenant` matrix.
4. Declared/documented/observed set comparison with abstention on ambiguity.
5. 20–40 local safe/vulnerable fixtures with licenses and separate ground truth.
6. HTTP checks only against a loopback fixture server, with fixed RPS, timeout,
   bytes, and methods.
7. Secure Skill envelope and human decision; nothing validates itself.
8. Secure Bench adapter for inventory and candidate recall/precision, time,
   abstentions, and operational failures.

Remote subdomains, generic crawling, browser automation, remote GraphQL, and
validation with real multi-tenant accounts remain outside the first MVP.

## Measuring against humans

Use narrow, adjudicable tasks:

1. Enumerate real routes and methods in a frozen Next.js application.
2. Correctly complete its authentication, role, and tenant matrix.
3. Detect discrepancies across code, OpenAPI, manifests, and redacted HAR.
4. Prioritize excessive responses or endpoints missing expected controls.
5. Produce reproducible evidence per analyst minute.

Report route recall/precision, validated-discrepancy recall/precision, FP/FN,
analyst minutes, wall-clock time, abstentions, and framework coverage
separately. A blind crossover study requires a new holdout and reviewers
external to corpus creation. Beating a cohort median on these tasks does not
mean beating "the best human" or guaranteeing system security.

## Risks and advancement conditions

- legal/scope: weak authorization or shared/expired assets;
- security: SSRF, DNS rebinding, redirects, side effects, and log leakage;
- accuracy: dynamic routes, rewrites, runtime generation, and server actions;
- privacy: HAR, tokens, PII, and internal names;
- licensing: private specifications, builds, code, and CT sources;
- reproducibility: volatile builds and traffic;
- cost: unnecessary crawling and AI analysis.

The offline crate was created only after scope, fixtures, and metrics were
fixed. A separate ADR, loopback tests, and explicit review remain prerequisites
for authorizing any network adapter.
