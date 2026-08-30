# Mitiquete offline Web/API pilot for M0.3

Status: **offline inventory complete; passive staging remains blocked**.

## Measured local result

SecureFlow read the detached Mitiquete checkout at `0dfb307902ea6f20c9a2755c8af4d338536b99fd` without modifying or executing it. The sealed scope covered only `apps/web/src`, whose deterministic tree hash is `5014e23107ba4d36eaca9cc5a0ea2a5a442ac7ed648a86d140f4c638645917bf`.

The inventory saw 454 files, read 450 JavaScript or TypeScript files totaling 2,118,059 bytes, and emitted 176 framework route records: 99 API routes and 77 pages. It did not truncate and reported no inventory issue. Local inference emitted 127 unvalidated candidates: 99 implemented HTTP endpoints correlated from the inventory, 27 intentionally abstained dynamic client calls, and one tRPC-shaped signal requiring human review.

These are three different quantities:

- **176 inventory records** describe source-level framework routes.
- **127 inference candidates** correlate or conservatively retain possible API signals.
- **0 human-validated vulnerabilities** is the only current vulnerability count.

An inventory record is not proof that a route is deployed or externally exposed. An inference candidate is not proof of missing authentication, broken authorization, or any other vulnerability. All 127 remain `not-assessed`; zero validated vulnerabilities is not a clean verdict.

The aggregate, privacy-preserving evidence is [`mitiquete-offline-web-m0.3-2026-08-30.json`](../evidence/mitiquete-offline-web-m0.3-2026-08-30.json). Full route artifacts remain under ignored local `target/` storage because they contain private repository paths.

## Reproduction boundary

Use `secureflow web-scope-create`, `web-inventory-nextjs`, and `web-infer` with the exact subtree and revision. Outputs must stay outside the target checkout, the source license must remain `private-or-undisclosed`, and the target hash must match before and after the run. A changed revision, subtree, authorization, limit, or SecureFlow version requires a new evidence artifact.

No command in this pilot starts the application, loads `.env` values, opens a socket, or sends HTTP. Both source checkouts remained detached and clean after execution.

## Fail-closed passive staging plan

The next stage is a dedicated non-production environment, not the public site. Before any request, bind written authorization and independent ownership review to the exact staging host, review the bounded HTTPS transport, provision dedicated test accounts, and seal the route allowlist and stop conditions.

The initial transport is limited to `GET`, `HEAD`, and `OPTIONS`, 12 total requests, three requests per minute, one concurrent request, two same-host redirects, five seconds per request, one MiB per response, and four MiB total. It retains allowlisted metadata and body hashes only. It stops on authorization expiry, scope drift, a non-public DNS result, HTTP 429, two consecutive 5xx responses, any response-budget breach, or operator-reported unexpected behavior.

Authentication, role, object-owner, and tenant comparisons remain disabled until dedicated staging accounts and expected-control matrices are sealed. Production remains prohibited by this M0.3 plan.
