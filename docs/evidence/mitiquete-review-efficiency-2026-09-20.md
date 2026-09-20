# Mitiquete review-efficiency evidence — 2026-09-20

## Scope

This receipt records the local efficiency lessons from the authorized Mitiquete
review without treating scanner candidates as vulnerabilities or transferring
one candidate's decision to another. The retained input set contains nine
component Security Cases and 53 candidates; the largest component contains 38.

## Implemented changes

- Both MCP surfaces expose an aggregate summary before candidate detail.
- Candidate listing is compact, filterable, and paginated. Universal MCP
  defaults to 25 and caps at 100; Review Room WebMCP defaults to 20 and caps at
  50.
- Candidate-key tool schemas are constant-size. They no longer embed every
  loaded candidate ID in an enum.
- Full evidence, limitations, recommendations, and decision rationales remain
  behind an explicit single-candidate investigation.
- Review Room groups identical source/title signals for navigation, while every
  decision remains candidate-specific.
- GitHub CI now runs Review Room tests, lint, build, and dependency audit.

## Reproducible byte measurements

Measurements used the retained 38-candidate `apps-web-src` case and the exact
debug binary built from this branch:

| Serialization boundary | Previous shape | New shape |
| --- | ---: | ---: |
| Candidate-key schema for the retained 53-candidate set | 2,571 bytes | 32 bytes |
| Largest-case list response | 15,585 bytes | 624-byte summary + 5,787-byte first page |

The initial summary plus first page is 6,411 bytes, 58.9% smaller than returning
the entire largest case. The constant candidate-key schema is 98.8% smaller than
the former dynamic enum for this retained set. These are serialized UTF-8 byte
measurements, not model-token counts, allowance charges, latency guarantees, or
provider billing claims.

The new flow can request a second page when needed, so total bytes approach the
full set only when the caller actually investigates the full set. Filtering by
severity, decision state, or query can reduce that further.

## False-positive lesson

Repeated patterns such as `RegExp.exec`, already-enforced authorization guards,
fixed external hosts, and internal paths should become source-backed Engine or
adapter tests before any automatic suppression is introduced. Review Room may
group equivalent-looking signals to save navigation and context, but it must not
copy a rejection, validation, or recommendation across candidate IDs. The
Mitiquete reconciliation remains evidence for future rule work, not a global
allowlist.

## Authority preserved

Summary, pagination, filtering, and grouping do not create a verdict. Only a
named human through `secureflow case-decide` records a final decision, and only
an exact authorized remediation handoff permits bounded patch preparation.
