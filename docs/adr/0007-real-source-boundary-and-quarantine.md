# ADR 0007: Separate acquisition, per-source licensing, and quarantine

## Decision

The network boundary ends before the parser. Each snapshot retains the ZIP,
revision, and hash. SecureFlow accepts only identifier families covered by an
explicit policy and license evidence. Everything else is retained in quarantine
with a stable reason.

OSV is a transport and aggregation format, not a global license. GitHub
Advisory Database, RustSec, and OpenSSF Malicious Packages remain distinct
sources even when they appear in the same ecosystem ZIP.

## Consequences

- The exact accepted input can be reconstructed and audited.
- Policy changes remain visible and reproducible.
- The accepted count may be much smaller than the ZIP count; that is expected.
- A feed containing 227k records does not justify calling them 227k
  vulnerabilities.
- Incremental updates remain blocked until deletion semantics and recovery are
  equivalent to a complete snapshot.
