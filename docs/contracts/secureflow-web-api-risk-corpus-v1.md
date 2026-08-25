# SecureFlow Web API Risk Corpus v1

## Purpose

This contract defines a deterministic, synthetic development corpus for API
exposure analysis. It is separate from the 24-case Next.js regression corpus.
The canonical artifact contains 200 risky scenarios and 200 paired safe
controls generated from 20 security families across 10 runtime profiles.

The corpus is known to developers. It is not an independent holdout, does not
describe vulnerabilities in a real target, and cannot support a claim of human
superiority or production safety.

## Pairing and coverage

Every pair shares the framework, route, method, expected controls, and expected
decision. The risky member intentionally violates the expected decision; the
safe member enforces it. Every scenario records:

- framework, runtime, route surface, method, and normalized route;
- actor, authentication state, role, and tenant relation;
- attacker-controlled parameters and sensitivity;
- expected controls and expected versus fixture behavior;
- synthetic evidence, provenance, SPDX license, template, and profile;
- pair identity and counterpart scenario identity;
- synthetic ground truth and an automated-output ceiling of candidate or
  hardening.

## Deterministic scale without stored duplication

Only 400 canonical scenarios are retained. Variants are generated on demand
from a canonical fingerprint and variant index. Thirteen variants per scenario
produce 5,200 descriptors; fifty produce 20,000. Variant identity includes the
canonical fingerprint, index, route mutation, and generated aliases.

Variant descriptors are evaluation inputs, not new canonical knowledge. They
must not be inserted as independent corpus records or allowed to cross a
train/development/holdout boundary without their canonical lineage.

## Holdout gate

This development corpus sets `known_to_developers=true`,
`holdout_eligible=false`, and `independent_holdout=false`. A genuine holdout
must be curated independently after this corpus is frozen, use disjoint
lineage groups, keep labels hidden from systems and reviewers as required by
the prospective protocol, and be admitted by hash commitment before opening.

## Generation

```bash
cargo run -p secureflow-web --bin secureflow-web-risk-corpus -- \
  tests/fixtures/web-api-risk-corpus/LICENSE \
  tests/fixtures/web-api-risk-corpus/corpus.json
```

The output uses create-new semantics and will not overwrite an existing corpus.
