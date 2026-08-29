# `secureflow-secure-review-v1` contract

## Purpose

This contract imports a Secure Skill `review-contract` 1.1 JSON output as a
local contextual assessment and binds it to an already authorized
`secureflow-run-v1` or `secureflow-run-v2`. It does not turn its findings into confirmed
vulnerabilities.

The normative schema is
[`schemas/secureflow-secure-review-v1.schema.json`](../../schemas/secureflow-secure-review-v1.schema.json).

## Decision boundary

Every envelope contains these constants:

```json
{
  "semantics": {
    "imported_findings_are": "contextual-candidates",
    "validation_authority": "human-only",
    "no_findings_mean_safe": false
  }
}
```

Therefore:

- `verification_status: verified` describes the imported review's declared
  state; it is not equivalent to `human_review.decision: validated`.
- A `non_finding` neither counts as a vulnerability nor proves safety.
- Zero findings does not mean the target is clean.
- Future inclusion in the knowledge base requires a human decision through a
  separate workflow.

## Provenance

The importer does not execute Secure Skill. With size limits, it reads only
four canonical files within the supplied root:

- `package.json` for name, version, and declared license;
- `skills/secure/SKILL.md`;
- `skills/secure/references/review-contract.json`;
- `LICENSE`.

It records the supplied commit, SHA-256 values for the Skill, contract,
license, and payload, plus the `run_id` and target hash. Resolved paths must
remain within the root to prevent symlink escapes.

The baseline inspected on 2026-08-23 was Secure Skill 2.0.0 at commit
`e6e80b264007cd33f0dac3efe19f57658cc27b1f`, contract 1.1, under MIT. Hashes are
recomputed for every import; this historical reference does not replace that
verification. When the source root contains `.git`, the adapter also requires
the declared revision to match `HEAD`. For a snapshot without `.git`, the
revision remains operator-declared and retained file hashes fix the content.

## Limits

- The payload is limited to 16 MiB and remains local.
- Known objects and enums are validated strictly; unknown fields fail closed.
- Scope and location paths must be relative and contain neither `..` nor
  Windows separators.
- `fix` requires the payload to declare explicit authorization and remediation;
  importing it neither authorizes nor executes changes.
- `threat-model` requires the `threat_model` object.
- The payload may contain sensitive fragments in `evidence`; it must not be
  sent to a remote provider or imported into the ledger without redaction and a
  human decision.

## CLI

```bash
cargo run -p secureflow -- secure-review-import \
  --review /path/review.json \
  --manifest /path/secureflow-run.json \
  --secure-skill-root /path/secure-skill \
  --secure-skill-revision <full-commit> \
  --output /path/contextual-review.json

cargo run -p secureflow -- secure-review-validate \
  /path/contextual-review.json

cargo run -p secureflow -- secure-review-list \
  /path/contextual-review.json --format json
```
