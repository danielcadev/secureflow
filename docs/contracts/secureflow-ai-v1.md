# AI contracts v1

## Status

SecureFlow implements local preparation and response accounting. It includes
no network client and does not claim to have called a real model.

Normative schemas:

- [`secureflow-ai-request-v1`](../../schemas/secureflow-ai-request-v1.schema.json)
- [`secureflow-ai-response-v1`](../../schemas/secureflow-ai-response-v1.schema.json)

## Redacted request

`ai-prepare` requires both `--enable-ai` and `--consent-redacted-export`.
Consent is recorded for a possible later transmission, but the command only
writes a local file and reports `transmitted=false`.

The payload includes only required finding metadata:

- rule, taxonomy, severity, and confidence;
- relative paths and source/sink coordinates;
- hop types and coordinates;
- invariant and filtered limitations.

It deliberately excludes:

- source code;
- evidence descriptions, which may contain snippets;
- rationale, identity, and all other human-review metadata;
- absolute paths.

A conservative filter replaces complete fields when it detects bearer tokens,
authorization headers, common secret assignments, URLs, email addresses, or
long tokens. Redaction reduces risk but does not prove that sensitive data is
absent; a human must inspect the JSON before transmission.

## Routing and budget

- Logical provider: `openai`.
- Default family: `luna`.
- Prompt: `secureflow-ai-triage-v1`.
- Maximum: one call per request.
- Defaults: 6,000 input tokens, 1,000 output tokens, and a 16 KiB payload.
- 700 tokens are reserved for instructions.
- UTF-8 payload bytes are used as a conservative upper bound for payload tokens,
  not as a provider-tokenizer measurement.
- Future transport must perform real tokenization and reapply limits before
  sending.

Escalation is allowed only for ambiguity, never automatically, and always
requires human approval. This contract does not select a concrete API model
identifier. `luna` is a logical family that avoids coupling the stable contract
to changing release names.

## Response and authority

A response contains an assessment, short summary, typed limitations, and token
usage. `ai-apply-response` verifies that request, payload, model, prompt, run,
target, and finding match and that usage stays within budget.

Application writes another manifest and records the request identifier, hashes,
model, assessment, and tokens. The human decision is compared before and after
and must remain identical. Even `assessment: supports` remains advisory and
cannot produce `human_review.decision: validated`.

## Commands

```bash
cargo run -p secureflow -- ai-prepare \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --enable-ai \
  --consent-redacted-export \
  --output /tmp/secureflow-ai-request.json

cargo run -p secureflow -- ai-validate-request \
  /tmp/secureflow-ai-request.json

cargo run -p secureflow -- ai-apply-response \
  --manifest /tmp/secureflow-run.json \
  --request /tmp/secureflow-ai-request.json \
  --response /tmp/secureflow-ai-response.json \
  --output /tmp/secureflow-run-with-ai.json
```

The retained demonstration preparation produced 899 bytes for an SE1006 finding
and transmitted no data. Response application was verified only with a
synthetic test response and is not reported as a Luna evaluation.
