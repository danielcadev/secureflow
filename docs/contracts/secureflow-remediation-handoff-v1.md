# SecureFlow remediation handoff v1

`secureflow-remediation-handoff-v1` separates a reviewed security decision from
permission to edit code. Review Room can export a draft, but only
`secureflow remediation-authorize` can bind it to exact Security Case bytes,
human-validated candidate IDs, a named reviewer, and repository-relative paths.

An authorized handoff is intentionally narrow:

- every source case is identified by case ID, SHA-256, target root SHA-256, and
  revision when present;
- every selected candidate must already have a final `validated` human
  decision in that exact case;
- at least one allowed repository-relative path is required;
- merge and deployment are always false;
- prohibited actions remain explicit and travel with the artifact.

## Commands

```bash
secureflow remediation-validate /path/to/handoff-draft.json

secureflow remediation-authorize \
  --draft /path/to/handoff-draft.json \
  --case /path/to/decided-component-a.json \
  --case /path/to/decided-component-b.json \
  --reviewer "Daniel" \
  --rationale "Fix only the selected validated candidates in the listed paths." \
  --output /path/to/handoff-authorized.json
```

Authorization fails closed when a case changed, a revision differs, a candidate
is absent or not human-validated, a case is missing/extra, or output aliases an
input. The JSON Schema describes structural interoperability; the CLI performs
the semantic checks.

The artifact authorizes a bounded patch attempt and verification. It does not
assert that a patch is correct, change a candidate's decision, or authorize a
merge, release, deployment, network request, or exploitation.
