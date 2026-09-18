# SecureFlow Review Room

SecureFlow Review Room is an agent-native security review workspace for explicitly authorized code. It loads one or more local `secureflow-security-case-v1` documents produced by SecureFlow Core; it does not embed review fixtures or contact a target. A browser agent can inspect structured evidence and stage a recommendation. A person can select reviewed candidates and export a scoped `secureflow-remediation-handoff-v1` draft, but only the Core CLI can persist a final decision or authorize remediation.

The browser's export is a local review-room audit draft, not a replacement for a Security Case or a final decision record. Use `secureflow case-decide` to create the derived, human-authoritative case artifact.

## Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

From Codex desktop, open `http://localhost:3000` in the Codex side browser. The
SecureFlow skill uses this surface by default so local cases do not depend on a
Chrome extension or file-URL permission. For a manual external-browser session,
open the loopback URL yourself.

The plugin launcher can preload an explicitly validated component set:

```bash
bash plugins/secureflow/scripts/open-review-room.sh \
  --case /path/to/component-a/security-case.json \
  --case /path/to/component-b/security-case.json
```

It serves only those files through a tokenized, loopback-only session and prints
the complete URL for the Codex side browser. Without `--case`, the manual file
picker remains available.

## WebMCP tools

| Tool                         | Effect                                                       |
| ---------------------------- | ------------------------------------------------------------ |
| `list_security_cases`         | Reads exact loaded component identities and coverage.        |
| `list_candidates`             | Reads candidates and existing human dispositions.            |
| `inspect_evidence`            | Selects a candidate and returns its evidence boundary.       |
| `stage_agent_recommendation`  | Prepares the visible human review form but cannot submit it. |
| `prepare_remediation_handoff` | Reads the selection and reports the required next gate.      |

There is deliberately no WebMCP tool that records a final security decision,
authorizes remediation, or edits code.

## Verification

```bash
npm test
npm run lint
npm run build
npm audit --omit=dev
```

The WebMCP integration mirrors the loaded case state: valid read and stage calls
change the visible draft only, and an invalid candidate ID fails without
recording a decision.

## Evidence boundary

Review Room shows a workflow contract, not scanner accuracy or autonomous
vulnerability validation. Loaded findings remain candidates and its display of
confidence is not a vulnerability verdict. SecureFlow must abstain when the
available evidence does not justify a conclusion.

## Load a case

```bash
secureflow case-create --run-manifest /path/to/run.json --output /tmp/case.json
secureflow case-validate /tmp/case.json
```

Select one case or a set of component case files in the opening screen. The app
rejects duplicate identities and other contracts with an accessible inline error.
It decodes bounded local bytes as strict UTF-8 and applies semantic validation;
the standalone JSON Schema is a structural interoperability check, not a
replacement for `secureflow case-validate`.

After persisting selected `validated` decisions with `case-decide`, export a fix
handoff from Review Room and authorize it with the exact decided case files:

```bash
secureflow remediation-authorize \
  --draft /path/to/handoff-draft.json \
  --case /path/to/decided-case.json \
  --reviewer "Your name" \
  --rationale "Fix only the selected candidates in the listed paths." \
  --output /path/to/handoff-authorized.json
```

## License

This app is part of SecureFlow and is available under MIT OR Apache-2.0, matching the repository root licenses.
