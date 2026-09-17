# SecureFlow Review Room

SecureFlow Review Room is an agent-native security review workspace for explicitly authorized code. It loads a local `secureflow-security-case-v1` document produced by SecureFlow Core; it does not embed review fixtures or contact a target. A browser agent can inspect structured evidence, compare retained context, draft hardening guidance, and stage a recommendation. Only a person can record the final `validated`, `rejected`, or `abstained` decision through the Core CLI.

The browser's export is a local review-room audit draft, not a replacement for a Security Case or a final decision record. Use `secureflow case-decide` to create the derived, human-authoritative case artifact.

## Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

Open `http://localhost:3000` in a browser with imperative WebMCP support.

## WebMCP tools

| Tool                         | Effect                                                       |
| ---------------------------- | ------------------------------------------------------------ |
| `list_candidates`            | Reads all candidates and existing human dispositions.        |
| `inspect_evidence`           | Selects a candidate and returns its evidence boundary.       |
| `compare_revision`           | Selects a candidate and returns the supplied revision note.  |
| `draft_hardening`            | Returns evidence-bound remediation guidance.                 |
| `stage_agent_recommendation` | Prepares the visible human review form but cannot submit it. |

There is deliberately no WebMCP tool that records a final security decision.

## Verification

```bash
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

Select `/tmp/case.json` in the opening screen. The app rejects other contracts with an accessible inline error.

## License

This app is part of SecureFlow and is available under MIT OR Apache-2.0, matching the repository root licenses.
