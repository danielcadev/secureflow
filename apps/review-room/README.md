# SecureFlow Review Room

SecureFlow Review Room is an agent-native security review workspace for explicitly authorized code. A browser agent can inspect structured evidence, compare revisions, draft hardening guidance, and stage a recommendation. Only a person can record the final `validated`, `rejected`, or `abstained` decision.

This vertical demo uses three synthetic candidates and performs no network requests to a target. State is stored in the browser and can be exported as an audit JSON document.

## Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

Open `http://localhost:3000` in a browser with imperative WebMCP support.

## WebMCP tools

| Tool | Effect |
| --- | --- |
| `list_candidates` | Reads all candidates and existing human dispositions. |
| `inspect_evidence` | Selects a candidate and returns its evidence boundary. |
| `compare_revision` | Selects a candidate and returns the supplied revision note. |
| `draft_hardening` | Returns evidence-bound remediation guidance. |
| `stage_agent_recommendation` | Prepares the visible human review form but cannot submit it. |

There is deliberately no WebMCP tool that records a final security decision.

## Verification

```bash
npm run lint
npm run build
npm audit --omit=dev
```

The WebMCP contracts were also exercised in a supported browser: valid read and stage calls changed the same visible state as the UI, and an invalid candidate ID failed without recording a decision.

## Evidence boundary

The demo shows a workflow contract, not scanner accuracy or autonomous vulnerability validation. Its fixtures are synthetic, its findings are candidates, and its confidence values are illustrative. SecureFlow must abstain when the available evidence does not justify a conclusion.

## License

This app is part of SecureFlow and is available under MIT OR Apache-2.0, matching the repository root licenses.
