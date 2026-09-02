# WebMCP Challenge submission draft

## SecureFlow Review Room

SecureFlow turns an AI security review into an auditable human-agent workflow. Instead of exposing another scanner dashboard, the Review Room gives a browser agent structured access to security candidates, source-to-sink evidence, revision context, and hardening guidance. The agent can investigate and stage a recommendation, while the human retains the only control that records a final disposition.

### Why WebMCP fits

Security dashboards contain dense, semantically important evidence that is awkward and error-prone for an agent to infer from pixels or raw DOM text. WebMCP exposes the same primary workflow as five narrow tools with explicit schemas and side-effect annotations. Read tools distinguish candidates from confirmed vulnerabilities. The one mutating tool only stages a recommendation and returns `finalized: false` and `status: awaiting_human_decision`.

### Human-agent experience

The agent lists three candidates, inspects the strongest authorization candidate, compares its revision, and drafts a hardening direction. It then stages a recommendation in the visible form. The person can disagree, edit the rationale, validate, reject, or abstain. Every agent and human action is shown in an audit trail and can be exported as JSON. There is no agent tool for the final decision.

### Implementation

The demo is a React 19/Vinext application with the imperative WebMCP API. It is local-first, uses a synthetic authorized case, performs no target requests, and requires no API key. The five tools share application state with the visible interface, register with an abortable lifecycle, validate candidate IDs, and return concise JSON. Local browser storage preserves decisions and the audit trail.

### Demonstration script (under 3 minutes)

1. **0:00–0:20 — Problem.** “Scanners produce candidates, but security decisions need context and accountability. SecureFlow Review Room lets a person and browser agent investigate together.”
2. **0:20–0:45 — Guardrails.** Show the authorized synthetic scope, offline evidence badge, three candidates, and explain that none is confirmed.
3. **0:45–1:25 — Agent reads.** Ask the agent to list candidates, inspect `AUTHZ-014`, compare its revision, and draft hardening. Show the selected evidence and source-to-sink flow.
4. **1:25–1:55 — Agent stages.** Ask it to stage the recommendation. Point out the populated rationale, `awaiting_human_decision`, and the new agent audit event.
5. **1:55–2:25 — Human decides.** Edit the rationale, choose a disposition, and press “Record human decision.” Explain that this control has no WebMCP equivalent.
6. **2:25–2:45 — Auditability.** Export the audit JSON and show agent versus human actors.
7. **2:45–2:55 — Close.** “AI investigates. Humans decide. Evidence persists.”

### Suggested agent prompt

> List the security candidates in this SecureFlow case. Inspect AUTHZ-014, compare its revision, draft a hardening recommendation, and stage your evidence-bound disposition for my review. Do not claim that it is confirmed and do not make the final decision.

### Required links before submission

- Public application: _add deployed URL_
- Public source repository: `https://github.com/danielcadev/secureflow`
- Public demo video: _add YouTube URL_
