# SecureFlow Review Room — WebMCP demo script

Target length: 2:20–2:40. The challenge requires a public YouTube video under three minutes with audio.

## Recording setup

- Record at 1920×1080 with the browser zoom at 100%.
- Use ChatGPT's in-app browser so the WebMCP interaction is visible and authentic.
- Keep the deployed Review Room and this exact prompt ready before recording:

  > Inspect AUTHZ-014, compare its revision, draft an evidence-bound hardening recommendation, and stage your recommendation. Do not make the final security decision.

- Record your microphone separately if possible. Speak naturally; do not rush to fill every second.
- Never call the candidate a confirmed vulnerability before the human decision.

## Shot-by-shot narration

### 0:00–0:15 — The problem

**On screen:** Open the deployed Review Room. Keep the candidate list and selected evidence record visible.

**Say:**

> Security scanners can produce candidates, but a candidate is not automatically a vulnerability. The difficult part is connecting evidence, understanding context, and keeping the final decision accountable.

### 0:15–0:32 — What SecureFlow is

**On screen:** Point briefly to the authorized-scope indicator, candidate queue, evidence confidence, and human-decision boundary.

**Say:**

> SecureFlow Review Room is a human-agent workspace for authorized security review. It imports structured findings, exposes only evidence-bound investigation tools to the agent, and reserves every final disposition for a human reviewer.

### 0:32–0:52 — The candidate and evidence

**On screen:** Select `AUTHZ-014`. Show the Record and Source-to-sink tabs.

**Say:**

> This candidate says a project identifier reaches a sensitive lookup. SecureFlow shows the untrusted input, the visible session guard, and the database operation. It also states the evidence boundary: static evidence cannot prove runtime reachability or exploitability.

### 0:52–1:35 — WebMCP agent workflow

**On screen:** In ChatGPT's in-app browser, send the prepared prompt. Let the agent use the page tools. Show the visible UI updating when the recommendation is staged.

**Say:**

> Instead of making the agent scrape buttons and text, the page exposes a small WebMCP interface. The agent can list candidates, inspect evidence, compare a revision, draft hardening, and stage a provisional recommendation. These tools return structured data and update the same workspace the reviewer sees.

> The agent notices that authentication is present, but no tenant predicate is visible in the lookup. It recommends validating the candidate and binding the query to the active organization. Importantly, it still cannot record the final decision.

### 1:35–2:05 — Human decision and audit trail

**On screen:** Review the staged rationale. Select Validate, adjust the rationale if needed, and click Record human decision. Scroll to the audit log.

**Say:**

> I review the evidence and decide whether to validate, reject, or abstain. I can change the agent's rationale before recording anything. The audit log separates agent actions from the human decision, so the result remains traceable rather than becoming an unreviewed AI claim.

### 2:05–2:28 — Why WebMCP matters

**On screen:** Return to the full Review Room with the validated status and audit log visible.

**Say:**

> WebMCP turns the website into a shared operating surface for a person and an agent. SecureFlow uses that capability to make security review faster without hiding uncertainty or transferring authority to the model. AI investigates, humans decide, and the evidence persists.

### 2:28–2:35 — Close

**On screen:** Hold on the SecureFlow name and deployed URL.

**Say:**

> This is SecureFlow Review Room.

## Final recording checklist

- Duration is below 3:00.
- Narration is audible and in English.
- The video shows the live deployed application, not static mockups.
- At least one WebMCP tool invocation is visibly demonstrated.
- The human decision is performed manually.
- The audit log visibly distinguishes the agent and human actions.
- Upload to YouTube as Public or Unlisted and test the link while signed out.
