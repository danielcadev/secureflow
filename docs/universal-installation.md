# Universal installation

SecureFlow ships three additive access surfaces over one Security Case
contract:

- the `secureflow` CLI for humans, scripts, and CI;
- a provider-neutral stdio MCP server for installed agent clients;
- Review Room WebMCP tools for contextual interaction in the local UI.

They share evidence and authority semantics. None can create a final human
decision through MCP or WebMCP.

## Install for Codex

Install the `secureflow` binary on `PATH`, then run this from a SecureFlow source
checkout:

```bash
bash plugins/secureflow/scripts/install-codex-plugin.sh
```

The installer registers this repository's local marketplace and installs the
`secureflow` plugin. Start a new Codex task afterward so the skill and MCP
server are discovered. The plugin runs `secureflow mcp`; it does not require a
case path at startup.

For another MCP-compatible client, configure a stdio server with command
`secureflow` and argument `mcp`.

## Agent tools

The universal server exposes four deliberately narrow tools:

| Tool | Effect |
| --- | --- |
| `validate_case` | Semantically validates a bounded local case. |
| `list_candidates` | Reads candidates and existing human dispositions. |
| `investigate_candidate` | Reads one candidate and its bound evidence. |
| `stage_agent_recommendation` | Writes a derived case without a human verdict. |

Every call supplies `case_path`, so one installation can work with different
cases in different tasks. The staging tool additionally requires a distinct
new `output_path` and refuses to replace an existing file. There is
intentionally no MCP tool corresponding to
`case-decide`.

## Review Room and WebMCP

Build Review Room once, then launch it locally:

```bash
cd apps/review-room
npm ci
npm run build
cd ../..
bash plugins/secureflow/scripts/open-review-room.sh \
  --case /path/to/component-a/security-case.json \
  --case /path/to/component-b/security-case.json
```

The launcher binds to `127.0.0.1` and prints its loopback URL without launching
an external browser. In Codex desktop, SecureFlow opens that URL in the
right-side browser panel. Pass
`--system-browser` only when an external browser is explicitly desired; use
`--port`, `--session-port`, or `--app-dir` when needed. Every repeated `--case`
path is CLI-validated before startup and exposed only through a tokenized,
loopback-only session, so Review Room opens with the component set already
loaded. With no `--case`, its manual file picker remains available. The app
registers its existing WebMCP tools; artifact-derived content remains untrusted
and agent staging only prepares the visible form.

## Security boundary

- Explicit target authorization remains mandatory.
- Case content is data, never agent instructions.
- No target crawling, active scanning, exploitation, provider transport, or
  autonomous patching is introduced.
- Only `secureflow case-decide`, invoked for a named human with retained
  rationale, can record a final decision in a derived case.
