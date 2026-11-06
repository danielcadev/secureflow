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

The installer checks that the CLI version matches the plugin manifest before
modifying the marketplace or installing. It selects the marketplace name from
the checkout's manifest, rather than assuming `personal`. An existing name
registered from a different source is not silently replaced. A separate local
candidate marketplace can be used without changing unrelated marketplaces.

The [local `1.1.0-rc.5` qualification](evidence/automatic-review-local-install-2026-10-02.md)
records one installed Linux candidate, its recoverable previous installation,
and the end-to-end checks. This is not a published or standalone UI release.

For another MCP-compatible client, configure a stdio server with command
`secureflow` and argument `mcp`.

## Agent tools

The default universal server exposes five deliberately narrow tools:

| Tool | Effect |
| --- | --- |
| `validate_case` | Semantically validates a bounded local case. |
| `summarize_candidates` | Reads compact aggregate counts before candidate detail. |
| `list_candidates` | Pages and filters compact candidates and decision state. |
| `investigate_candidate` | Reads one candidate and its bound evidence. |
| `stage_agent_recommendation` | Writes a derived case without a human verdict. |

Every call supplies `case_path`, so one installation can work with different
cases in different tasks. The staging tool additionally requires a distinct
new `output_path` and refuses to replace an existing file. There is
intentionally no MCP tool corresponding to
`case-decide`.

For an operator-scoped automatic run, see [Automatic review](automatic-review.md).
Starting MCP with an exact `--review-plan` and `--review-plan-sha256` adds three
tools for executing that plan, verifying its output, and reading one retained
Engine finding. The default installation does not gain execution permission.

The efficient default is summary → filtered page → selected investigation.
`list_candidates` defaults to 25 entries and accepts at most 100; its response
does not duplicate limitations, evidence records, or decision rationales.
`investigate_candidate` remains the explicit detail boundary. These limits
reduce repeated serialization and model context while preserving exact IDs and
human authority.

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
