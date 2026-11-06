# Repository scanner milestone

The completed scanner remains an optional SecureFlow evidence source after the
product pivot to AI-directed web and API research. This record preserves what
was built; it does not claim perfect coverage or novel vulnerability discovery.

## Implemented capabilities

- Authorized local Rust CLI and bounded Secure Engine adapter with required
  sandboxing, hashed reports, run manifests, and explicit failure states.
- Security Cases, SARIF import and export, contextual-review imports, human-only
  decisions, scoped remediation handoffs, and closure checks.
- Default read, investigate, and stage MCP tools; separately approved unattended
  component analysis and a launcher that loads verified cases in Review Room.
- Offline web inventory and supply-chain correlation with separate provenance.
  These profiles execute no target programs and contact no target domains.

The original scope is retained in [Repository scanner MVP](../mvp.md).
Implementation and commands are documented in [Automatic review](../automatic-review.md)
and [Architecture](../architecture.md).

## Retained evidence

[Local installation qualification](../evidence/automatic-review-local-install-2026-10-02.md)
records the local `1.1.0-rc.5` candidate, 249 Rust tests, ten launcher tests,
four installer tests, formatting, Clippy, and installed end-to-end controls.
Those are historical results, not fresh tests of the new dynamic broker.

The [Juice Shop trial](../evidence/github-juice-shop-trial-2026-10-02.md) returned
three pending candidates in selected source roots of an intentionally vulnerable
training app. Source validation did not establish three exploitable findings.
The [Uptime Kuma trial](../evidence/github-uptime-kuma-trial-2026-10-02.md) returned
zero candidates across 27 selected files of a real project. Neither result
establishes complete coverage, precision, recall, or production safety.

## Preservation boundary

No scanner command, installed plugin, existing case, version, tag, or release is
removed by the dynamic slice. Dynamic observations have their own contract and
must not be imported as fabricated Engine evidence or human decisions.
