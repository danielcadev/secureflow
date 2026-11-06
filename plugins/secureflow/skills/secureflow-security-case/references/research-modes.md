# Research modes at the final project handoff

The default SecureFlow MCP server handles local Security Cases. The source
checkout also includes two separate Node stdio servers. Check for the actual
scripts before using them; they are not added automatically to an existing
host configuration. Node 22 and private local evidence directories are required.

## Company and URL inventory

Use `plugins/secureflow/scripts/run-company-research.mjs --help` in the matching
checkout. Create an existing private root with `mktemp -d`, then start the
script with `--workspace-root <absolute-root> --mcp` or use its CLI equivalents.
It accepts company, URL, and GitHub-organization seeds and exposes six tools:
prepare, register discovery, summarize, list, inspect, and export.

The host must collect public metadata using its available authorized tools.
The inventory server performs no search, DNS, certificate-provider lookup,
repository clone, or HTTP fetch. Source hashes are host declarations: retain
the actual public bytes and hash them, or state that verified source evidence
is unavailable. Do not invent asset associations or choose an ambiguous company
identity silently. Do not import secrets, raw private responses, or URL tokens.

Register bounded batches, summarize first, request filtered pages of at most
20 assets, and inspect selected IDs. Export the inventory with its SHA-256.
All assets retain unverified ownership, unapproved scope, and disabled execution.
Describe untested assets and source gaps. The export is not an executable grant.

## Explicit runtime grants

Use `plugins/secureflow/scripts/run-dynamic-review.mjs --help`. Execution requires
the exact preexisting operator-approved plan and its byte SHA-256 at startup:
`--plan <absolute-file> --plan-sha256 <sha256> --mcp`. Never infer an operator
identity, approval reference, owned target, credentials or testing permission
from a company name or inventory. Existing explicit approval of the exact scope
is sufficient; do not ask for it again.

Version 1 is the qualified owned-loopback profile. It permits only approved GET
action IDs, verifies the pinned service-identity body before each action, and
enforces expiry, request, time and response bounds. Use the describe tool, select
approved action IDs, compare observations and negative controls, and finish the
run. Require a successful `finish_dynamic_run` tool response and matching retained
result; exit zero alone does not establish MCP success. A mismatch is a lead,
not a vulnerability or human decision.

Version 2 is an experimental HTTPS profile in the source tree. It requires a
separate explicit remote grant, exact origin, approved public IPv4 addresses,
inventory digest and asset ID. It pins DNS answers, TLS hostname and certificate
verification and refuses redirects. The final handoff tests its transport guards
with mocked dependencies; it does not qualify real remote targets or a complete
company investigation. Do not silently upgrade a version 1 grant or advertise
version 2 as a production-ready scanner.

No automatic public-provider collector, company-to-grant bridge, model-driven
research campaign, browser executor, dynamic-to-case import, autonomous patching
or disclosure is delivered. Report those limits when relevant instead of
substituting fabricated evidence or silently falling back to another workflow.
