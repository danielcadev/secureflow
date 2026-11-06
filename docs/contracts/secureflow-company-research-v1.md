# Company research contract v1

Status: source development implementation; local POSIX qualification. This
contract covers company/URL/organization intake and host-supplied asset metadata.
It creates no network authority, Security Case, vulnerability verdict, or
executable remote plan. The connected host supplies its own discovery and
reasoning capabilities. Provider calls and model usage outside this process
are not measured by the broker.

## Versioned documents

- [Request](../../schemas/secureflow-company-request-v1.schema.json): immutable
  UUID, canonical seed, local creation time, fixed capabilities and quotas.
- [Discovery](../../schemas/secureflow-company-discovery-v1.schema.json): source
  declarations and asset relationships supplied in each import.
- [Inventory](../../schemas/secureflow-company-inventory-v1.schema.json): merged
  identities, sources, relationships, fixed authority state, and coverage.

Schemas describe structural bounds. Runtime validation additionally enforces
canonical URLs and identities, cross-references, suffix rules, aggregate quotas,
canonical serialization, and journal integrity. Passing JSON Schema alone does
not establish an acceptable import or safe executable scope.

## Identity and provenance

Seeds are a plain company name (1–128 characters), URL (up to 2048), or GitHub
organization handle (up to 39). Company whitespace is normalized; the name never
produces a guessed domain. Organization handles and DNS names are lowercased.
The company status remains unresolved; other seed kinds remain seed-only and
unverified. No current tool promotes that status.

Sources have an ID, kind, URL, and declared SHA-256. Kinds include official-site,
scope-policy, github-metadata, certificate-transparency, dns-record, and
agent-search. A kind is a label supplied by the host, not proof of authenticity.
Source IDs can be reused only with identical canonical values. The broker
checks local bundle hashes for CLI imports; it does not fetch source bytes or
authenticate an upstream content hash. `recorded_at` is local import time,
not the time of upstream collection or proof of freshness.

Assets are domains, origins, GitHub repositories, or endpoints. Their IDs are
`sf_asset_` plus lowercase SHA-256 of `kind + "\n" + canonicalValue`. Import
merges identical assets' source IDs, relations and limitations. References must
resolve in the existing or incoming graph; source conflicts and dangling links
fail before publication. Relations are `references`, `deployed-on`, `contains`,
or `candidate-subdomain`. Only the last validates hierarchy: child and parent
must be domains, distinct, with a literal dot-boundary suffix. It does not prove
registrable-domain ownership. Other relations remain assertions by the host.

Domains use ASCII DNS labels and reject IP addresses, localhost names and
trailing dots. Origins and endpoints permit HTTPS or explicit high-port HTTP
on literal `127.0.0.1`. Query, fragment, userinfo, whitespace, backslash, alternate
IPv4 spellings and escaped control bytes are rejected. Origins must have only
a root path. Repository URLs must be exact HTTPS `github.com/owner/repo` values;
they are lowercased and reject trailing `.git`, slash and dot forms. HTTPS
private-IP references may be recorded because the broker never connects to any
address. Metadata admission is not an egress policy. Ordinary paths and plain
strings are not secret detectors; callers must minimize their evidence.

Every asset has `ownership: unverified`, `scope_status: unapproved`, and
`execution_allowed: false`. Extra authority fields are rejected. Coverage counts
only imported assets, sources and batches. Active tests, repository scans,
validated vulnerabilities, human decisions and broker provider calls remain
zero; host model usage is `not-measured`.

## Resource and response limits

| Resource | Limit |
| --- | --- |
| Batches per workspace | 64 |
| Sources per batch / workspace | 32 / 128 |
| Asset entries per batch / unique workspace identities | 100 / 512 |
| Sources per asset | 128 |
| Relations per entry / merged asset | 20 / 512 |
| Limitations per entry / merged asset | 20 / 128, 256 characters each |
| Canonical journal envelope | 65,536 bytes including metadata |
| Aggregate canonical inventory | 4 MiB |
| Inventory exports per workspace | 64 |
| List page / detail arrays | 20 identities / 20 entries per array |
| MCP input line / workspace creations per process | 65,536 bytes / 32 |

All resulting references, quotas, journal envelope size and aggregate inventory
size are checked before an append starts. CLI bundle files have a 64 KiB read
bound, while journal and MCP envelope overhead can further reduce usable
payload. List returns compact identities and counts, not full evidence arrays.
Inspect exposes total counts when details are truncated; a full local export
contains the bounded complete graph. MCP export returns a path and digest,
while CLI export also returns the inventory. These controls bound local work
and repeated context; they do not establish measured host-token savings or a
global disk quota across workspaces and process restarts.

## Storage and failure semantics

The configured existing absolute root and UUID workspace are owned by the local
UID with mode 0700. Files are owned regular files with mode 0600. Reads use
no-follow/nonblocking opens and byte bounds; directory inode checks detect
replacement. Trusted private ancestors and the local account remain assumptions.

`request.json` and `request.sha256` bind the session. Each canonical newline JSON
`batch-NNN.json` records version, workspace ID, request hash, consecutive batch
number, previous batch hash, local import timestamp, and normalized bundle.
Each method replays the journal and checks canonical bytes. Historical exports
are checked against the inventory hash at their recorded batch count. Replay
retains historical digests rather than copies of every graph generation.

Publication creates an exclusive provisional file, syncs it and the directory,
links a fresh final name, and syncs again. Failure after linking attempts to
quarantine the final under an unpublished name. Provisional hardlinks remain
as evidence on success. Writes never overwrite an existing final name. Failed
journal appends make the workspace unusable; create a fresh workspace and
re-import the retained, verified sources. An incomplete export consumes its
sequence number but grants no authority. Success requires a successful API/tool
response and matching retained final bytes; process exit alone is insufficient
for an MCP call that returned a handled error.

The intended usage is one writer per private workspace. Concurrent writers,
arbitrary filesystem failures and physical power loss are not qualified. A
hostile same-account process can rewrite a whole journal and its hashes; these
hashes provide integrity linkage, not signatures or protection from that actor.

## Host interface

The source launcher provides deterministic CLI operations and newline JSON-RPC
stdio MCP. Initialization precedes tools; tools and nested inputs use closed
contracts. Requests run serially and stdout delivery is awaited. Oversized
lines are drained and rejected; errors contain fixed codes, not stack traces or
raw input. EOF closes the process without starting background work.

Six tools prepare, register, summarize, list, inspect and export. There is no
approval, network, exploit, patch, or human-decision tool. Tool descriptions
expose this boundary. The source launcher does not change default MCP servers,
installed plugins, published versions, or the existing loopback executor.
