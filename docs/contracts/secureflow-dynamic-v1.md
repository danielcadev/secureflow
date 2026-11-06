# SecureFlow dynamic execution contract

This development contract defines a separately approved local execution boundary.
It does not change the installed offline skill, default MCP server, or scanner.
The schemas describe structural shape; runtime validation additionally enforces
authorization time, referential integrity, budgets, credentials and filesystem
rules. The plan is an operator assertion, not cryptographic proof of ownership.

## Startup grant

Start `plugins/secureflow/scripts/run-dynamic-review.mjs` with `--plan PATH`
and `--plan-sha256 SHA256`. The hash binds exact file bytes, not reserialized JSON.
The plan must be a regular nonsymlink file of at most 64 KiB. Every object is
closed; unknown fields are errors.

The plan version is `secureflow-dynamic-plan-v1`. Authorization names the
operator and approval reference, requires `owned_local_service: true`, and uses
real RFC3339 issue and expiry times. Future, expired, reversed, and more-than-24-hour
grants are rejected. Only literal `127.0.0.1` ports 1024 through 65535 are allowed.
An anonymous identity endpoint's exact body SHA-256 is pinned.

Each principal has an ID and either a `SECUREFLOW_DYNAMIC_[A-Z0-9_]+` environment
variable name or null for anonymous access. Values must be bounded Bearer tokens
without whitespace or CRLF; no credential value belongs in the plan. A grant
contains one to eight principals and one to 32 actions. Each unique action ID
binds a principal, canonical root-relative ASCII path, and expected HTTP status.

Paths allow only `/`, ASCII letters, digits, underscores and hyphens. Queries,
percent escapes, backslashes, dots, controls, and double slashes are rejected.
This deliberately narrow profile is not a general URL crawler.

| Budget | Accepted range |
| --- | --- |
| Maximum requests including identity probes | 2 to 64 and at least twice the number of approved actions |
| Per-request timeout | 1 to 5000 milliseconds |
| Cooperative execution window from startup | 1 to 120000 milliseconds |
| Maximum body bytes per response including identity | 1 to 65536 bytes |
| Minimum interval between request starts | 20 to 1000 milliseconds |

The output is a fresh absolute directory below an immediate parent owned by the
current account with no group/other permissions and no symlink. Existing output
is rejected; there is no resume or overwrite. Ancestors and same-account
processes are trusted. This first qualification targets Linux and Node 22.

## Network execution

The broker uses native Node HTTP and an explicitly created literal IPv4 socket.
It performs no DNS lookup, proxy routing, retries, redirect following, target-code
execution, subprocess launch, or write method. A GET can still have application
side effects: the operator must approve safe routes. Only synthetic owned fixture
routes are used in the qualification.

Before each action, an anonymous identity GET must return 200 and the pinned
body hash. Probe and action both consume budget and cadence. The probe/action
race is not prevented; the identity endpoint does not constitute attestation.

An action ID is attempted at most once. Calls are serialized. Expiry and a
monotonic execution deadline are checked before I/O and during completion. Identity,
transport, redirect, timeout, byte-limit, or budget failure stops later execution.
Invalid IDs or argument shapes cannot create network traffic.

The execution window does not terminate an idle MCP process. Passive status
reports the last recorded state; execute or finish observes elapsed expiry and
closes the run. There is no background deadline timer or idle disconnect policy.

Raw bodies and headers are neither returned to the MCP host nor retained.
Observations contain approved action/principal/path identifiers, numeric status,
body byte count and SHA-256, expected status, and `status-matched`,
`status-mismatched`, or `inconclusive`. A server error is inconclusive.
Matching status is not proof of correct authorization; mismatch is not a vulnerability.

## Evidence and finish

Create-new action and request reservation files precede I/O. Request receipts and
observations follow completion. The output retains exact `plan.json`,
`plan.sha256`, journals, and private files. Finalization first writes and
synchronizes `result.provisional.json`, then publishes a create-new hardlink
`result.json` and synchronizes the directory. The provisional file is retained
but is never a final result.

On publication failure, the broker marks its in-memory state failed and tries
to preserve an already-published inode as `result.unpublished.json` while
removing only its final-name link. Injected file and directory sync failures
are tested, but arbitrary filesystem errors can also prevent quarantine.
Neither a provisional/unpublished file nor `result.json` alone proves that
finalization succeeded. For MCP, require the actual `finish_dynamic_run`
response with `isError: false` and matching result status and final evidence;
EOF or process exit zero is not an acknowledgement of successful finalization.
Only the deterministic CLI uses exit zero to denote a completed action list.
An explicit failed or incomplete result never means completed coverage.
Physical power-loss durability is not claimed.
Restarting the same output cannot issue another request.

The result version is `secureflow-dynamic-result-v1`. It records plan hash,
approved/attempted/completed counts, request count, observations and a sanitized
failure code. `running` is transient, `completed` means every approved action
produced an observation, `incomplete` means early finish, and `failed` means a
fatal failure. Completion is not a clean security result. Lost client connections
and abrupt termination may leave only journals; no recovery is implemented.

The broker always records `human_decisions: 0`, `provider_calls: 0`,
`ai_reasoning: external-client-not-measured`, and `final_authority: human-only`.
Provider calls means calls made by the broker, not by a connected AI host.
No Security Case, human verdict, patch authority, or disclosure is synthesized.

## MCP and deterministic modes

Without `--mcp`, the script executes the approved list in order without a model.
With `--mcp`, newline-delimited JSON-RPC uses stdin/stdout, with protocol-only
stdout, serial requests, a 64 KiB line limit and strict tool arguments.
Responses wait for stdout write completion before dispatching the next request,
so a nonreading peer cannot grow an unbounded queue of responses in the broker.
There is no hard idle-output timeout; a stalled connection can remain open.

| Tool | Arguments | Authority |
| --- | --- | --- |
| `describe_authorized_dynamic_plan` | Empty object | Read grant without credential values |
| `execute_authorized_dynamic_action` | `action_id` only | One preapproved GET plus identity probe |
| `dynamic_run_status` | Empty object | Read minimized observations |
| `finish_dynamic_run` | Empty object | Close evidence with honest completion status |

The server implements a narrow MCP stdio lifecycle, not HTTP MCP, arbitrary
resources, sampling, elicitation, cancellation, or universal client compatibility.
The [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
defines newline framing and protocol-only stdout; the
[lifecycle specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
defines initialization before tool use. A subprocess test is not qualification
of every host model or client.
