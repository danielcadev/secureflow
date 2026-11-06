# Local dynamic research walkthrough

This source-only development slice demonstrates a real MCP subprocess executing
approved HTTP checks against a synthetic service it owns. It does not require an
application repository, add a model provider, contact a domain, or modify the
installed SecureFlow plugin.

## Run the controlled demo

From this development checkout, with Node 22 on Linux:

```sh
node scripts/demo-dynamic-local.mjs
```

The harness starts a synthetic loopback service, writes a private fresh grant,
and calls the broker through MCP. It retains plan, hash, journals, observations,
result and demo qualification in a fresh temporary directory, printed at the
end. Only the harness's own child and service are closed; existing Review Room
sessions are untouched.

Two provisioned users and an anonymous principal exercise an authorized baseline,
a correct cross-user denial, anonymous denial, an intentionally broken guard,
and a corrected negative control. Expected statuses are operator-supplied policy
expectations. Observed mismatch is not a validated vulnerability. No contextual
model reasoning or real-world discovery is exercised.

Fresh timestamps and ephemeral ports mean different runs do not have identical
plan or result hashes. Each run is verifiable against its own exact plan hash;
repeatability means the same controlled outcome pattern, not byte-identical
network captures or a reconstruction of arbitrary service state.

## Use the broker with an owned local fixture

An operator must independently approve the service, identity endpoint, principal
references, exact paths, safe GET behavior, time and request budgets, and private
fresh output directory. Do not reuse the demo's expired grant for another target.

```sh
sha256sum /absolute/private/approved-plan.json
node plugins/secureflow/scripts/run-dynamic-review.mjs \
  --plan /absolute/private/approved-plan.json \
  --plan-sha256 <exact-plan-sha256> --mcp
```

The host must pass credential variables in its private environment, not tool
arguments, source, command-line values, or prompts. Select approved action IDs
with `execute_authorized_dynamic_action`; inspect compact observations and use
`finish_dynamic_run`. Without `--mcp` the runner executes all approved IDs in
order; this is automation without AI.

The [contract](contracts/secureflow-dynamic-v1.md) and plan schema define the full
grant. There is no install-once dynamic integration yet. The existing installed
skill and default MCP retain their offline source/case behavior.

## Checks and limitations

```sh
node --test scripts/tests/dynamic-review.test.mjs \
  scripts/tests/auto-review-launcher.test.mjs \
  scripts/tests/plugin-installation.test.mjs
```

Tests cover the new boundary, not full security coverage of a service.
Status-only evidence cannot distinguish sensitive data from an error page, prove
resource ownership, or establish impact. Service identity is not attestation;
GETs can have side effects; same-account local processes and trusted filesystem
ancestors remain assumptions. A failed or partial run is not clean evidence.

Next work is minimized policy-bound observations, an actual host-model loop,
stateful hypotheses, proper dynamic Security Cases and Review Room presentation,
and a separately qualified remote/browser profile. See the
[execution plan](plans/autonomous-web-api.md).
