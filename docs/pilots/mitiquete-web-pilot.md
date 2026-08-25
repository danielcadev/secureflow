# Mitiquete SecureFlow Web pilot

Status: **prepared and blocked; no production network observation executed**.

## Authorization and scope

The requesting user states that they own and authorize bounded security
observation of `https://mitiqueteonline.com`. The retained artifact binds that
assertion to the source task reference and a SHA-256 digest. This is an
auditable owner assertion, not independent proof of domain ownership.

Initial scope is deliberately narrower than the general SecureFlow Web model:

- exact apex host `mitiqueteonline.com` only;
- HTTPS port 443 only;
- no subdomains, including `www`;
- same-host redirects only, with revalidation before every hop;
- `GET`, `HEAD`, and `OPTIONS` only;
- four explicit passive paths;
- no credentials, proxy, retained response body, state-changing request, or
  authentication comparison.

## Bounded observation design

The local state machine enforces a maximum of 12 requests, three requests per
minute, one concurrent request, two redirects, a five-second timeout policy,
one MiB per response, and four MiB total. It rejects non-public DNS results and
stops on HTTP 429, two consecutive 5xx responses, scope drift, response limits,
or operator-reported unexpected behavior.

The authorization window is checked both when the plan is parsed and before
each guarded request. A not-yet-valid or expired authorization fails closed.
Marking ownership as verified also requires a bound ownership-artifact hash and
a non-pending reviewer; changing a prerequisite boolean alone is insufficient.

Only allowlisted response metadata and a body SHA-256 are retained. Cookies,
authorization headers, query strings in redirect locations, body text,
secrets, and PII are not retained.

## Blocking gates

The current artifact cannot authorize execution because this crate deliberately
has no production HTTP transport. JSON cannot enable that missing compiled
capability. The exact remaining gates are:

1. bind and independently verify an ownership artifact;
2. implement and review a bounded HTTPS transport with DNS revalidation and no
   proxy/credential path;
3. run the same workflow in staging and review the evidence;
4. provide dedicated staging test accounts before enabling any authentication,
   role, owner, or tenant comparison.

No production request should be sent until a new version removes these blockers
through code and tests, not by editing the retained JSON.
