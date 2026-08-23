# Security policy

## Supported versions

Security fixes are provided for the latest published `0.1.x` release and the
current `main` branch. Pre-release snapshots and historical local artifacts are
not supported distributions.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/danielcadev/secureflow/security/advisories/new)
and include:

- the affected commit or release;
- the smallest reproducible input or fixture that does not expose third-party
  secrets or personal data;
- the expected security invariant and observed behavior;
- whether exploitation requires a malicious target repository, local account,
  scanner binary, retained artifact, or network access;
- suggested disclosure constraints, if any.

Reports are evaluated skeptically and reproduced locally. A scanner finding is
not treated as a confirmed vulnerability until a human verifies the affected
path, preconditions, impact, and evidence.

## Authorized-use boundary

SecureFlow is designed for code and systems that you own, open-source projects,
or targets for which you have explicit authorization. The current Web module is
offline-only. Do not use this project for credential attacks, destructive
testing, secret extraction, indiscriminate crawling, or scanning third parties
without permission.

## Scope of this policy

This policy covers SecureFlow's own source, release artifacts, contracts, and
documented build process. Vulnerabilities in Secure Engine, Secure Skill,
Secure Bench, upstream advisory feeds, or analyzed applications should be
reported to their respective maintainers unless the defect is in SecureFlow's
adapter or handling of those inputs.
