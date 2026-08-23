# `secureflow-correlation-v2` contract

V2 preserves v1's exact finding–ecosystem–package link and adds a conservative
evaluation of an installed version against retained OSV data.

## Result per advisory

- `affected`: an exact match in `affected.versions` or membership in a valid
  OSV `SEMVER` range;
- `not-affected`: all supported data excludes the version and no unsupported
  information could contradict that result;
- `unknown`: invalid version, invalid JSON or events, missing data, or
  `ECOSYSTEM`/`GIT` ranges that SecureFlow cannot evaluate locally;
- `not-evaluated`: no version was provided.

`fixed` boundaries are exclusive, `last_affected` boundaries are inclusive,
`introduced: 0` represents the beginning, and SemVer precedence ignores build
metadata. Events must be ordered and form valid alternating intervals.
SecureFlow abstains on ambiguity instead of silently repairing data.

Each assessment preserves hashes of `ranges_json` and `versions_json` and,
when a range matches, the hash of that exact range. The summary reconciles
affected, not-affected, unknown, and not-evaluated counts.

## Authority boundary

An affected version means that the advisory declares the package and range. It
does not prove that the finding has the same cause, the dependency is
reachable, the code is exploitable, or the application is vulnerable.
Therefore:

- `version_result_validates_vulnerability=false`;
- `causal_relationship_asserted=false`;
- `changes_human_decision=false`;
- `validation_authority=human-only`.

V1 remains valid for historical evidence; V2 is the default write format.
Provenance includes complete snapshots and, when present, complete catalog
deltas.
