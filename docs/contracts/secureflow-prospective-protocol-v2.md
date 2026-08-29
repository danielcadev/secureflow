# Prospective study contracts v2

SecureFlow v2 separates three hash-bound contracts:

- `secureflow-prospective-dataset-v1` freezes a label-free authorized dataset,
  exact case hashes, split/lineage accounting, provenance, licenses,
  authorization, ground-truth commitment, and anti-leakage declarations;
- `secureflow-prospective-protocol-v2` binds the exact dataset bytes, equivalent
  SecureFlow-assisted-human and human-comparator lanes, randomization,
  environment, capabilities, outcomes, metrics, blinding, and preregistered
  success policy before execution; and
- `secureflow-prospective-submission-v1` binds one pseudonymous participant,
  lane, case, outcome, raw artifact, timeline, and resource measurement while
  keeping every finding pending independent adjudication.

The semantic validators are stricter than schema shape alone. They verify
content-derived identifiers, exact SHA-256 bindings, authorization chronology,
balanced minimum holdout accounting, lineage-disjoint splits, equivalent lane
controls, holdout-only prospective submissions, mutually exclusive outcomes,
zero retries, and permanent prohibitions on global superiority, human
replacement, and production-safety claims.

The six-case repository fixture is a known synthetic contract test. Its holdout
is known to the authors, so its contracts permanently set `fixture_only=true`,
`independent_holdout=false`, and `comparison_eligible=false`. It tests parsing,
hashing, tamper rejection, and CLI behavior; it supplies no effectiveness or
human-comparison result.

The contracts do not prove that labels were honestly withheld, participants or
adjudicators are independent, consent exists, or declared cohorts performed the
work. They do not execute a study, open ground truth, score submissions, or
declare a winner. See the [study runbook](../prospective-study-runbook.md) for
the required human and operational controls.
