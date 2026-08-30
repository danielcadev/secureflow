# Blind prospective study runbook

Status: **contracts implemented; real study not executed**. No independent
holdout has been frozen, no cohort has been recruited, no labels have been
opened, and no comparative result exists. The bundled six-case corpus is a
known synthetic contract fixture and is permanently ineligible for comparison
claims.

The v2 contracts make a future study auditable. They do not execute either
lane, adjudicate findings, calculate a winner, or prove that a human commitment
was honestly made.

## Research question and claim boundary

The first defensible question is task-bounded:

> On a previously unseen, explicitly authorized Rust and TypeScript holdout,
> does a SecureFlow-assisted human cohort improve validated recall and analyst
> time without reducing precision beyond a preregistered margin, compared with
> a human cohort without SecureFlow under equivalent capabilities?

A finite study cannot establish that SecureFlow is globally, always, or
universally better than humans. It cannot support human replacement or
production-safety claims. A task-bounded comparison remains `not-established`
when the protocol is sealed and is only eligible for later consideration after
independent blinded adjudication, the preregistered criterion, uncertainty
analysis, and publication of negative and mixed results.

## Roles that must be independent

- A corpus custodian holds ground truth and the identity of any private source.
- At least three participants per lane did not author the evaluated cases.
- At least two primary adjudicators are independent from corpus authors and
  SecureFlow developers; a third independent adjudicator resolves retained
  disagreements.
- The person operating the study cannot silently edit submissions, retry a
  failed case, or open labels early.

Participant identity is represented only by a pseudonymous SHA-256 commitment.
The mapping and consent record stay outside publishable submissions. A hash is
an integrity commitment, not proof that the participant, consent, independence,
or experience declaration is genuine; those remain externally auditable human
evidence.

## Minimum real holdout

- At least 20 opaque holdout cases: at least 10 vulnerable cases and 10 safe
  controls, with one principal security invariant per case.
- Rust and TypeScript results reported separately.
- Predeclared families such as authorization, filesystem, parsers, webhooks,
  and supply chain; no post-result family selection.
- Lineage-disjoint development, validation, and holdout splits, plus a retained
  overlap audit against the complete historical SecureFlow/Engine inventory.
- Labels, PoCs, weakness names, expected locations, and repairs absent from all
  bytes supplied to participants or either lane.
- Equivalent non-treatment tools, case bytes, time limits, environment class,
  network policy, and access policy. SecureFlow availability is the planned
  treatment difference.
- A randomized order committed before execution. No retries under v2; a rerun
  requires a new versioned protocol.

The custodian-declared vulnerable/control counts are commitments. SecureFlow
cannot verify those counts without opening labels, so label absence and
custodian separation require external review.

## Artifact separation

```text
study-root/
├── public/
│   ├── cases/                         # opaque authorized case bytes
│   ├── dataset-draft.json             # no contract ID and no labels
│   ├── frozen-dataset.json            # exact bytes bound by later artifacts
│   ├── authorization-scope.json
│   ├── reviewer-commitment.json
│   ├── provenance.json
│   ├── licenses.json
│   ├── overlap-audit.json
│   ├── historical-inventory.json
│   ├── environment.json
│   ├── capabilities.json
│   ├── randomization-commitment.json
│   ├── secureflow-lane.json
│   └── human-lane.json
├── private-ground-truth/              # separate custodian; never passed to CLI
├── protocol-draft.json
├── sealed-protocol.json
├── raw-submissions/                    # immutable participant output bytes
├── sealed-submissions/                 # hash-bound, one case/lane/participant
└── adjudication/                       # opened only after submissions close
```

Every committed relative case path must stay beneath the case root, be a
regular non-symlink file, remain below 8 MiB, and match its SHA-256. The local
verifier rejects observed symlink components and path escapes, but ordinary
filesystem checks are not a transactional snapshot: a privileged local actor
could race pathname checks and reads. Freeze on read-only media or an immutable
snapshot when the threat model includes a hostile local operator.

## 1. Freeze the label-free dataset

```bash
cargo run -p secureflow -- benchmark-dataset-freeze \
  --draft study-root/public/dataset-draft.json \
  --case-root study-root/public \
  --authorization-scope study-root/public/authorization-scope.json \
  --reviewer-commitment study-root/public/reviewer-commitment.json \
  --provenance-manifest study-root/public/provenance.json \
  --license-manifest study-root/public/licenses.json \
  --overlap-audit study-root/public/overlap-audit.json \
  --historical-inventory study-root/public/historical-inventory.json \
  --output study-root/public/frozen-dataset.json
```

The output is no-overwrite and mode `0600` on Unix. Its content-derived
`dataset_id` binds the draft, while the protocol binds the exact serialized
dataset bytes. Validate retained bytes before protocol sealing:

```bash
cargo run -p secureflow -- benchmark-dataset-validate \
  study-root/public/frozen-dataset.json \
  --case-root study-root/public \
  --authorization-scope study-root/public/authorization-scope.json \
  --reviewer-commitment study-root/public/reviewer-commitment.json \
  --provenance-manifest study-root/public/provenance.json \
  --license-manifest study-root/public/licenses.json \
  --overlap-audit study-root/public/overlap-audit.json \
  --historical-inventory study-root/public/historical-inventory.json
```

## 2. Seal protocol v2 before execution

The draft must contain the exact dataset SHA-256 and hashes of every supplied
artifact. Both lane configurations and the randomization commitment are
verified, not merely declared.

```bash
cargo run -p secureflow -- benchmark-protocol-preflight --version v2 \
  --draft study-root/protocol-draft.json \
  --dataset-manifest study-root/public/frozen-dataset.json \
  --provenance-manifest study-root/public/provenance.json \
  --license-manifest study-root/public/licenses.json \
  --overlap-audit study-root/public/overlap-audit.json \
  --environment-manifest study-root/public/environment.json \
  --capability-manifest study-root/public/capabilities.json \
  --randomization-commitment study-root/public/randomization-commitment.json \
  --secureflow-lane-configuration study-root/public/secureflow-lane.json \
  --human-lane-configuration study-root/public/human-lane.json \
  --output study-root/sealed-protocol.json
```

Run the equivalent `benchmark-protocol-validate --version v2` command with the
sealed protocol and the same nine retained inputs immediately before execution.
The dataset must have been frozen no later than protocol sealing, the protocol
must be sealed before authorization expiry, and every submission must be
recorded between sealing and expiry. Publish or externally timestamp the exact
sealed bytes before results are observed.

Protocol v1 remains the CLI default for compatibility. New studies should pass
`--version v2` explicitly. Version-specific options fail closed instead of
being silently ignored.

## 3. Record one mutually exclusive outcome

Each participant records exactly one outcome per case and lane:

- `findings`: one or more candidates with location, evidence hash, bounded
  impact, and repair; every candidate remains pending independent adjudication;
- `no-finding`: a negative observation with hashes of its rationale and reviewed
  scope, never a statement that the case or repository is clean;
- `abstention`: insufficient evidence or another predeclared reason, counted as
  neither positive nor negative; or
- `operational-error`: timeout, crash, malformed output, resource exhaustion,
  or harness failure, never converted into `no-finding`.

Required integer telemetry includes analyst-active and wall-clock nanoseconds,
micro-USD cost, input/output tokens, and peak RSS bytes. Attempt ordinal is
exactly zero because v2 has no verifiable retry linkage. Aggregate reports must
also retain abstention and operational-error counts.

```bash
cargo run -p secureflow -- benchmark-submission-seal \
  --draft study-root/submission-draft.json \
  --protocol study-root/sealed-protocol.json \
  --dataset study-root/public/frozen-dataset.json \
  --raw-artifact study-root/raw-submissions/opaque-response.json \
  --output study-root/sealed-submissions/opaque-submission.json

cargo run -p secureflow -- benchmark-submission-validate \
  study-root/sealed-submissions/opaque-submission.json \
  --protocol study-root/sealed-protocol.json \
  --dataset study-root/public/frozen-dataset.json \
  --raw-artifact study-root/raw-submissions/opaque-response.json
```

The submission ID binds the complete draft. Validation also rebinds it to the
exact protocol, exact dataset serialization, retained raw bytes, allowed lane,
holdout-only case policy for a preregistered study, and authorization timeline.

## 4. Close, adjudicate, and report

1. Close and hash all submissions before the custodian opens labels.
2. Blind lane identity from adjudicators where feasible.
3. Validate actor control, complete source-to-sink or invariant violation,
   trust boundary, supported configuration, and reproducible impact. Scanner
   output alone is not a vulnerability.
4. Retain disagreements and the independent tie-break decision.
5. Report TP/FN, FP/TN, recall, precision, false-positive rate, active time,
   wall time, tokens, cost, RSS, abstentions, and operational errors separately
   per lane, language, family, and preregistered cohort.
6. Apply the frozen uncertainty and multiplicity methods. Do not create a
   composite winner score or choose metrics after seeing results.
7. Publish negative and mixed outcomes and all protocol deviations.

The v2 contracts deliberately stop before label opening and scoring. An
adjudication/result contract and an independently operated study are still
required before any task-bounded comparison can become evidence.
