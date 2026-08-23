# Blind prospective study runbook

Status: **prepared, not executed**. No real sealed holdout, recruited cohort, or
human results exist yet. This document does not authorize superiority claims.

## A question that can be measured

SecureFlow may aim to outperform human performance on scoped tasks, not to be
"better than every human, always." The first defensible question is:

> On a previously unseen, authorized Rust and TypeScript holdout, does
> SecureFlow improve recall and precision of validated findings per minute over
> human review without SecureFlow, under predeclared time and capability limits?

Cases in which the human performs better must also be reported. "Always" is a
universal quantifier that a finite corpus cannot establish.

## Minimum design

- Start with 20–40 cases, at least half vulnerable and half controls.
- Report Rust and TypeScript results separately.
- Predeclare families: authorization, filesystem, parser, webhook, and supply
  chain. Do not add a family after observing results.
- Recruit at least three reviewers with documented experience who did not
  create the corpus.
- Use a blocked crossover design: every case is reviewed in one human condition
  and by SecureFlow, but no person sees two equivalent variants.
- Commit the randomized order before execution and apply equal time limits.
- Use two independent adjudicators and a third for disagreements.
- Keep labels, PoCs, and expected answers outside the tree delivered to
  participants and systems.
- Publish crashes, abstentions, and negative results.

An initial result compares only that cohort, corpus, and capability set. A
replication with a more experienced cohort and a new holdout is necessary to
approach a claim such as "better than a strong expert." Comparing only with the
creator or with students who lack equivalent tools is insufficient.

## Artifact separation

```text
study-root/
├── public/
│   ├── corpus-manifest.json       # Opaque IDs, hashes, and paths; no labels
│   ├── provenance-manifest.json   # Origin, authorization, and review
│   ├── license-manifest.json      # License per case/fixture
│   └── environment-manifest.json  # Binaries, configs, resources, and network
├── private-ground-truth/          # Separate custodian; never enters preflight
├── protocol-draft.json
├── sealed-protocol.json
├── submissions/                   # Raw outputs, time, cost, and abstentions
└── adjudication/                  # Opened only after submissions close
```

The public manifest may disclose `case-0001`, its language, and its hash, but
not whether the case is vulnerable, its weakness, or the expected location.
The authorization declaration must retain the owner, scope, validity period,
and restrictions without publishing private data.

## Preflight without opening labels

After freezing a release/configuration and before execution:

```bash
cargo run -p secureflow -- benchmark-protocol-preflight \
  --draft study-root/protocol-draft.json \
  --corpus-manifest study-root/public/corpus-manifest.json \
  --provenance-manifest study-root/public/provenance-manifest.json \
  --license-manifest study-root/public/license-manifest.json \
  --environment-manifest study-root/public/environment-manifest.json \
  --output study-root/sealed-protocol.json

cargo run -p secureflow -- benchmark-protocol-validate \
  study-root/sealed-protocol.json
```

The command checks that the four real SHA-256 values match the draft and then
seals the protocol. It neither inspects nor receives the private ground truth.
The protocol must still be published or registered with an external timestamp
before results so third parties can verify the preregistration.

## Execution

1. Freeze the commit, binaries, configuration, machine, network, and budget.
2. The custodian distributes only opaque cases and retains the labels.
3. Record monotonic start/end times, crashes, authorized retries, tokens, and
   cost for each case; a timeout is not a clean result.
4. Retain raw reports and human responses by hash; do not correct outputs.
5. Close all submissions before opening labels.
6. When feasible, adjudicate evidence and exploitability without knowing which
   condition produced the finding.
7. Calculate TP/FN and FP/TN separately, paired intervals, minutes, and
   abstentions. Publish disagreements and negative cases too.

## "Better" criterion for the first replication

It must be fixed before sealing. One conservative option is to require all of:

- the lower bound of the paired recall interval above the predeclared margin;
- non-inferior precision within a small margin;
- a predeclared reduction in median analyst minutes;
- no hidden increase in crashes, abstentions, or cost;
- sensitivity analysis by language, family, and reviewer.

If any condition fails, the outcome is mixed or negative. It must not be turned
into a superiority claim by changing metrics after observing it.

## Current blockers

- The holdout must be selected and licensed without contamination from the
  public fixtures already used.
- A label custodian and real reviewers/adjudicators must be recruited.
- The exact SecureFlow and comparator configurations must be frozen.
- A prospective submission and scoring contract is missing. Secure Bench
  currently imports retained results only and must not know labels at runtime.
- Ethical treatment, consent, compensation, and participant privacy must be
  defined.
