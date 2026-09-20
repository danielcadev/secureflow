# Remediation closure v1

`secureflow remediation-check` is a read-only pre-commit gate. It reconciles
every candidate in the supplied cases with recorded human decisions, an optional
authorized handoff, exact patch files, and retained local evidence. It never
records or changes a human decision. A passing result means `ready_for_review`;
it grants no permission to commit, merge, publish, deploy, or contact targets.

## Authority and outcomes

Permission to investigate or fix a set of candidates is not a declaration that
each candidate is a vulnerability. Stage the investigation first, then retain
the person's explicit dispositions and their reference. Do not infer a reviewer
identity from Git configuration. Existing approval of an exact disposition table
can be used without requesting it again.

| Outcome | Required evidence and authority |
| --- | --- |
| `fixed` | Recorded `validated` decision, selection in an authorized handoff, nonempty linked patch paths, source-review and regression-test artifacts. |
| `no_change` | Recorded `rejected` decision, source-review artifact, no patch paths and no handoff selection. |
| `blocked` | An unresolved problem; any partial patch still needs handoff authorization. The gate stays incomplete. |
| `pending_review` | A proposal or contradictory earlier verdict awaiting human review; no patch paths. The gate stays incomplete. |

The gate rejects closing a `validated` candidate as `no_change`. A prior bulk
validation followed by a false-positive recommendation is a contradiction to
resolve, not permission to rewrite decisions. Preserve original and erroneous
artifacts, prepare a reconciliation from the originals, and record corrected
dispositions only when the person explicitly chooses them.

Counts are candidate counts. A disappearing scanner signal is not proof of
security impact or successful remediation. A single fix can affect several
signals. Retained source analysis and regression evidence must explain each
candidate; `rescan` evidence alone cannot satisfy `fixed`.

## Invocation

```bash
secureflow remediation-check \
  --report /local/evidence/closure.json \
  --case /local/evidence/component-a.decided.json \
  --case /local/evidence/component-b.decided.json \
  --handoff /local/evidence/handoff.authorized.json \
  --repository /local/isolated-checkout \
  --evidence-root /local/evidence
```

Repeat `--case` for every case covered by the review, including cases without
candidates. Omit `--handoff` when there is no patch or fixed outcome. The report
must cover all supplied cases and every candidate exactly once. Cases selected
by the handoff must be present with exactly the bytes, target identity, revision,
and human-validated decisions that the handoff binds.

The checkout must be at `base_commit` before committing. The gate compares the
complete staged/unstaged diff against HEAD plus nonignored untracked files with
the report's exact file inventory. Every changed file must be inside handoff
scope and linked to an authorized candidate. It checks resulting file contents,
executable mode, deletions, and the hashes of all referenced evidence files.
Symlink and submodule patches are unsupported. Evidence stays outside the
checkout. The gate executes Git inspection only, never commands from the report.

Run in an isolated checkout. Record pre-edit status; do not copy all user changes
under an allowed directory. When a working-tree case needs uncommitted input,
retain an exact baseline snapshot and its provenance rather than mixing a partial
copy into the patch. The caller remains responsible for proving that this
baseline is the scanned target: this gate checks the case/handoff binding and
checkout commit, but does not reconstruct historical working-tree fingerprints.

## Report format

The JSON uses `secureflow-remediation-closure-v1`; unknown fields are rejected.
The illustrative report below uses placeholder IDs and hashes that must be
replaced with exact retained identities. The structural schema is
`schemas/secureflow-remediation-closure-v1.schema.json`; the CLI additionally
enforces references, human decisions, scope, and filesystem checks.

```json
{
  "contract_version": "secureflow-remediation-closure-v1",
  "base_commit": "<full Git commit ID>",
  "cases": [{
    "case_id": "<case ID>",
    "case_sha256": "<SHA-256 of exact case file>",
    "outcomes": [{
      "candidate_id": "<candidate ID>",
      "outcome": "fixed",
      "rationale": "Describe the confirmed boundary, change, and regression coverage.",
      "evidence": [
        {"path": "source-review.md", "sha256": "<hash>", "kind": "source_review"},
        {"path": "regression.log", "sha256": "<hash>", "kind": "regression_test"}
      ],
      "changed_paths": ["src/auth.rs", "src/auth.test.rs"]
    }]
  }],
  "files": [
    {"path": "src/auth.rs", "mode": "100644", "sha256": "<resulting file hash>"},
    {"path": "src/auth.test.rs", "mode": "100644", "sha256": "<resulting file hash>"}
  ],
  "checks": [{
    "name": "regression suite",
    "passed": true,
    "evidence": {"path": "regression.log", "sha256": "<hash>", "kind": "regression_test"}
  }]
}
```

File modes are `100644`, `100755`, or `000000` with `sha256: null` for a deletion.
Artifact paths are relative to `--evidence-root`; patch paths are relative to the
checkout. Paths cannot contain traversal, control characters, or `.git` segments.

Record applicable test, lint, typecheck, baseline comparison, rescan, and review
results in `checks`. A failed global check remains failed even if pre-existing;
retain baseline evidence alongside it. The CLI returns nonzero for incomplete
closure, including empty checks, any failed check, or unresolved candidates.

## Trust and limits

This is a consistency and integrity gate, not an independent security verdict.
Artifact hashes prove which evidence was used, not that its contents or a declared
passing check are true. The operator selects the applicable checks; the gate does
not discover omitted tests or verify the semantic relevance of a file labeled as
related. It cannot authenticate the person behind a CLI invocation or prevent an
agent with unrestricted filesystem access from fabricating JSON. Human review
and agent instruction boundaries remain necessary.

Filesystem mode verification currently targets Unix. Use trusted private
ancestors with no concurrent writers: the check is not a sandbox or a guarantee
against local filesystem races. Re-run after any patch, case, or evidence change.
Ignored files are outside the Git inventory and must not be force-added afterwards.
