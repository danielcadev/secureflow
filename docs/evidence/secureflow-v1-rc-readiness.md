# SecureFlow v1 RC readiness receipt

Status: implementation candidate; not production readiness, a release, or a
publication approval.

## Implemented evidence boundary

- `secureflow-security-case-v1` is additive to frozen run contracts and binds
  authorized target/revision, source provenance, evidence hashes, candidates,
  staged recommendations, and human decisions.
- CLI commands are non-interactive: `case-create`, `case-validate`,
  `case-inspect`, `case-list`, `case-import-secure-review`,
  `case-import-sarif`, `case-decide`, and `case-export-sarif`.
- Secure Skill results remain `contextual-candidate`; SARIF results remain
  `external-tool-candidate`; Secure Engine results remain `engine-candidate`.
  Validation enforces this source-to-class authority map exhaustively, and an
  `agent` source cannot originate a v1 candidate. Agent recommendations remain
  staged against an existing candidate; none of these inputs creates a
  vulnerability verdict.
- `case-mcp` is stdio-only and exposes only read, investigate, and stage.
  Staging writes a derived case and cannot record a final decision.
- Review Room loads the same versioned case JSON rather than synthetic review
  fixtures. It rejects unknown or malformed fields, invalid hashes and semantic
  references, duplicate identifiers or decisions, and invalid source authority;
  it also rejects files larger than 32 MiB before reading them. Artifact-derived
  WebMCP results are annotated as untrusted. Its browser audit is not a Core
  decision artifact.
- The standalone JSON Schema validates structural shape only. Core semantic
  acceptance and CI gating use `secureflow case-validate`; Review Room applies
  its repository-native semantic validator before rendering a local case.

## Reproducibility and qualification commands

```bash
bash scripts/demo-security-case-local.sh
PATH=/home/danielcastrillon/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin:$PATH cargo fmt --all -- --check
PATH=/home/danielcastrillon/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin:$PATH cargo clippy --workspace --all-targets --locked -- -D warnings
PATH=/home/danielcastrillon/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin:$PATH cargo test -p secureflow-case -p secureflow --test cli --locked
PATH=/home/danielcastrillon/.rustup/toolchains/1.92.0-x86_64-unknown-linux-gnu/bin:$PATH cargo test --workspace --locked
(cd apps/review-room && npm test && npm run lint && npm run build && npm audit --omit=dev)
```

These commands passed on 2026-09-17 at detached commit
`4f162ad9751466f9bc82c2fe7be7367fb954c74b` with the remediation working tree
applied. Focused CLI probes also rejected an `agent` source paired with an
`engine-candidate` and a target SHA-256 containing `g`, both with exit status 1.
Regression coverage additionally rejects malformed UTF-8 before JSON parsing,
preserves canonical Unicode, validates 4,096 indexed source/candidate pairs,
and proves that a structurally schema-valid authority mismatch is rejected by
`case-validate`.
This is local implementation evidence, not release-environment qualification.
Publication, a version tag, distribution, and any production-readiness claim
still require explicit human approval and the existing release gates.
