# `secureflow-prospective-protocol-v1` contract

Before results are observed, this contract seals the research question,
corpus, licenses, systems, capabilities, blinding, resources, retry and crash
policy, metrics, uncertainty, and success criterion. Any modification changes
the identifier.

The technical minimum requires 20 cases (10 vulnerable and 10 controls), an
unseen holdout, hidden labels, SecureFlow, a human cohort, two adjudicators,
separate precision, recall, and time, abstentions, and publication of negative
results. This permits a task-bounded comparison while prohibiting claims of
global superiority or production safety.

The included fixture only tests the contract with synthetic hashes. It is not
a real preregistration or an executed corpus.

For real material, `benchmark-protocol-preflight` recomputes hashes for the
public corpus manifest, provenance, licenses, and environment before sealing.
The command never receives ground truth; it cannot prove that the custodian
kept labels hidden or that the declared cohort exists. That evidence remains
human and external. See the
[`prospective study runbook`](../prospective-study-runbook.md).
