# `secureflow-correlation-v1` contract

This contract links one exact finding to operator-declared package context and
catalog matches by ecosystem and package name. It retains the run hash,
complete snapshots, and canonical rebuild state.

It does not evaluate version ranges, assert causality, or change the human
decision. An empty list does not prove safety, and a non-empty list does not
validate the finding. The identifier is derived from stable content rather
than the creation timestamp.
