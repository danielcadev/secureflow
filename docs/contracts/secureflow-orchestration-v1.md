# `secureflow-orchestration-v1` contract

This is a local, deterministic state machine. It orders authorization,
analysis, prioritization, optional context, optional advisory AI, human
validation, and reproducible evaluation. It runs neither network operations
nor scanners.

Supplemental artifacts are validated and linked by hash to the same run. If
pending candidates remain, the next action can only be human review or
abstention; benchmarking stays blocked. AI and context may enrich a review,
but they are never prerequisites for human review and never have validation
authority.
