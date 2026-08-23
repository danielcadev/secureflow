# `secureflow-catalog-backup-v1` contract

`catalog-backup` uses SQLite's online backup API, writes to a private temporary
file, verifies `quick_check` and foreign keys, and publishes through a hardlink
without overwriting. The manifest binds SHA-256, byte size, schema, application
ID, statistics, snapshots, and canonicalization state.

`catalog-backup-verify` recomputes hashes and integrity checks.
`catalog-restore` starts only from a verified backup and creates a new database
and manifest. An interrupted process never publishes a final database under
the requested name.
