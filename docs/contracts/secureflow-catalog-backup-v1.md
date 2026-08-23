# Contrato `secureflow-catalog-backup-v1`

`catalog-backup` usa la API online de SQLite, escribe en un temporal privado,
verifica `quick_check` y claves foráneas y publica por hardlink sin overwrite.
El manifest liga SHA-256, bytes, schema, application ID, stats, snapshots y
canonicalización.

`catalog-backup-verify` rehace hashes e integridad. `catalog-restore` sólo parte
de un backup verificado y crea otra base y otro manifest nuevos. Un proceso
interrumpido no publica una base final bajo el nombre solicitado.
