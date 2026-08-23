# ADR 0008: cadena incremental OSV y catálogo v3

## Estado

Aceptado, 23 de agosto de 2026.

## Contexto

Reimportar ZIP completos para cada cambio es costoso. `modified_id.csv` enumera
IDs nuevos/modificados, pero no es una foto completa y por tanto la ausencia no
puede representar una eliminación. El catálogo v2 sólo conservaba snapshots.

## Decisión

- añadir `secureflow-advisory-delta-v1` sólo para índices per-ecosystem;
- exigir índice/payloads/licencias adquiridos fuera de SecureFlow y ligados por
  hash/revisión;
- encadenar cada delta a un snapshot completo y al delta anterior;
- avanzar cursor sólo si todos los payloads se aceptan y los conteos cuadran;
- tratar `withdrawn` como upsert explícito retenido;
- reservar desactivación por ausencia a snapshots completos posteriores;
- guardar deltas/records/imports en schema SQLite v3;
- mantener v2 verificable read-only y migrar sólo al abrir writable;
- mantener FTS por fila para deltas y conservar rebuild para cargas masivas o
  recovery de `dirty`.

## Consecuencias

Replay e interrupciones son idempotentes, forks/rollbacks se rechazan y las
correlaciones pueden ligar los deltas completos. Un delta `preparing` bloquea
consultas de advisories, procedencia, backups y trabajos no relacionados hasta
reanudar o recuperar un backup; los conteos e integridad siguen disponibles
para diagnóstico. Los lotes confirmados pueden existir físicamente durante la
recuperación, pero nunca forman un cursor publicable. No se ofrece un “abort”
que borre evidencia. Los ZIP completos siguen siendo necesarios para
reconciliar presencia y detectar ausencias reales.
