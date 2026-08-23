# Contrato `secureflow-advisory-delta-v1`

## Propósito

Procesar cambios recientes de un `modified_id.csv` **por ecosistema** de OSV
sin volver a normalizar un ZIP completo y sin convertir ausencias en borrados.
La adquisición ocurre fuera del parser. El manifest conserva índice, revisión,
hash, cursor, payloads, fuentes, licencias, cuarentena y snapshot base.

La documentación oficial de OSV define cada fila como
`<modified RFC3339>,<ID>`, ordenada de más reciente a más antigua. Es una lista
de registros nuevos/modificados, no un inventario completo.

## Preparación

`delta-prepare-osv` exige:

- el índice per-ecosystem adquirido y su locator/generación/ETag;
- un directorio plano con exactamente un `<ID>.json` por fila posterior al
  cursor exclusivo;
- igualdad temporal entre la fila y `record.modified`;
- ecosistema, ID primario, fuente y licencia admitidos por la misma política de
  snapshots;
- un snapshot completo base y, salvo el primer delta, el ID del delta anterior;
- timestamp de adquisición no anterior al cambio más reciente.

El índice completo se retiene. Cada archivo termina en `records/` o
`quarantine/`, usa permisos privados y queda ligado por SHA-256. Un payload
faltante causa error; nunca significa baja. Cualquier cuarentena conserva la
evidencia pero bloquea la aplicación y el avance del cursor.

## Aplicación al catálogo v3

`catalog-import-delta`:

1. revalida el manifest, índice y todos los archivos;
2. migra una copia writable v2→v3 de forma transaccional cuando procede;
3. exige que el snapshot base siga siendo la foto completa más reciente;
4. exige una cadena lineal mediante `previous_delta_id` y cursor contiguo;
5. rechaza forks, timestamps antiguos y contenido distinto con el mismo
   `modified`;
6. conserva cada revisión raw y actualiza FTS por fila en la misma transacción;
7. reconcilia conteos por fuente y sólo entonces marca el delta `complete`.

Un replay de un delta completo verifica cada hash contra `delta_records` y no
reaplica estado histórico. Una interrupción entre lotes deja `preparing`; el
mismo manifest puede continuar idempotentemente. Un delta diferente no puede
adelantarlo. La recuperación destructiva se hace desde un backup verificado,
no borrando filas manualmente.

La reanudación por lotes no equivale a una transacción atómica de extremo a
extremo: los lotes ya confirmados existen físicamente mientras el delta sigue
`preparing`. Durante ese estado, las consultas de advisories, la procedencia,
los backups y los trabajos no relacionados fallan de forma conservadora; sólo
se permiten diagnóstico de integridad/conteos y reanudar el manifest exacto.
Un consumidor que abra SQLite por fuera de la API de SecureFlow debe imponer
la misma barrera y nunca presentar el estado parcial como un cursor válido.

## Semántica de bajas

- `absence_deactivates_record=false` siempre;
- un registro con `withdrawn` es un upsert explícito y se retiene con estado
  withdrawn para trazabilidad;
- sólo un snapshot completo posterior puede desactivar registros que ya no
  aparecen en una fuente completa;
- ni un modelo ni una heurística infieren borrados.

`withdrawn` tampoco demuestra que un finding concreto sea falso o verdadero.

## Compatibilidad y límites

- schema SQLite writable actual: v3;
- catálogos/backups v2 permanecen verificables read-only; la primera escritura
  migra una copia o base autorizada;
- máximo 256 MiB por índice, 1,1 millones de filas y 4 MiB por payload aceptado;
- sólo formato per-ecosystem en v1; el índice global con prefijos no se acepta;
- no hay downloader dentro de SecureFlow ni polling automático;
- `validation_authority=human-only`.

## Evidencia actual

Las pruebas cubren payload faltante, tampering, cuarentena, `withdrawn`, replay,
interrupción/reanudación, fork y snapshot antiguo. En el catálogo real copiado
de 229.644 registros, la migración v2→v3 conservó conteos y pasó integridad. Un
replay solapado oficial de siete RUSTSEC quedó completo sin inserts/updates ni
bajas; esto prueba el pipeline y su idempotencia, no la llegada de siete
vulnerabilidades nuevas.
