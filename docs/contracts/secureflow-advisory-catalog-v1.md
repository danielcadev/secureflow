# SecureFlow advisory catalog v1

## Propósito

Este contrato describe el catálogo SQLite local de registros públicos de
vulnerabilidades. No reemplaza el ledger JSONL de decisiones humanas: ambos
almacenes tienen autoridades y ciclos de vida distintos.

- el catálogo guarda advisories externos, versiones de origen y relaciones;
- el ledger guarda observaciones de SecureFlow que ya recibieron una decisión
  humana;
- ningún advisory externo ni coincidencia del catálogo valida un finding.

## Identidad física

- `PRAGMA application_id = 0x53464b42`;
- `PRAGMA user_version = 3` para escritura; v2 sigue verificándose read-only y
  migra transaccionalmente en la primera apertura writable;
- SQLite incluido mediante `rusqlite`, con WAL, claves foráneas y
  `trusted_schema=OFF`;
- archivo `0600` y directorios nuevos `0700` en Unix;
- los paths de base que sean symlinks se rechazan;
- una base SQLite ajena no se adopta ni modifica como catálogo SecureFlow.

## Entidades

| Tabla | Función |
| --- | --- |
| `sources` | nombre estable, expresión SPDX declarada, hash de evidencia y locator |
| `source_record_revisions` | JSON exacto, hash, fecha upstream e instante de importación |
| `source_records` | vista normalizada vigente de cada ID en cada fuente |
| `canonical_vulnerabilities` | identidad interna para un componente de alias exactos |
| `canonical_redirects` | continuidad cuando dos componentes se fusionan |
| `identifiers` | CVE, GHSA, RUSTSEC, OSV u otros IDs exactos |
| `identifier_relationships` | `primary`, `alias`, `upstream` o `related` con provenance |
| `affected_packages` | ecosistema, paquete, PURL y rangos/versiones sin expandirlos por versión |
| `advisory_references` | referencias tipadas del registro de origen |
| `source_record_fts` | índice FTS5 local de título y detalles |
| `advisory_snapshots`, `snapshot_records`, `source_snapshot_imports` | fotos completas, presencia y bajas por ausencia comprobada |
| `advisory_deltas`, `delta_records`, `source_delta_imports` | cadena incremental, replay y conteos por fuente |

## Reglas de canonicalización

1. El ID primario y los elementos de `aliases` forman aristas de equivalencia.
2. La clausura es simétrica y transitiva, de acuerdo con la semántica OSV.
3. `upstream` y `related` se conservan, pero nunca fusionan entidades.
4. Toda fusión conserva un redirect del ID canónico anterior.
5. No se usa similitud textual ni IA para fusionar registros.
6. Una corrección upstream que elimine un alias requiere
   `catalog-rebuild-canonicalization`; el rebuild desde records activos puede
   dividir componentes y conserva redirects sólo cuando no son ambiguos.

## Ingestión

El CLI acepta un archivo OSV JSON o un árbol local de archivos `.json`. Cada
feed requiere:

- `source_name`;
- `source_license_expression`;
- un artefacto local de licencia/términos cuyo SHA-256 se registra;
- `source_locator` estable.

La definición de una fuente es inmutable dentro de una base. Cambiar licencia,
evidencia o locator requiere registrar otra fuente o una migración explícita.
Los archivos de entrada nunca se modifican.

Límites actuales:

- 4 MiB por registro OSV;
- 1.100.000 archivos por invocación CLI;
- 1.024 relaciones de identificadores por registro;
- 4.096 paquetes afectados y 4.096 referencias por registro;
- 100.000 versiones enumeradas por entrada afectada;
- profundidad de directorio de entrada máxima de 64;
- lotes máximos de 50.000 registros o 64 MiB.

En carga masiva, FTS queda marcado `dirty` mientras se normalizan los lotes. La
búsqueda textual falla cerrada hasta completar `rebuild_search_index`; búsquedas
exactas y por paquete no dependen de FTS. `catalog-rebuild-index` permite
recuperar una importación interrumpida. Los deltas mantienen FTS por fila en la
misma transacción de cada lote y no reconstruyen el índice completo. Si un
delta queda `preparing`, todas las consultas de advisories y procedencia fallan
cerradas hasta reanudar el manifest exacto o restaurar un backup verificado;
`catalog-stats` y `catalog-check` permanecen disponibles para diagnóstico.

## Consultas

- `catalog-lookup`: identificador exacto;
- `catalog-search`: frase literal sobre título/detalles mediante FTS5;
- `catalog-package`: ecosistema y nombre exactos;
- `correlate-package --version`: evaluación exacta/SEMVER conservadora con
  estados affected/not-affected/unknown/not-evaluated;
- `catalog-stats`: conteos lógicos y tamaño físico;
- `catalog-check`: `quick_check`, claves foráneas y estado FTS.

Toda salida declara `validation_authority=human-only`. Una coincidencia sólo es
contexto para priorizar o investigar.

## Compatibilidad OSV

El parser consume los campos necesarios y tolera campos adicionales para
mantener compatibilidad hacia adelante. Los rangos y versiones se conservan
como JSON acotado; no se expande cada versión a una fila. Correlación v2
interpreta sólo listas exactas y rangos `SEMVER` válidos; `GIT`, `ECOSYSTEM` o
datos ambiguos producen `unknown`.

El formato no descarga fuentes ni infiere su licencia. Snapshots y deltas
verifican términos, conteos, hashes y rechazos. La ausencia en
`modified_id.csv` nunca borra; consulte
[`secureflow-advisory-delta-v1`](./secureflow-advisory-delta-v1.md).
