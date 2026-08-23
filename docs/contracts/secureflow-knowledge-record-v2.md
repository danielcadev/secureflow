# Contrato `secureflow-knowledge-record-v2`

## Propósito

Este contrato representa una observación de seguridad con decisión humana en
el ledger JSONL local. No es una base mundial de vulnerabilidades ni convierte
un candidato en verdad por aparecer repetido.

El schema normativo está en
[`schemas/secureflow-knowledge-record-v2.schema.json`](../../schemas/secureflow-knowledge-record-v2.schema.json).
El lector conserva compatibilidad con v1; las nuevas importaciones escriben v2
y no migran ni reinterpretan registros anteriores.

## Provenance y licencia

Cada registro fija hashes del manifiesto, target y binario, la versión del
engine y, cuando existe, la revisión del target. `source_license` es una
declaración explícita del operador, no una conclusión legal de SecureFlow:

- `spdx-declared` requiere una expresión declarada y el SHA-256 de evidencia
  local, por ejemplo un archivo `LICENSE`;
- `private-or-undisclosed` expresa que el código no se está incorporando como
  corpus público;
- `unknown` conserva la incertidumbre en vez de inventar una licencia.

SecureFlow guarda el hash de la evidencia de licencia, no su contenido ni su
ruta absoluta. La expresión SPDX todavía no se resuelve ni se valida contra un
catálogo externo.

## Deduplicación trazable

`observation_fingerprint` identifica una observación exacta mediante un hash de
campos con longitudes prefijadas. Incluye el snapshot del target, nombre del
engine, regla, fingerprint upstream o finding ID, ubicaciones, invariante y
evidence path. No incluye timestamps ni la decisión humana.

Cuando otra importación produce el mismo fingerprint:

1. el nuevo registro se conserva como evidencia longitudinal;
2. `duplicate_of_record_id` apunta al primer registro v2 de esa observación;
3. decisiones humanas diferentes continúan visibles;
4. no se deduplica entre targets, engines o evidencias distintas;
5. los registros v1 no reciben fingerprints inferidos retroactivamente.

Esto es deduplicación exacta y conservadora. No demuestra equivalencia
semántica entre scanners ni entre versiones modificadas de un repositorio.

## Límites operativos

- sólo se importan findings con decisión humana terminal;
- rationale y referencia de evidencia se guardan por SHA-256;
- no se guarda código fuente;
- un ledger mayor de 128 MiB se rechaza en esta implementación;
- el writer sigue siendo único y reescribe el archivo atómicamente;
- SQLite/FTS5 permanece condicionado a mediciones y consultas reales.
