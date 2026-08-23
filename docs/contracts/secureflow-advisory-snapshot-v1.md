# Contrato `secureflow-advisory-snapshot-v1`

Un snapshot es el límite reproducible entre adquisición de red y procesamiento
local. SecureFlow no descarga dentro del parser: recibe un ZIP OSV ya adquirido
y exige locator, revisión inmutable, timestamp, hash y evidencia local de
licencia.

## Invariantes

- ZIP máximo de 512 MiB, 16 GiB descomprimidos, 1,1 millones de entradas y
  4 MiB por registro;
- rechazo de symlinks, cifrado, path traversal, nombres duplicados, archivos
  especiales y ratios de compresión mayores a 1.000:1;
- cada entrada termina exactamente en `records/` o `quarantine/`; el accounting
  debe reconciliar el total del archivo;
- raw JSON se conserva byte a byte; sólo los campos indexados normalizan
  controles de terminal;
- archivos `0600`, directorios `0700`, publicación por rename a un directorio
  nuevo y validación posterior de todos los hashes;
- GHSA requiere evidencia CC-BY-4.0; RUSTSEC requiere su licencia soportada por
  registro; MAL requiere Apache-2.0 de OpenSSF y que cada objeto `affected`
  apunte al path oficial `ossf/malicious-packages/.../osv/malicious/...`;
- un registro desconocido o sin procedencia admitida se conserva en cuarentena,
  nunca desaparece ni se importa;
- `validation_authority` siempre es `human-only`.

La política v2 añade la comprobación específica de OpenSSF. El validador sigue
leyendo snapshots históricos v1 para no romper evidencia retenida.

## Ciclo del catálogo

`catalog-import-snapshot` registra primero el snapshot como `preparing`, importa
lotes idempotentes, completa cada fuente, desactiva registros ausentes en una
foto completa y finalmente marca el snapshot `complete`. Un artefacto anterior
queda bloqueado. Reprocesar el mismo hash/revisión/timestamp con otra política
sí está permitido; un artefacto distinto con timestamp igual no.

La actualización mediante `modified_id.csv` usa ahora el contrato separado
`secureflow-advisory-delta-v1`, con cadena al snapshot base, replay, recovery y
`withdrawn` explícito. La ausencia en el índice nunca desactiva. Los ZIP
completos siguen siendo la autoridad para presencia/ausencia y reconciliación
periódica.
