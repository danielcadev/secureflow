# SecureFlow

SecureFlow es una plataforma local-first para analizar código autorizado,
priorizar señales de seguridad y ayudar a un investigador humano a validar
vulnerabilidades con evidencia reproducible.

El proyecto combina, mediante contratos versionados y procesos separados:

- Secure Engine para análisis determinista de flujos source-to-sink.
- Secure Skill para revisión contextual de invariantes de seguridad.
- Secure Bench para evaluación reproducible y métricas separadas.
- Una knowledge base local con provenance, deduplicación y versionado.
- Agentes de IA opcionales para priorización e investigación de casos ambiguos.

La decisión humana es siempre autoritativa. Un candidato no se convierte en
vulnerabilidad sólo porque lo sugiera un scanner o un modelo.

El humano debe seguir siendo mejor que SecureFlow en el juicio contextual y la
decisión de seguridad. La plataforma sólo debe aportar más cobertura,
velocidad, memoria de patrones y reproducibilidad; cuando no tenga evidencia
suficiente, debe abstenerse.

## Primera ejecución reproducible

El CLI actual ejecuta un binario de Secure Engine indicado explícitamente,
conserva su `secure-json-v1` sin reserializar y genera un manifiesto
`secureflow-run-v1`. El reconocimiento de autorización es obligatorio:

```bash
cargo run -p secureflow -- scan \
  --binary /ruta/a/secure \
  --authorized \
  --authorization-reviewer "Daniel" \
  --authorization-reference "repositorio local propio" \
  --output /tmp/secureflow-report.json \
  --manifest-output /tmp/secureflow-run.json \
  /ruta/al/target
```

En Linux el CLI exige Bubblewrap por defecto: red privada y filesystem del host
de sólo lectura. El run conserva el hash del binario `/usr/bin/bwrap`. Sólo una
decisión operativa explícita puede usar `--sandbox disabled`; nunca hay fallback
silencioso si el sandbox requerido no está disponible.

`--authorization-reviewer` es obligatorio. Las bases `written-consent`,
`organization-policy` y `other-documented` exigen además
`--authorization-reference`; una expiración RFC3339 vencida falla antes de
ejecutar el engine. `--target-revision-kind` y `--target-revision` permiten
ligar el run a un commit o snapshot explícito; una revisión Git debe ser el
object ID completo en minúsculas.

Después se puede validar el manifiesto sin ejecutar ningún scanner:

```bash
cargo run -p secureflow -- validate-run /tmp/secureflow-run.json
```

Los candidatos se pueden consultar sin abrir el JSON manualmente:

```bash
cargo run -p secureflow -- list-findings \
  /tmp/secureflow-run.json --decision pending --format text

cargo run -p secureflow -- show-finding \
  /tmp/secureflow-run.json sf_finding_<id>
```

También se puede generar un informe Markdown local. Por defecto no incluye el
texto de la rationale humana, aunque sí conserva su decisión:

```bash
cargo run -p secureflow -- export-report \
  --manifest /tmp/secureflow-run.json \
  --output /tmp/secureflow-report.md
```

El informe declara explícitamente que los findings son candidatos y que cero
candidatos no constituye una garantía de seguridad. La opción
`--include-human-rationale` sólo debe usarse cuando el destino del informe esté
autorizado para recibir ese contexto.

Una revisión humana se escribe en otro manifiesto; el original queda intacto:

```bash
cargo run -p secureflow -- review-run \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --decision validated \
  --reviewer "Daniel" \
  --rationale "La ruta source-to-sink fue verificada localmente" \
  --output /tmp/secureflow-run-reviewed.json
```

Los findings ya revisados pueden entrar a un ledger local append-only:

```bash
cargo run -p secureflow -- knowledge-import \
  --manifest /tmp/secureflow-run-reviewed.json \
  --ledger .secureflow/knowledge.jsonl \
  --source-license-status spdx-declared \
  --source-license-expression MIT \
  --source-license-evidence /ruta/al/target/LICENSE

cargo run -p secureflow -- knowledge-list \
  .secureflow/knowledge.jsonl --decision validated --format json
```

El ledger v2 guarda provenance, revisión del target, licencia declarada con
evidencia hasheada, ubicaciones relativas y hashes de la rationale/referencia;
no guarda el texto fuente ni la rationale completa. Observaciones exactas
repetidas se conservan y enlazan al primer registro, sin inferir equivalencia
entre engines. También se puede declarar `private-or-undisclosed` o `unknown`
en vez de inventar una licencia. Los schemas normativos se imprimen con
`secureflow schema` y `secureflow knowledge-schema`; v1 permanece disponible
mediante `secureflow knowledge-schema --version v1`.

Los advisories públicos viven en un catálogo SQLite separado para no confundir
conocimiento externo con decisiones humanas. La ruta reproducible prepara un
ZIP OSV adquirido externamente, conserva todos los aceptados y rechazados,
evidencia de licencia y accounting exacto:

```bash
cargo run -p secureflow -- snapshot-prepare-osv \
  --archive /ruta/npm-all.zip \
  --output .secureflow/npm-snapshot \
  --artifact-locator https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip \
  --artifact-revision gcs-generation:<id> \
  --expected-ecosystem npm \
  --acquired-at 2026-08-23T17:47:25Z \
  --github-license-evidence /ruta/GHAD-LICENSE.md \
  --openssf-malicious-packages-license-evidence /ruta/OPENSSF-LICENSE

cargo run -p secureflow -- catalog-import-snapshot \
  --database .secureflow/advisories.sqlite3 \
  --manifest .secureflow/npm-snapshot/manifest.json \
  --archive /ruta/npm-all.zip
```

La importación manual de OSV JSON sigue disponible para fuentes explícitas:

```bash
cargo run -p secureflow -- catalog-import-osv \
  --database .secureflow/advisories.sqlite3 \
  --input /ruta/al/snapshot-osv \
  --source-name github-advisory-database \
  --source-license-expression CC-BY-4.0 \
  --source-license-evidence /ruta/al/snapshot-osv/LICENSE \
  --source-locator https://github.com/github/advisory-database

cargo run -p secureflow -- catalog-lookup \
  --database .secureflow/advisories.sqlite3 CVE-2026-0001 --format json

cargo run -p secureflow -- catalog-search \
  --database .secureflow/advisories.sqlite3 "command injection" --format json

cargo run -p secureflow -- catalog-package \
  --database .secureflow/advisories.sqlite3 crates.io nombre-del-crate --format json

cargo run -p secureflow -- catalog-stats .secureflow/advisories.sqlite3
cargo run -p secureflow -- catalog-check .secureflow/advisories.sqlite3
```

La base conserva revisiones raw, alias exactos y rangos compactos; `upstream` y
`related` no fusionan vulnerabilidades. Durante importaciones masivas FTS se
reconstruye al final y queda `dirty` si el proceso se interrumpe; se recupera
con `catalog-rebuild-index`. Los componentes exactos de aliases se pueden
reconstruir con `catalog-rebuild-canonicalization`, incluyendo splits cuando
una revisión retira un alias. Toda consulta estructurada mantiene
`validation_authority=human-only`.

El piloto real de crates.io, GitHub Actions y npm procesó 229.644 registros
fuente activos como 228.674 entidades canónicas en una base de 1,20 GB. Incluye
219.658 reportes de paquetes maliciosos OpenSSF; por eso esas cifras son
registros de seguridad, no vulnerabilidades humanas validadas. 328 registros
npm sin procedencia admitida quedaron en cuarentena. Evidencia exacta:
[`docs/evidence/real-advisory-pilot-2026-08-23.json`](./docs/evidence/real-advisory-pilot-2026-08-23.json).

Un finding se enlaza conservadoramente con advisories de un paquete sin evaluar
todavía el rango de versión ni afirmar causalidad:

```bash
cargo run -p secureflow -- correlate-package \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --database .secureflow/advisories.sqlite3 \
  --ecosystem crates.io --package tokio --version 1.0.0 \
  --output /tmp/secureflow-correlation.json

cargo run -p secureflow -- orchestrate-plan \
  --manifest /tmp/secureflow-run.json \
  --correlation /tmp/secureflow-correlation.json \
  --output /tmp/secureflow-plan.json
```

Backups y restores crean destinos nuevos, hasheados y verificados:

```bash
cargo run -p secureflow -- catalog-backup \
  --database .secureflow/advisories.sqlite3 \
  --output /backups/advisories.sqlite3 \
  --manifest-output /backups/advisories.backup.json

cargo run -p secureflow -- catalog-backup-verify \
  --backup /backups/advisories.sqlite3 \
  --manifest /backups/advisories.backup.json
```

En el host documentado se midieron 100k, 500k y 1M registros sintéticos. El
millón produjo 900k entidades canónicas, ocupó 2,07 GB y tardó 104,7 s en NVMe/
Btrfs. Esto demuestra capacidad del almacenamiento, no la existencia de un
millón de vulnerabilidades reales. Método y límites:
[`docs/knowledge-benchmark.md`](./docs/knowledge-benchmark.md).

Una salida estructurada `review-contract` 1.1 de Secure Skill puede importarse
como candidatos contextuales vinculados a un run autorizado:

```bash
cargo run -p secureflow -- secure-review-import \
  --review /ruta/review.json \
  --manifest /tmp/secureflow-run.json \
  --secure-skill-root /ruta/secure-skill \
  --secure-skill-revision <commit-completo> \
  --output /tmp/secureflow-contextual-review.json

cargo run -p secureflow -- secure-review-list \
  /tmp/secureflow-contextual-review.json --format text
```

El importador registra hashes, versión, commit y licencia, y verifica el commit
contra `HEAD` cuando el source root conserva `.git`; no ejecuta la skill. Sus
findings permanecen `contextual-candidates`, la autoridad de
validación es `human-only` y cero findings nunca significa que el target sea
seguro. El tercer schema se imprime con `secureflow secure-review-schema`.

Un resultado retenido de Secure Bench se importa por una ruta de evaluación
separada, verificando el schema upstream y los fingerprints de suite y run:

```bash
cargo run -p secureflow -- benchmark-import \
  --result /ruta/result.json \
  --run-manifest /ruta/run.json \
  --suite /ruta/suite.toml \
  --secure-bench-root /ruta/secure-bench \
  --secure-bench-revision <commit-completo> \
  --study-kind historical-public-diagnostic \
  --output /tmp/secureflow-benchmark.json

cargo run -p secureflow -- benchmark-summary \
  /tmp/secureflow-benchmark.json --format text
```

La salida mantiene TP/FN por expectativa vulnerable, FP/TN por control seguro,
ratios con denominadores, fallos y rendimiento separados. Nunca habilita
rankings, claims de superioridad ni production readiness. Su schema se imprime
con `secureflow benchmark-schema`.

La ruta evaluativa completa y separada puede ejecutar los 14 fixtures
sintéticos locales sin modificar Secure Bench:

```bash
bash scripts/eval-local.sh
```

El protocolo, resultado observado y límites están en
[`docs/evaluation.md`](./docs/evaluation.md).

Antes de un estudio nuevo se puede sellar un protocolo prospectivo con holdout,
cohorte humana, blinding, adjudicación, costes y límites de claims:

```bash
cargo run -p secureflow -- benchmark-protocol-seal \
  --draft /ruta/protocol-draft.json \
  --output /ruta/protocol-sealed.json
```

El fixture del repositorio sólo prueba el contrato; no es un preregistro real.

La IA opcional empieza con un contrato offline. El CLI prepara un solo finding
redacted y presupuestado, pero no hace llamadas de red:

```bash
cargo run -p secureflow -- ai-prepare \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --enable-ai \
  --consent-redacted-export \
  --output /tmp/secureflow-ai-request.json
```

La familia lógica por defecto es Luna. El payload excluye código, descripciones
de evidencia, metadata humana y paths absolutos; un filtro conservador redacta
posibles secretos. La preparación informa `transmitted=false`. Una respuesta
estructurada puede registrarse después con `ai-apply-response`, conservando
hashes y tokens sin cambiar la decisión humana. No hay cliente de proveedor
implementado todavía.

El `scan` calcula y registra el hash SHA-256 del target, del binario y del
reporte, y comprueba target y binario antes y después de ejecutar para fallar
si cambian durante el análisis. Proyecta los candidatos a un modelo canónico y
deja cada revisión humana en `pending`. Sólo los códigos `0` (sin findings) y
`1` (con findings) cuentan como ejecución completada; `2+`, señal, timeout o
reporte inválido son fallos operativos aunque stdout contenga JSON. Los comandos
que crean artefactos derivados rechazan una salida que
sea la misma entrada; `scan` tampoco permite escribir resultados dentro del
target analizado.
El proceso se ejecuta sin shell, sin stdin y con entorno limpio. En Linux recibe
un grupo de procesos propio, core dumps desactivados y límites de 2 GiB de
memoria virtual, 256 descriptores y CPU ligada al timeout; el hash de esta
configuración queda en el manifiesto. Con el modo requerido, Bubblewrap añade
un namespace de red privado, root host de sólo lectura, `/proc` y `/dev`
aislados; no equivale a aislamiento fuerte frente a un kernel comprometido ni
a una VM.

El timeout aceptado es de 1 a 3.600 segundos y se acorta para terminar antes de
una expiración de autorización registrada. Binarios mayores de 1 GiB se
rechazan. En Unix, los artefactos derivados se crean con modo `0600`; los
directorios nuevos del ledger usan `0700`.

El target usa el fingerprint `secureflow-target-sha256-v2`: distingue archivo
y directorio, prefija longitudes para evitar serializaciones ambiguas, excluye
`.git` y rechaza symlinks. El hashing falla cerrado por encima de 250.000
archivos, 500.000 entradas, 16 GiB totales, 2 GiB por archivo o 256 niveles de
directorio. Paths no UTF-8 también se rechazan para evitar fingerprints
ambiguos.

## Estado actual

Este workspace integra los proyectos originales por procesos y contratos, no
por copia física. Secure Engine, Secure Skill, Secure Bench, CMS Nova y
Mitiquete permanecen en sus propios directorios y conservan sus historiales.

El primer contrato es [`secureflow-run-v1`](./docs/contracts/secureflow-run-v1.md).

## Flujo objetivo

```text
scope autorizado
  -> análisis determinista local
  -> normalización y deduplicación
  -> priorización determinista
  -> validación IA opcional
  -> decisión humana
  -> informe y knowledge base local
  -> benchmark/evals separados
```

## Límites

- No se escanean terceros sin autorización explícita.
- No se ejecuta el código del repositorio analizado durante el análisis estático.
- La IA está desactivada por defecto y no puede aprobar un hallazgo.
- No se sube código fuente automáticamente.
- No se descargan ni mezclan feeds externos automáticamente; cada snapshot debe
  aprobar licencia, procedencia, adapter y accounting de rechazos.
- La capacidad sintética de 1M registros no constituye una base global real ni
  un claim de cobertura.

La arquitectura y el MVP están documentados en [`docs/`](./docs/).
La decisión provisional JSONL vs. SQLite, repetida para knowledge v2, está respaldada por
[`docs/knowledge-benchmark.md`](./docs/knowledge-benchmark.md).
El flujo de demostración está en [`docs/demo.md`](./docs/demo.md) y la matriz de
claims permitidos para CV/paper en
[`docs/evidence-and-claims.md`](./docs/evidence-and-claims.md).
La matriz requisito-evidencia y los pendientes de publicación están en
[`docs/completion-audit.md`](./docs/completion-audit.md).

## Estado de la implementación

El MVP local está operativo: workspace Rust, contrato y schema,
adapter de proceso externo, proyección, ordenamiento, deduplicación dentro de
un engine, informe Markdown, registro explícito de revisión humana y ledger
local JSONL. La
integración contextual de Secure Skill también está implementada mediante un
contrato separado y provenance verificable. Secure Bench ya puede importar
resultados v2 retenidos en una ruta exclusivamente evaluativa. El catálogo
SQLite/FTS5 implementa revisiones de origen, alias exactos, paquetes, consultas
e integridad local. La ruta IA ya tiene preparación redacted y accounting
offline; el transporte a proveedor continúa deshabilitado y no se presenta
como funcionalidad terminada.

## Licencia

SecureFlow se distribuye bajo los términos de MIT o Apache License 2.0, a
elección del usuario. Consulta [`LICENSE-MIT`](./LICENSE-MIT) y
[`LICENSE-APACHE`](./LICENSE-APACHE).
