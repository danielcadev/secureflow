# Auditoría de cumplimiento del MVP

Estado observado: 23 de agosto de 2026.

Esta matriz separa funcionalidad demostrable, evidencia y trabajo posterior. Un
check técnico no constituye una afirmación de que SecureFlow encuentre todas
las vulnerabilidades ni de que supere a un investigador humano.

## Goal largo: requisito contra evidencia

| Requisito | Evidencia actual | Estado y límite |
| --- | --- | --- |
| Workspace Rust independiente | Siete packages bajo `crates/`; los repositorios fuente se consumen por procesos o contratos | Cumplido para el MVP; no hay copia física de los proyectos originales |
| Análisis determinista autorizado | `secureflow scan` exige `--authorized`, ejecuta un binario explícito sin shell y valida `secure-json-v1` | Cumplido para targets locales; la identidad y la autorización son declaraciones del operador, no firmas verificables |
| Provenance estable | Hashes SHA-256 de target, binario, configuración y reporte; fingerprint de árbol con dominio/longitudes; target y binario se comprueban antes y después del proceso | Cumplido con límites fail-closed; no es un snapshot transaccional y un cambio que se revierta entre ambas mediciones podría no observarse |
| Boundary de proceso | Entorno limpio, stdin nulo, stdout/stderr separados y acotados, timeout 1–3.600 s ajustado a expiración, binario máximo 1 GiB, process group y rlimits Linux | Cumplido para el MVP Linux; no existe todavía sandbox de red/filesystem ni aislamiento de namespaces |
| Contrato canónico estricto | `secureflow-run-v1`, structs con rechazo de campos desconocidos y validación semántica | Cumplido; Secure Engine conserva la propiedad de su contrato externo |
| Priorización y deduplicación | Orden determinista y deduplicación exacta por fingerprint, regla y ubicaciones | Cumplido para una ejecución/un engine; no hay reconciliación semántica entre engines |
| Flujo humano | `list-findings`, `show-finding`, `review-run`, decisión `abstained` e informe Markdown | Cumplido; sólo la decisión humana puede marcar `validated` |
| Inmutabilidad de entradas | Los comandos derivados rechazan salida igual a una entrada, incluidos hardlinks en Unix; `scan` rechaza outputs dentro del target; nuevos artefactos usan `0600` y directorios del ledger `0700` | Cumplido con pruebas; sigue existiendo una ventana TOCTOU local entre comprobación y escritura |
| Knowledge base local | JSONL v2 para decisiones humanas y catálogo SQLite v1 separado para advisories, revisiones, alias, paquetes y FTS5 | Cumplido como infraestructura local; no hay deduplicación semántica ni fuente real aprobada todavía |
| Decisión JSONL/SQLite basada en números | JSONL medido hasta 10k; SQLite medido en NVMe/Btrfs con 100k, 500k y 1M registros sintéticos | JSONL queda para el ledger pequeño; SQLite demostró 1M source records/900k entidades en 104,736 s y 2,07 GB, sin extrapolar a records reales |
| Secure Skill | Import estricto de `review-contract` 1.1, commit/hashes/licencia y envelope separado; si existe `.git`, el commit debe coincidir con `HEAD` | Cumplido como adapter; un snapshot sin `.git` conserva hashes pero su revisión es declarada por el operador; no convierte `verified` upstream en validación SecureFlow |
| Secure Bench | Import de `result-v2`, fingerprints de suite/run, verificación opcional de `HEAD`, TP/FN y FP/TN separados y claims bloqueados | Cumplido como ruta evaluativa; el corpus Phase 1 es sintético y conocido, no un holdout publicable |
| IA local-first | Preparación redacted desactivada por defecto, consentimiento, presupuesto, Luna por defecto, modelo/prompt/tokens y respuesta advisory | Cumplido como contrato offline; no hay cliente de red ni medición de calidad/coste real de un proveedor |
| Evidencia para CV/paper | Demo, evaluación separada, schemas, ADRs y matriz de claims permitidos/prohibidos | Cumplido para describir un prototipo de ingeniería; no respalda superioridad, production readiness ni eficacia general |
| Preservación de originales | Demo y evaluación escriben bajo `/tmp`; verificación Git posterior | Cumplido en esta sesión: `secure-engine`, `secure-skill`, `secure-bench` y `cms-nova-secure-engine-test` siguen limpios. Fuera de SecureFlow se observaron ocho cambios en `cms-nova`, `SEO.md` sin seguimiento en `mitiquete` y siete cambios en su backup; no fueron creados ni alterados por este trabajo |
| Publicación reproducible | Todos los packages tienen `publish = false`; metadata y textos legales declaran `MIT OR Apache-2.0`; Git local usa la rama `main` | Commit raíz local creado; todavía no existe tag, remoto ni publicación |

## Evidencia ejecutada

- `cargo test --workspace --locked`: 85 pruebas aprobadas, 0 fallos.
- `cargo check --workspace --all-targets --locked`: aprobado.
- `cargo audit --deny warnings`: 156 dependencias revisadas contra 1.225
  advisories, sin vulnerabilidades ni warnings reportados.
- `scripts/demo-local.sh`: 6 candidatos deterministas, todos `pending`; request
  Luna de 899 bytes de payload, `transmitted=false`; importaciones de Secure
  Skill y del benchmark histórico válidas. El catálogo sintético importó 2
  registros de origen como 1 entidad canónica,
  pasó `quick_check` y no tuvo violaciones de claves foráneas. Artefactos de
  esta ejecución: `/tmp/secureflow-demo.erV96m`.
- `scripts/eval-local.sh`: 14 casos sintéticos, 0 TP, 7 FN, 2 FP, 5 TN, 0
  fallos operativos y 70 ms agregados. Artefactos de esta ejecución:
  `/tmp/secureflow-eval.blwfZ9`.
- El SHA-256 del reporte raw de la demo coincide con el hash registrado en el
  manifiesto; los timestamps de creación y finalización delimitan la ejecución.
- Dos demos consecutivos conservaron exactamente el target hash, el orden y el
  contenido de los seis findings canónicos. El raw report cambió únicamente en
  timestamps y duraciones del engine, por lo que no se afirma identidad byte a
  byte de telemetría volátil.
- La auditoría de dependencias debe repetirse después de cualquier cambio al
  lockfile.
- Los scripts fijan `umask 077`; los artefactos nuevos de demo/evaluación no
  deben conceder permisos a grupo u otros usuarios locales.
- `catalog_bench` en NVMe/Btrfs: 100k/500k/1M source records sintéticos; el
  millón produjo 900k entidades canónicas, 2.072.891.392 bytes, 104.736,081 ms
  de carga total, lookup exacto de 66,451 μs, FTS worst-case de 843,406 ms y
  paquete exacto de 450,295 μs. CSV retenido en
  `docs/evidence/catalog-benchmark-2026-08-23.csv`.

Los paths bajo `/tmp` son evidencia local retenida de la sesión, no artefactos
publicables permanentes. Una release debe producir un bundle versionado y
hasheado desde un commit limpio.

## Qué falta antes de llamar al proyecto publicable

1. Congelar una versión, repetir los gates desde el commit limpio y crear un
   tag reproducible cuando el MVP vaya a publicarse. No existe remoto ni se ha
   publicado nada.
2. Corpus prospectivo congelado con controles, anti-leakage, protocolo de
   adjudicación y comparadores bajo capacidades equivalentes.
3. Cohorte humana y evaluación ciega antes de cualquier claim de superar a
   personas en una tarea estrecha.
4. Si se habilita IA real: transporte auditado, política de proveedor,
   residencia/retención de datos, coste y calidad medidos por finding.

## Qué no se construye todavía

- descarga o ingestión indiscriminada de CVE/NVD/OSV;
- presentar capacidad sintética como una base global de vulnerabilidades reales;
- embeddings para todos los advisories o deduplicación IA sin labels;
- explotación, active scanning o parches autónomos;
- dashboard web o sistema distribuido;
- deduplicación semántica sin corpus etiquetado;
- ranking comercial o claims de superioridad;
- sandbox parcial presentado como aislamiento completo.
