# Evidencia honesta para CV y paper

## Claims respaldados hoy

| Claim acotado | Evidencia reproducible | Límite que debe acompañarlo |
| --- | --- | --- |
| Prototipo local-first en Rust | workspace con siete packages y `cargo test --workspace` | no release firmada ni commit de SecureFlow todavía |
| Integra un analizador por proceso externo | `scan`, SHA-256 de binario/target/reporte, límites y `secure-json-v1` | validado con fixtures locales; no demuestra cobertura general |
| Limpia descendants al vencer el timeout | grupo de procesos Unix, rlimits Linux y prueba con un child que conserva pipes | no hay sandbox de filesystem todavía |
| Mantiene validación humana como autoridad | estados human review, manifests derivados, tests que IA no altera decisión | depende de identidad declarada por CLI; no hay firma humana aún |
| Exporta evidencia legible sin elevar candidatos | informe Markdown con provenance, accounting, evidencia y limitaciones | no es un certificado de seguridad ni reemplaza la revisión humana |
| Integra revisión contextual sin mezclar veredictos | `secureflow-secure-review-v1`, hashes de Skill/contrato/licencia | importa outputs; todavía no orquesta la ejecución de Secure Skill |
| Importa benchmarks neutrales | schema upstream, fingerprints suite/run, métricas separadas | el adapter sólo importa; la ejecución vive en un script separado y nunca permite rankings |
| Ejecuta un diagnóstico sintético separado | 14 casos locales, bundle raw e import `local-development-diagnostic` | corpus conocido, una ejecución, no preregistro ni claim comparativo |
| Reduce datos antes de IA | request de demostración de 899 bytes sin source/descripciones y con redacción | el detector de secretos es conservador, no una garantía formal |
| Mide almacenamiento antes de escalar | JSONL v2: 10k records, mediana 91,508 ms en el host documentado | una máquina, workload sintético, sin concurrencia ni p95 real |
| Demuestra capacidad de catálogo local | SQLite/FTS5: 100k, 500k y 1M source records; CSV retenido y consultas separadas | datos sintéticos; 1M source records no equivale a 1M vulnerabilidades reales |
| Deduplica IDs externos conservadoramente | unión exacta CVE/GHSA/OSV/RUSTSEC por `aliases`; `upstream`/`related` no fusionan | quitar un alias upstream exige reconstruir desde snapshot; no hay dedup semántico |
| Conserva licencia y repeticiones exactas | knowledge v2 con estado de licencia declarado, hash de evidencia y `duplicate_of_record_id` | no valida legalmente SPDX ni deduplica semánticamente entre engines |

## Formulación sugerida para CV

> Built a Rust local-first security orchestration prototype that integrates a
> deterministic analyzer, contextual review contracts, human-only adjudication,
> provenance-bound benchmark imports, and budgeted redacted AI request
> preparation. Added versioned JSON contracts, SHA-256 traceability, an
> versioned reviewed-finding ledger, and a measured local SQLite advisory
> catalog; no source is sent to a model by default.

Versión corta en español:

> Construí un prototipo local-first en Rust para orquestar análisis estático,
> revisión contextual, decisión humana, evidencia reproducible y preparación IA
> redacted con presupuestos y trazabilidad por hashes.

No usar todavía:

- “supera a investigadores humanos”;
- “encuentra más vulnerabilidades que Semgrep/OpenGrep”;
- “production-ready”;
- “base global de 300.000 vulnerabilidades reales”;
- “IA autónoma que valida vulnerabilidades”;
- “cero falsos positivos”.

La visión puede aspirar a superar desempeño humano en tareas estrechas y
medibles, pero el claim sólo es publicable después de un estudio preregistrado
con expertos, adjudicación ciega, tiempo, cobertura, precisión, recall,
incertidumbre y análisis de desacuerdos.

## Unidad de evidencia para un paper

Cada resultado publicable debería fijar antes de ejecutar:

- pregunta de investigación y criterio de éxito;
- corpus, licencia, procedencia, deduplicación y estado público/holdout;
- versión/hash de scanners, configuración, adapters y schemas;
- unidad de TP/FN y FP/TN;
- política para crashes, timeouts, unsupported y abstenciones;
- número de repeticiones y protocolo de retries;
- hardware, OS, aislamiento y límites;
- raw reports, decisiones del matcher y hashes;
- evaluación humana ciega y resolución de desacuerdos;
- limitaciones, intervalos de incertidumbre y amenazas a validez.

## Resultados que sí pueden mostrarse

- El fixture local Phase 3 produjo seis candidatos en la ejecución retenida de
  SecureFlow. Son candidatos, no seis vulnerabilidades validadas.
- Un humano marcó un candidato como `abstained` en el ensayo local; esto prueba
  el estado de abstención, no la falsedad o validez del finding.
- El baseline histórico Phase 1 importado conserva 0 TP, 7 FN, 3 FP y 4 TN con
  sus unidades y limitaciones. Es evidencia de neutralidad del importador, no
  una medida del Engine actual.
- El request IA real se preparó localmente con 899 bytes y cero transmisiones.
  No es una medición de calidad de Luna.
- Las pruebas automatizadas verifican contratos y flujos del prototipo; no son
  casos de vulnerabilidad ni sustituyen un benchmark de detección.
- El catálogo procesó 1M source records sintéticos en 104,736 s sobre NVMe/
  Btrfs y produjo 900k entidades canónicas; esto mide infraestructura, no
  cobertura de vulnerabilidades.

## Bloqueos antes de publicación

1. SecureFlow aún no tiene repositorio Git propio, commit reproducible ni tag.
2. El metadata Cargo declara MIT, pero falta una decisión explícita del creador
   y un archivo de licencia raíz correspondiente.
3. Falta congelar un corpus propio con controles y protocolo anti-leakage.
4. Falta ejecutar comparadores bajo capacidades y condiciones equivalentes.
5. Falta una cohorte humana y adjudicación independiente.
6. Falta transporte IA real auditado; las respuestas aplicadas en tests son
   sintéticas.
7. Falta medir coste/latencia/calidad por finding y demostrar ahorro de tiempo.

Hasta resolverlos, la evidencia es válida para presentar arquitectura y rigor
de ingeniería de un prototipo, no eficacia superior.
