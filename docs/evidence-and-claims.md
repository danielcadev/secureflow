# Evidencia honesta para CV y paper

## Claims respaldados hoy

| Claim acotado | Evidencia reproducible | Límite que debe acompañarlo |
| --- | --- | --- |
| Prototipo local-first en Rust | workspace con nueve packages, toolchain 1.92 fijado, repositorio público y gates locales/CI | la publicación no demuestra eficacia general y la release inicial no está firmada |
| Integra un analizador por proceso externo | `scan`, SHA-256 de binario/target/reporte, límites y `secure-json-v1` | validado con fixtures locales; no demuestra cobertura general |
| Aísla la ejecución Linux por defecto | grupo de procesos, rlimits y Bubblewrap con root host de sólo lectura y namespace de red privado | no equivale a una VM ni protege frente a un kernel comprometido; el modo deshabilitado exige una elección explícita |
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
| Procesa snapshots reales con cuarentena | 229.644 registros fuente activos de crates.io, GitHub Actions y npm; hashes, revisiones, licencias y 347 rechazos retenidos | son advisories/reportes de seguridad —incluidos 219.658 reportes de paquetes maliciosos—, no vulnerabilidades validadas |
| Actualiza el catálogo sin inferir bajas | delta per-ecosystem encadenado, payloads exactos, replay/recovery y `withdrawn`; piloto solapado oficial de 7 RUSTSEC sobre la copia real | no hubo cambios posteriores al snapshot; el piloto prueba idempotencia, no siete advisories nuevos |
| Correlaciona sin elevar señales | lookup exacto evalúa listas/rangos SEMVER y conserva unknown, hashes de run/catálogo y causalidad=false | el contexto de paquete es declarado por el operador y requiere revisión humana; affected no prueba exploitabilidad |
| Sella un protocolo prospectivo | contrato con holdout, etiquetas ocultas, cohorte humana, dos adjudicadores, tiempo/coste, resultados negativos y preflight de hashes reales | el fixture es sintético; todavía no existe holdout/cohorte/ejecución ni base para comparar con humanos |
| Inventaría APIs Next.js sin red | scope sellado, 6/6 rutas del fixture, 11 candidatos locales, JSON/SARIF y 24/24 aserciones | fixture sintético conocido, no holdout; no mide repositorios reales ni autoriza claims de superioridad |
| Genera evidencia de release | CI remoto por commits, SBOM CycloneDX determinista y bundle hasheado desde un commit limpio publicado con `v0.1.0` | tag anotado sin firma y sin verificación de reproducibilidad binaria entre hosts |

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
- El piloto real produjo 228.674 componentes canónicos por aliases exactos a
  partir de 229.644 registros aceptados. La diferencia es deduplicación de IDs,
  no confirmación de exploits ni una métrica de precisión.
- La vertical Web pasó 24/24 aserciones de desarrollo y 6/6 rutas etiquetadas.
  Esto prueba los contratos y el fixture conocido; `independent_holdout=false`
  impide presentarlo como eficacia general o comparación humana.

## Bloqueos antes de claims comparativos

1. La release pública, su CI y sus checksums no sustituyen un estudio de
   eficacia; el tag inicial tampoco aporta firma criptográfica.
2. Falta congelar un corpus propio con controles usando el protocolo
   prospectivo antes de observar resultados.
3. Falta ejecutar comparadores bajo capacidades y condiciones equivalentes.
4. Falta una cohorte humana y adjudicación independiente.
5. Falta transporte IA real auditado; las respuestas aplicadas en tests son
   sintéticas.
6. Falta medir coste/latencia/calidad por finding y demostrar ahorro de tiempo.

Hasta resolverlos, la evidencia es válida para presentar arquitectura y rigor
de ingeniería de un prototipo, no eficacia superior.
