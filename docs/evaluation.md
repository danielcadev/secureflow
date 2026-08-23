# Evaluación local separada de producción

## Propósito

`scripts/eval-local.sh` ejecuta el corpus sintético Phase 1 de Secure Bench
contra un binario explícito de Secure Engine. Esta ruta nunca participa en la
decisión humana sobre un target de producción y no inyecta respuestas del
benchmark al scanner.

## Ejecución

```bash
cd /ruta/al/checkout/secureflow
bash scripts/eval-local.sh
```

El script:

1. valida el corpus desde el root de Secure Bench;
2. copia y escanea por separado 7 casos vulnerables y 7 controles seguros;
3. genera un bundle raw y un `secure-bench-result-v2` bajo `/tmp`;
4. lo importa como `local-development-diagnostic` con hashes de suite, run,
   schema, licencia y commits;
5. imprime TP/FN por expectativa y FP/TN por control seguro.

Los repositorios originales no se modifican. Se pueden reemplazar binarios y
paths mediante `SECUREFLOW_BENCH_ROOT`, `SECUREFLOW_BENCH_BINARY`,
`SECUREFLOW_ENGINE_BINARY` y `SECUREFLOW_BENCH_SUITE`.

## Resultado observado el 23 de agosto de 2026

Con Secure Engine reportando versión 0.1.6 y la suite pública de 14 casos:

| Métrica | Resultado |
| --- | ---: |
| TP por expectativa vulnerable | 0 |
| FN por expectativa vulnerable | 7 |
| FP por control seguro | 2 |
| TN por control seguro | 5 |
| Recall vulnerable | 0/7 (0,00 %) |
| Tasa FP en controles | 2/7 (28,57 %) |
| Cobertura limpia de controles | 5/7 (71,42 %) |
| Fallos operativos | 0 |
| Findings normalizados | 6 |
| Duración agregada | 70 ms / 14 muestras |

Estos números son un diagnóstico de desarrollo, no una comparación publicable.
Que existan seis findings normalizados pero cero matches indica que el
matcher no acreditó ninguna expectativa bajo su contrato exacto; no autoriza a
concluir que el scanner simplemente “no detectó nada”. En cuatro casos
vulnerables (`001`, `009`, `011`, `013`) sí hubo findings; en `001`, `011` y
`013` coincidieron source, sink y evidence path, pero no los strings exactos de
categoría/invariante del matcher Phase 1. En `009` también discrepó el source.
Los casos vulnerables `003`, `005` y `007` no produjeron findings normalizados.
Los controles `010` y `014` produjeron los dos falsos positivos.

Esto puede reflejar a la vez cobertura faltante y drift entre el contrato
legacy Phase 1 y la taxonomía que reporta el Engine actual. Debe evaluarse por
una ruta prospectiva compatible con taxonomía, sin reescribir las respuestas
del corpus después de observar los resultados.

## Límites

- la suite es pequeña, sintética y conocida por los desarrolladores;
- no hubo preregistro, holdout nuevo ni evaluación humana ciega;
- el runner limpia el entorno, pero este script no añade aislamiento kernel de
  red o filesystem;
- una ejecución no permite intervalos de incertidumbre ni claims generales;
- los resultados no demuestran superioridad, production readiness ni desempeño
  en repositorios reales.

## Diagnóstico separado de SecureFlow Web

La vertical Web tiene un segundo diagnóstico completamente local. El fixture
Next.js etiqueta seis rutas y 24 aserciones sobre inventario, correlación de
artefactos, exclusión de decoys y semántica segura. La ejecución retenida del
23 de agosto de 2026 produjo:

| Medida | Resultado |
| --- | ---: |
| Rutas esperadas/reportadas | 6 / 6 |
| Precision/recall/F1 de rutas | 1,00 / 1,00 / 1,00 |
| Candidatos locales | 11 |
| Correlacionados/revisión/abstención | 4 / 5 / 2 |
| Aserciones de desarrollo | 24 / 24 |
| Red o ejecución del target | no / no |

Los contratos de resultado fijan `independent_holdout=false`,
`superiority_claim_allowed=false` y `production_safety_claim_allowed=false`.
El corpus fue construido junto al parser y puede tener leakage de desarrollo;
por eso no se combina con las métricas históricas de Secure Bench ni con un
futuro estudio humano. Evidencia:
[`web-route-lab-2026-08-23.json`](./evidence/web-route-lab-2026-08-23.json) y
[`web-development-corpus-2026-08-23.json`](./evidence/web-development-corpus-2026-08-23.json).

## Estudio prospectivo siguiente

`benchmark-protocol-seal` valida y sella el contrato
`secureflow-prospective-protocol-v1` antes de observar resultados. Exige como
mínimo 20 casos, 10 vulnerables y 10 controles, holdout no visto, etiquetas
ocultas, SecureFlow y cohorte humana, dos adjudicadores, blinding, auditoría de
leakage, tiempo/coste, abstenciones y publicación de resultados negativos.

`tests/fixtures/prospective-protocol-draft.json` prueba únicamente el contrato
con hashes sintéticos. No es un preregistro, no contiene un corpus real y no
autoriza todavía ningún claim de superar a humanos.

`benchmark-protocol-preflight` añade el paso para un estudio real: vuelve a
calcular los hashes del manifest público del corpus, provenance, licencias y
entorno antes de sellar. No recibe el ground truth. La cohorte, randomización,
captura de tiempos, apertura de labels y adjudicación siguen pendientes. Véase
[`prospective-study-runbook.md`](./prospective-study-runbook.md).
