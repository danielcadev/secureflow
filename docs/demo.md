# Demo local reproducible

## Qué demuestra

El demo conecta cinco verticales sin modificar los repositorios originales:

1. ejecuta Secure Engine sobre su fixture local explícitamente autorizado;
2. valida, prioriza, lista candidatos y exporta un informe Markdown;
3. prepara un request Luna redacted sin transmitirlo;
4. importa dos registros OSV sintéticos, reconcilia CVE/GHSA y consulta el
   catálogo SQLite local;
5. importa por separado un ejemplo sintético de Secure Skill y un resultado
   histórico retenido de Secure Bench.

No automatiza una decisión humana, no llama una API, no ejecuta un exploit y no
presenta el resultado histórico como capacidad actual.

## Ejecución

En el layout local inspeccionado:

```bash
cd /ruta/al/checkout/secureflow
bash scripts/demo-local.sh
```

Se pueden reemplazar las dependencias explícitamente:

```bash
SECUREFLOW_ENGINE_BINARY=/ruta/secure \
SECUREFLOW_ENGINE_TARGET=/ruta/target-autorizado \
SECUREFLOW_SKILL_ROOT=/ruta/secure-skill \
SECUREFLOW_BENCH_ROOT=/ruta/secure-bench \
bash scripts/demo-local.sh
```

El script usa `mktemp` y retiene los artefactos en un directorio nuevo bajo
`/tmp/secureflow-demo.*`. Nunca sobrescribe inputs. El target debe estar
explícitamente autorizado por quien ejecuta el demo.

## Separación de evidencia

- `run.json` y `engine-report.json` corresponden al scan real local.
- `report.md` es una vista legible del mismo run; conserva candidatos como
  candidatos y omite rationales humanas por defecto.
- `ai-request.json` corresponde al primer candidato de ese run, pero
  `transmitted=false`.
- `advisories.sqlite3` contiene dos source records sintéticos unidos en una
  entidad canónica por alias CVE/GHSA; no es un feed real ni valida findings.
- `contextual-review.json` usa un payload sintético de contrato y el manifiesto
  fixture canónico. No se presenta como review del target escaneado.
- `benchmark.json` resume un resultado histórico público ya retenido. No
  reejecuta Secure Bench ni Secure Engine.

## Paso humano deliberadamente ausente

El demo no llama `review-run` porque no debe fabricar una identidad o decisión
humana. Después de inspeccionar un finding, una persona puede ejecutar:

```bash
cargo run -p secureflow -- review-run \
  --manifest /tmp/secureflow-demo.XXXXXX/run.json \
  --finding-id sf_finding_<id> \
  --decision validated|rejected|abstained \
  --reviewer "Nombre real" \
  --rationale "Evidencia verificable" \
  --output /tmp/secureflow-demo.XXXXXX/run-reviewed.json
```

Sólo ese manifiesto derivado es elegible para `knowledge-import`.
