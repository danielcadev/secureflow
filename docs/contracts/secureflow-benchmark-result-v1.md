# Contrato `secureflow-benchmark-result-v1`

## Propósito

Este contrato resume un resultado retenido `secure-bench-result-v2` sin
ejecutar el benchmark ni ningún scanner. Secure Bench permanece fuera de la
ruta que decide si un finding de producción es válido.

El schema normativo está en
[`schemas/secureflow-benchmark-result-v1.schema.json`](../../schemas/secureflow-benchmark-result-v1.schema.json).

## Verificación de entrada

La importación requiere cuatro entradas explícitas:

1. resultado `secure-bench-result-v2`;
2. run manifest exacto referenciado por el resultado;
3. suite exacta referenciada por el resultado;
4. root y commit exactos de Secure Bench.

El adapter carga `schemas/result-v2.schema.json` desde ese root, valida el
resultado con el schema upstream y comprueba que los SHA-256 calculados de
suite y run coincidan con `provenance.suite_fingerprint` y
`provenance.run_manifest_fingerprint`. También conserva hashes del resultado,
schema, licencia y binario evaluado. Si el root contiene `.git`, el commit
declarado debe coincidir con `HEAD`; en un snapshot sin `.git`, la revisión es
una declaración del operador ligada a hashes de contenido.

No se ejecuta Cargo, Secure Bench, Secure Engine ni código del corpus durante
la importación.

## Métricas separadas

SecureFlow no inventa un score compuesto. Conserva las diez ratios de calidad,
counts, fallos y mediciones de rendimiento de Secure Bench. La proyección
TP/FP/TN/FN explicita unidades distintas:

- TP: expectativas vulnerables detectadas;
- FN: expectativas vulnerables elegibles sin crédito de detección;
- FP: casos de control seguro con al menos una alerta;
- TN: casos de control seguro completados sin alerta.

TP/FN usan `vulnerable-expectation`; FP/TN usan `safe-control-case`. Por ello no
deben sumarse ciegamente para producir una exactitud global. Un crash, timeout,
missing, unsupported o parse failure nunca se transforma en un control limpio;
en el lado vulnerable, un caso elegible sin detección no recibe crédito.

## Frontera de claims

Todo envelope fija:

```json
{
  "claims": {
    "evaluation_only": true,
    "ranking_allowed": false,
    "superiority_claim_allowed": false,
    "production_readiness_claim_allowed": false
  }
}
```

`study_kind` es una clasificación declarada por el operador, no inferida por el
adapter. Debe contrastarse con la metodología y las limitaciones del estudio
original antes de publicar resultados.

`local-development-diagnostic` identifica ejecuciones iterativas visibles para
los desarrolladores. No es preregistro, holdout ni evidencia publicable de
superioridad.

## Baseline histórico verificado

El 23 de agosto de 2026 se importó, sin reejecutarlo, el baseline público Phase
1 de Secure Engine 0.1.0:

| Campo | Valor retenido |
| --- | ---: |
| Suite | `phase-1-javascript-typescript` |
| Casos vulnerables / controles seguros | 7 / 7 |
| TP expectativas | 0 |
| FN expectativas | 7 |
| FP controles seguros | 3 |
| TN controles seguros | 4 |
| Recall vulnerable | 0/7 (0.00%) |
| Tasa FP en controles intentados | 3/7 (42.85%) |
| Cobertura limpia de controles elegibles | 4/7 (57.14%) |
| Fallos operativos | 0 |
| Duración cold total | 70 ms / 14 muestras |

El resultado es sintético, histórico y público. No mide el Secure Engine actual,
no permite afirmar superioridad o inferioridad general y no es evidencia de
production readiness. Su valor aquí es demostrar importación neutral y
reproducible, incluso cuando el resultado es desfavorable.

Provenance de la comprobación:

- Secure Bench commit `485402e099f7e99577203e56604bbaadec0623fa`;
- result SHA-256 `b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099`;
- run SHA-256 `21d707e281109630aa2cc2172d8664dad3d55439811578aa65943cb00e2f6c41`;
- suite SHA-256 `57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b`;
- result schema SHA-256 `b16fc0667b870c2639e677d3de1daa847d41669ca4a05cef041b6cfe3a064eb7`.

## CLI

```bash
cargo run -p secureflow -- benchmark-import \
  --result /ruta/result.json \
  --run-manifest /ruta/run.json \
  --suite /ruta/suite.toml \
  --secure-bench-root /ruta/secure-bench \
  --secure-bench-revision <commit-completo> \
  --study-kind historical-public-diagnostic \
  --output /ruta/benchmark-envelope.json

cargo run -p secureflow -- benchmark-validate \
  /ruta/benchmark-envelope.json

cargo run -p secureflow -- benchmark-summary \
  /ruta/benchmark-envelope.json --format text
```
