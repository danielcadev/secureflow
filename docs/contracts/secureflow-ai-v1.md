# Contratos IA v1

## Estado

SecureFlow implementa preparación local y accounting de respuestas. No incluye
un cliente de red ni afirma haber llamado a un modelo real.

Schemas normativos:

- [`secureflow-ai-request-v1`](../../schemas/secureflow-ai-request-v1.schema.json)
- [`secureflow-ai-response-v1`](../../schemas/secureflow-ai-response-v1.schema.json)

## Request redacted

`ai-prepare` requiere simultáneamente `--enable-ai` y
`--consent-redacted-export`. El consentimiento se registra para un envío
posterior, pero el comando sólo escribe un archivo local y reporta
`transmitted=false`.

El payload incluye únicamente metadatos necesarios del finding:

- regla, taxonomía, severidad y confianza;
- paths relativos y coordenadas source/sink;
- tipos y coordenadas de los hops;
- invariante y limitaciones filtradas.

Excluye deliberadamente:

- source code;
- descripciones de evidencia, que pueden contener snippets;
- rationale, identidad y demás metadata de revisión humana;
- paths absolutos.

Un filtro conservador reemplaza campos completos cuando detecta bearer tokens,
authorization headers, asignaciones típicas de secretos, URLs, correos o tokens
largos. Esta redacción reduce riesgo, pero no prueba ausencia perfecta de datos
sensibles; el humano debe inspeccionar el JSON antes de transmitirlo.

## Routing y presupuesto

- proveedor lógico: `openai`;
- familia por defecto: `luna`;
- prompt: `secureflow-ai-triage-v1`;
- máximo: un call por request;
- defaults: 6000 input tokens, 1000 output tokens y 16 KiB de payload;
- se reservan 700 tokens para instrucciones;
- el número de bytes UTF-8 del payload se usa como upper bound conservador de
  tokens del payload, no como medición de tokenizer del proveedor;
- el transporte futuro deberá hacer tokenización real y volver a aplicar los
  límites antes de enviar.

El escalado sólo puede ocurrir ante ambigüedad, nunca automáticamente y siempre
requiere aprobación humana. Este contrato no selecciona aún un identificador
de modelo de API concreto; `luna` es una familia lógica para no acoplar el
contrato estable a nombres de release cambiantes.

## Response y autoridad

Una respuesta contiene assessment, resumen corto, limitaciones tipadas y uso de
tokens. `ai-apply-response` verifica que request, payload, modelo, prompt, run,
target y finding coincidan, y que el consumo esté dentro del presupuesto.

La aplicación escribe otro manifiesto y registra request ID, hashes, modelo,
assessment y tokens. La decisión humana se compara antes/después y debe quedar
idéntica. Incluso `assessment: supports` continúa siendo advisory; no puede
producir `human_review.decision: validated`.

## Comandos

```bash
cargo run -p secureflow -- ai-prepare \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --enable-ai \
  --consent-redacted-export \
  --output /tmp/secureflow-ai-request.json

cargo run -p secureflow -- ai-validate-request \
  /tmp/secureflow-ai-request.json

cargo run -p secureflow -- ai-apply-response \
  --manifest /tmp/secureflow-run.json \
  --request /tmp/secureflow-ai-request.json \
  --response /tmp/secureflow-ai-response.json \
  --output /tmp/secureflow-run-with-ai.json
```

La preparación real de demostración generó 899 bytes para un finding SE1006 y
no transmitió datos. La aplicación de respuestas se verificó sólo con una
respuesta sintética de prueba; no se reporta como evaluación de Luna.
