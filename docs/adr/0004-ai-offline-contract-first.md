# ADR 0004 — IA opcional, offline y contract-first

## Estado

Aceptado para el MVP.

## Decisión

La primera integración IA prepara requests locales redacted y aplica respuestas
estructuradas retenidas. El workspace no contiene aún transporte de proveedor.

## Razones

- permite auditar exactamente qué podría salir del equipo antes de habilitar
  red;
- hace medibles budgets, modelo, prompt y tokens sin convertir el modelo en
  autoridad de seguridad;
- evita gastar tokens en findings no seleccionados;
- permite probar invariantes de privacidad y accounting sin credenciales;
- desacopla la familia lógica Luna de identificadores concretos de API.

## Consecuencias

- `ai-prepare` falla si falta enablement o consentimiento explícitos;
- un payload minimizado puede perder contexto y debe abstenerse cuando no basta;
- la respuesta completa se conserva como artefacto local y el run guarda su
  hash y resultado estructurado;
- una futura fase de transporte necesita revisión separada de credenciales,
  residencia de datos, retry, costes, rate limits y logging;
- los modelos más fuertes no se seleccionan automáticamente.
