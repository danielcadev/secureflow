# ADR 0005: knowledge v2 y deduplicación exacta trazable

## Estado

Aceptado para el MVP.

## Contexto

El registro v1 preservaba la decisión y provenance del scanner, pero no hacía
explícita la licencia del source ni podía enlazar la misma observación entre
ejecuciones. Cambiar v1 en sitio haría ambiguos los artefactos ya creados.

## Decisión

- conservar lectura estricta de v1;
- escribir nuevas importaciones como `secureflow-knowledge-record-v2`;
- exigir al operador un estado de licencia, permitiendo `unknown`;
- requerir evidencia hasheada para una declaración SPDX;
- conservar observaciones repetidas y enlazarlas al primer registro v2;
- limitar el ledger a 128 MiB y mantener un único writer durante el MVP;
- no inferir equivalencia entre engines ni migrar v1 automáticamente.

## Consecuencias

El historial y los desacuerdos humanos permanecen auditables. El ledger puede
contener v1 y v2, por lo que los consumidores deben mirar `record_version` por
registro. La deduplicación es deliberadamente conservadora y puede dejar
duplicados semánticos; reducirlos requerirá un reconciliador evaluado por
separado. La declaración de licencia no constituye asesoría legal.
