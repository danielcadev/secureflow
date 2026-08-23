# ADR 0006: catálogo SQLite separado a escala V1

## Estado

Aceptado para el prototipo local, 2026-08-23.

## Contexto

El ledger JSONL de decisiones humanas fue medido hasta 10.000 registros. A esa
escala carga y valida todo el archivo en aproximadamente 91,5 ms de mediana,
pero reescribe el ledger completo, tiene un límite de 128 MiB y no ofrece
búsqueda textual ni concurrencia de lectura eficiente. Extrapolarlo a cientos
de miles de advisories no era justificable.

La meta se reformuló en unidades distintas:

- 300.000–500.000 vulnerabilidades canónicas como alcance V1 eventual;
- 1.000.000 o más registros de origen/revisiones como capacidad técnica;
- relaciones como una dimensión separada, no como vulnerabilidades adicionales.

## Decisión

- mantener JSONL v2 para el historial pequeño de decisiones humanas;
- añadir dentro de `secureflow-knowledge` un catálogo SQLite v1 para advisories;
- importar OSV desde archivos locales, sin transporte de red;
- conservar cada revisión raw y su hash;
- registrar fuente, licencia declarada, evidencia hasheada y locator;
- fusionar sólo IDs primarios/`aliases` exactos;
- conservar `upstream`/`related` sin fusionarlos;
- usar rangos compactos, sin materializar todas las versiones;
- usar FTS5 contentless y reconstrucción al final de una carga masiva;
- limitar memoria por número de registros y bytes por lote;
- reservar la IA para priorización posterior, nunca para la ingestión masiva.

## Evidencia

El benchmark release sobre NVMe/Btrfs del host documentado midió 100k, 500k y
1M registros sintéticos. Un millón produjo 900k entidades canónicas, ocupó
2,07 GB decimales y terminó normalización + FTS en 104,736 s. La búsqueda exacta
tuvo mediana de 66,451 μs. Véase `docs/knowledge-benchmark.md` para método,
resultados completos y límites.

## Consecuencias

La infraestructura ya demuestra capacidad para un millón de registros
sintéticos sin modelos ni servicios externos. Esto no significa que SecureFlow
ya posea un millón de vulnerabilidades reales, ni que 2,07 GB sea una estimación
válida para feeds reales. El tamaño depende de detalles, rangos, referencias y
revisiones históricas.

La base sigue teniendo un único writer. WAL permite lectores, pero no se ha
medido concurrencia. La eliminación upstream de un alias requiere reconstruir
desde snapshot para dividir componentes. Antes de descargar un feed real deben
aprobarse licencia, procedencia, estrategia incremental y tratamiento visible
de registros rechazados.
