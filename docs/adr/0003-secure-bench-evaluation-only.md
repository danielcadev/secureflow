# ADR 0003 — Secure Bench sólo en la ruta de evaluación

## Estado

Aceptado para el MVP.

## Decisión

SecureFlow importa resultados retenidos de Secure Bench mediante un adapter
separado. El adapter no forma parte de `scan`, priorización, Secure Skill,
revisión humana ni knowledge import.

## Razones

- evaluar un sistema con el mismo camino que decide findings de producción
  crea riesgo de contaminación y optimización contra el test;
- conservar denominadores, fallos y provenance evita transformar errores en
  resultados limpios;
- no existe un score compuesto neutral que justifique un ranking general;
- los estudios históricos, holdouts retirados y recuperaciones post-open tienen
  interpretaciones distintas que no deben colapsarse.

## Consecuencias

- la importación verifica schema y hashes, pero no reejecuta el experimento;
- `study_kind` queda marcado como declaración del operador;
- TP/FN y FP/TN conservan sus unidades en lugar de alimentar una accuracy
  engañosa;
- cualquier comparación futura debe usar un protocolo preregistrado, mismas
  capacidades, misma población, intervalos de incertidumbre y limitaciones;
- ningún resultado habilita claims de superioridad o production readiness.
