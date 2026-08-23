# Contrato `secureflow-prospective-protocol-v1`

Sella antes de observar resultados la pregunta, corpus, licencias, sistemas,
capacidades, blinding, recursos, retry/crash policy, métricas, incertidumbre y
criterio de éxito. El ID cambia ante cualquier modificación.

El mínimo técnico exige 20 casos (10 vulnerables y 10 controles), holdout no
visto, etiquetas ocultas, SecureFlow, cohorte humana, dos adjudicadores,
precision/recall/tiempo separados, abstenciones y publicación de resultados
negativos. Esto permite una comparación acotada a la tarea; prohíbe claims de
superioridad global y seguridad de producción.

El fixture incluido sólo prueba el contrato con hashes sintéticos. No es un
preregistro real ni un corpus ejecutado.

Para material real, `benchmark-protocol-preflight` recalcula antes de sellar
los hashes del manifest público del corpus, provenance, licencias y entorno.
El comando no recibe ground truth; no puede verificar por sí mismo que el
custodio realmente mantuvo las etiquetas ocultas ni que la cohorte declarada
existe. Esas evidencias siguen siendo humanas/externas. Véase el
[`runbook prospectivo`](../prospective-study-runbook.md).
