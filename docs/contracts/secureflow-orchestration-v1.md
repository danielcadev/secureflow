# Contrato `secureflow-orchestration-v1`

Es una máquina de estados local y determinista. Ordena autorización, análisis,
priorización, contexto opcional, IA advisory opcional, validación humana y
evaluación reproducible. No ejecuta red ni scanners.

Los artefactos suplementarios se validan y se enlazan por hashes al mismo run.
Si quedan candidatos pendientes, la siguiente acción sólo puede ser revisión
humana o abstención; el benchmark queda bloqueado. IA y contexto enriquecen,
pero nunca son prerrequisitos para que una persona revise ni autoridad para
validar.
