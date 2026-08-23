# ADR 0002 — Secure Skill como import contextual

## Estado

Aceptado para el MVP.

## Decisión

SecureFlow integra Secure Skill mediante un adapter Rust de importación y un
envelope propio. No copia la metodología completa, no invoca el modelo y no
proyecta automáticamente sus findings al tipo canónico validado de Secure
Engine.

## Razones

- Secure Skill produce razonamiento contextual, no evidencia determinista
  equivalente a un scanner;
- `verification_status` pertenece al contrato upstream y no demuestra que un
  humano de SecureFlow haya validado el hallazgo;
- conservar el payload, hashes, versión, commit y licencia permite reproducir
  qué metodología produjo la evaluación;
- mantener findings y non-findings separados evita inflar métricas;
- la frontera reduce acoplamiento y permite actualizar Secure Skill sin mover
  su código ni su historial.

## Consecuencias

- el envelope es un artefacto paralelo vinculado por `run_id` y target hash;
- una reconciliación futura entre findings deterministas y contextuales debe
  guardar enlaces explícitos, nunca fusionarlos sólo por similitud textual;
- el ledger actual no acepta estos candidatos porque carecen de decisión humana
  SecureFlow;
- la automatización de la ejecución de la skill queda fuera de este incremento.

## Licencia

Secure Skill declara MIT. El adapter se diseñó contra su contrato público 1.1 y
registra el hash de la licencia usada. SecureFlow conserva una nota de terceros
y no incorpora el texto completo de la skill.
