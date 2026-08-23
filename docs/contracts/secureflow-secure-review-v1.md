# Contrato `secureflow-secure-review-v1`

## Propósito

Este contrato importa una salida JSON de `review-contract` 1.1 de Secure Skill
como una evaluación contextual local y la liga a un `secureflow-run-v1` ya
autorizado. No convierte sus findings en vulnerabilidades confirmadas.

El schema normativo está en
[`schemas/secureflow-secure-review-v1.schema.json`](../../schemas/secureflow-secure-review-v1.schema.json).

## Frontera de decisión

Todo envelope contiene estas constantes:

```json
{
  "semantics": {
    "imported_findings_are": "contextual-candidates",
    "validation_authority": "human-only",
    "no_findings_mean_safe": false
  }
}
```

Por tanto:

- `verification_status: verified` describe el estado declarado por la revisión
  importada; no equivale a `human_review.decision: validated`;
- un `non_finding` no se suma a vulnerabilidades ni demuestra seguridad;
- cero findings no significa que el target esté limpio;
- la incorporación futura a la knowledge base requiere una decisión humana en
  un flujo separado.

## Provenance

El importador no ejecuta Secure Skill. Lee únicamente, con límites de tamaño,
cuatro archivos canónicos dentro del root indicado:

- `package.json` para nombre, versión y licencia declarada;
- `skills/secure/SKILL.md`;
- `skills/secure/references/review-contract.json`;
- `LICENSE`.

Registra el commit suministrado, los SHA-256 de la skill, contrato, licencia y
payload, además del `run_id` y hash del target. Las rutas resueltas deben quedar
dentro del root para impedir escapes mediante symlinks.

El baseline inspeccionado el 23 de agosto de 2026 fue Secure Skill 2.0.0,
commit `e6e80b264007cd33f0dac3efe19f57658cc27b1f`, contrato 1.1 y licencia MIT.
Los hashes se calculan de nuevo en cada importación; esta referencia histórica
no sustituye esa verificación. Cuando el source root contiene `.git`, el
adapter exige además que la revisión declarada coincida con su `HEAD`. Para un
snapshot sin `.git`, la revisión permanece declarada por el operador y son los
hashes de los archivos retenidos los que fijan el contenido.

## Límites

- El payload se limita a 16 MiB y permanece local.
- Los objetos y enums conocidos se validan estrictamente; campos desconocidos
  fallan de forma cerrada.
- Paths de scope y locations deben ser relativos y no contener `..` ni
  separadores de Windows.
- `fix` requiere que el payload declare autorización explícita y remediation;
  importarlo no autoriza ni ejecuta cambios.
- `threat-model` requiere el objeto `threat_model`.
- El payload puede contener fragmentos sensibles en `evidence`; no debe enviarse
  a un proveedor remoto ni importarse al ledger sin redacción y decisión humana.

## CLI

```bash
cargo run -p secureflow -- secure-review-import \
  --review /ruta/review.json \
  --manifest /ruta/secureflow-run.json \
  --secure-skill-root /ruta/secure-skill \
  --secure-skill-revision <commit-completo> \
  --output /ruta/contextual-review.json

cargo run -p secureflow -- secure-review-validate \
  /ruta/contextual-review.json

cargo run -p secureflow -- secure-review-list \
  /ruta/contextual-review.json --format json
```
