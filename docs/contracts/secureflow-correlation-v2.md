# Contrato `secureflow-correlation-v2`

V2 conserva el enlace exacto finding–ecosistema–paquete de v1 y añade una
evaluación conservadora de la versión instalada contra datos OSV retenidos.

## Resultado por advisory

- `affected`: coincidencia exacta en `affected.versions` o inclusión en un
  rango OSV `SEMVER` válido;
- `not-affected`: todos los datos soportados excluyen la versión y no existe
  información no soportada que pueda contradecirlo;
- `unknown`: versión inválida, JSON/eventos inválidos, datos faltantes o rangos
  `ECOSYSTEM`/`GIT` que SecureFlow no sabe evaluar localmente;
- `not-evaluated`: no se proporcionó versión.

Los límites `fixed` son exclusivos, `last_affected` inclusivos, `introduced: 0`
representa el inicio y la precedencia SemVer ignora build metadata. Los eventos
deben estar ordenados y alternar intervalos de forma válida; SecureFlow se
abstiene ante ambigüedad en vez de reparar datos silenciosamente.

Cada assessment conserva hashes de `ranges_json`/`versions_json` y, cuando un
rango coincide, el hash del rango exacto. El resumen reconcilia affected,
not-affected, unknown y not-evaluated.

## Límite de autoridad

Una versión afectada significa que el advisory declara ese paquete/rango. No
prueba que el finding tenga la misma causa, que la dependencia sea alcanzable,
que el código sea explotable ni que la aplicación sea vulnerable. Por eso:

- `version_result_validates_vulnerability=false`;
- `causal_relationship_asserted=false`;
- `changes_human_decision=false`;
- `validation_authority=human-only`.

V1 continúa validándose para evidencia histórica; V2 es la escritura por
defecto. La provenance incluye snapshots completos y, cuando existen, deltas
completos del catálogo.
