# SecureFlow Web v1

## Propósito

SecureFlow Web v1 construye un inventario determinista de APIs web en targets
explícitamente autorizados y compara rutas implementadas, documentadas,
observadas y protegidas. La primera vertical soporta convenciones locales de
Next.js App Router y Pages Router.

V1 no ejecuta código del target, no abre conexiones de red y no interpreta una
ruta oculta o no documentada como protegida.

## Contratos

- `secureflow-web-scope-v1`: autorización vigente, repositorios y assets
  permitidos, límites y política offline.
- `secureflow-web-inventory-v1`: fuentes con licencia/provenance, rutas,
  parámetros, controles conocidos, evidencia, limitaciones y accounting.
- `secureflow-web-inference-v1`: candidatos de API correlacionados desde código
  cliente, manifests y contratos locales, con confianza, provenance,
  abstenciones y estado de presencia.
- `secureflow-web-assessment-v1`: candidatos, hardening, abstenciones y
  validaciones humanas reproducibles.
- `secureflow-web-case-v1`: ground truth de un caso sintético o licenciado.
- `secureflow-web-lab-result-v1`: comparación evaluativa de rutas con
  precision, recall, F1, faltantes y reportes inesperados.
- `secureflow-web-development-corpus-v1`: 20–40 aserciones sintéticas de
  desarrollo, con licencia, procedencia y split explícito.
- `secureflow-web-corpus-result-v1`: resultados por caso que bloquean claims de
  holdout, superioridad y seguridad de producción.

Los schemas normativos viven en `schemas/` y rechazan campos desconocidos.

## Invariantes

- La autorización debe existir, tener referencia, reviewer y expiración futura.
- `network_execution` es `disabled`; todos los presupuestos de requests son cero.
- El root se liga mediante un hash determinista del árbol antes y después del
  inventario. Un cambio concurrente invalida la ejecución.
- No se siguen symlinks ni se leen rutas fuera del root.
- Los controles desconocidos no se consideran seguros.
- Una API no documentada produce hardening, no una vulnerabilidad automática.
- Una ruta inferida siempre conserva `classification=candidate` y
  `vulnerability_status=not-assessed`; la confianza no sustituye validación.
- Sólo se aceptan rutas same-origin que comiencen en `/`; URLs externas y
  traversal no se convierten en targets. Strings dinámicos no resueltos quedan
  como candidatos abstained sin una ruta ejecutable.
- Sólo una observación con evidencia de reproducción y decisión humana puede
  usar `human-validated-vulnerability`.
- Una revisión humana crea un assessment derivado con
  `parent_assessment_id`; preserva el artefacto previo y liga la evidencia
  retenida por SHA-256 en vez de sobrescribir la decisión original.
- Cero observaciones no prueba seguridad.
- Los IDs de fuentes, casos y resultados son identidades ligadas al contenido;
  detectan inconsistencias accidentales, pero no son firmas ni acreditan quién
  produjo el artefacto.

## Laboratorio local

El fixture `tests/fixtures/web-nextjs` es sintético, no contiene APIs privadas y
cubre App Router, Pages Router, route groups, parámetros dinámicos, middleware,
server actions, llamadas cliente, un manifest retenido y artefactos
OpenAPI/GraphQL/tRPC.

Las pruebas comparan la salida real con `expected.json`, validan los contratos,
comprueban determinismo y verifican que el hash del target no cambie. El binario
`secureflow-web-lab` compara un inventario retenido con un caso y escribe JSON y
SARIF mediante creación sin overwrite:

```bash
cargo run -p secureflow-web --bin secureflow-web-lab -- \
  inventory.json expected.json result.json result.sarif
```

El resultado es diagnóstico de desarrollo. Sus campos de claims prohíben usarlo
como evidencia de superioridad o production readiness.

El CLI principal expone el flujo sin depender de los binarios auxiliares:

```bash
cargo run -p secureflow -- web-scope-create --help
cargo run -p secureflow -- web-inventory-nextjs --help
cargo run -p secureflow -- web-infer --help
cargo run -p secureflow -- web-assess --help
cargo run -p secureflow -- web-review-assessment --help
cargo run -p secureflow -- web-lab --help
cargo run -p secureflow -- web-corpus-evaluate --help
```

El corpus versionado en `tests/fixtures/web-nextjs/corpus.json` contiene 24
aserciones atómicas sobre inventario, correlación, decoys y semántica segura.
La ejecución retenida pasó 24/24. Es un corpus conocido por los desarrolladores,
no una prueba independiente ni un estudio con humanos.

La inferencia local consume un scope sellado y un inventario ya producido. La
salida debe quedar fuera del target para conservar el árbol autorizado:

```bash
cargo run -p secureflow-web --bin secureflow-web-infer -- \
  /target/autorizado scope.json inventory.json /evidencia/inference.json
```

## Límites actuales

- La detección de métodos de App Router reconoce exports nombrados sin ejecutar
  TypeScript; Pages Router conserva métodos como desconocidos.
- Middleware matchers y alcance real de server actions aún requieren análisis
  adicional.
- V1 infiere desde OpenAPI JSON, schemas GraphQL, routers tRPC simples,
  llamadas literales `fetch`/Axios y manifests Next.js retenidos. OpenAPI YAML,
  composición de routers, aliases, strings dinámicos y tráfico autorizado aún
  requieren adaptadores posteriores.
- `.next` se excluye del hash actual y no se lee directamente. Los manifests se
  analizan sólo cuando están retenidos dentro del árbol autorizado y hasheado.
- No existe adquisición DNS/CT real. Los futuros tests usarán respuestas
  simuladas antes de considerar un adapter pasivo en red.
- El uso de `symlink_metadata`, lectura y hash antes/después reduce cambios
  concurrentes, pero no forma un snapshot transaccional. Un atacante local que
  pueda intercambiar y restaurar archivos durante la lectura conserva una
  ventana TOCTOU residual; targets hostiles requieren aislamiento de filesystem
  más fuerte.
