# Diagnóstico: SecureFlow Recon / API Exposure

## Decisión

Sí debe existir como módulo de SecureFlow, pero **no debe implementarse aún como
scanner de red general**. La frontera recomendada es un componente futuro
`secureflow-recon` que produce un inventario trazable y una matriz de cobertura;
Secure Engine y Secure Skill consumen ese contexto sin convertir una ruta
descubierta en vulnerabilidad.

El primer incremento debe ser offline y local. El descubrimiento pasivo de
subdominios y las comprobaciones HTTP requieren antes un contrato de
autorización verificable, protección frente a scope escape y un benchmark
local. “El usuario escribió `--authorized`” no es evidencia suficiente para
automatizar tráfico contra terceros.

## Flujo propuesto

```text
autorización + allowlist versionada
              │
              ▼
collectors offline ──► inventario normalizado ──► matriz de coverage/auth
  Next.js                 declared                  declarada/documentada/
  OpenAPI                 documented                observada/esperada
  tRPC/GraphQL            observed                         │
  HAR/logs del dueño                                      ▼
                                                checks seguros opcionales
                                                         │
Secure Engine ──► inventario/coverage ──► Secure Skill ──► humano ──► Bench
```

Las cuatro clases no se fusionan silenciosamente:

- `declared`: extraída de código o configuración;
- `documented`: OpenAPI/Swagger/schema entregado;
- `observed`: build manifests, HAR o logs proporcionados por el propietario;
- `expected-control`: método, auth, rol, tenant, cache y respuesta esperados.

Las diferencias generan candidatos como `declared-not-documented`,
`observed-not-declared`, `missing-auth-expectation` o
`inconsistent-tenant-control`. Ninguna diferencia prueba exposición ni
exploitabilidad.

## Scope y autorización

Antes de cualquier red, un contrato versionado debería fijar y hashear:

- propietario/autorizador, base de autorización y referencia retenida;
- inicio, expiración y zona horaria;
- dominios exactos, wildcards permitidos, IP/CIDR, puertos y protocolos;
- repositorios, commits y entornos (`local`, `staging`, producción si procede);
- métodos HTTP permitidos, identidades sintéticas y datos de prueba;
- acciones prohibidas, máximo RPS, concurrencia, bytes y duración;
- política de redirects, DNS, proxies y proveedores externos;
- contacto de emergencia y reglas de parada.

Cada resolución DNS y redirect debe revalidarse contra el allowlist para evitar
rebinding o salto a un SaaS fuera de scope. Wildcard DNS, CDN compartido y
subdominios de terceros se registran como ambiguos; no se sondean por defecto.
La expiración o la falta de evidencia detiene la fase. El modo inicial es
`offline/passive`; la red requiere opt-in separado y registro de cada request.

## Inventario Next.js

El collector local puede analizar sin ejecutar el target:

- `app/**/page.*`, `layout.*`, `route.*`, `default.*` y metadata relevante;
- `pages/**` y `pages/api/**`;
- segmentos dinámicos/catch-all, route groups, parallel e intercepting routes;
- `middleware.*`, matchers, rewrites, redirects, `basePath` e i18n;
- exports de métodos en route handlers y patrones de auth cercanos;
- manifests de build suministrados (`routes-manifest`, pages/app build manifests)
  con versión de Next.js retenida;
- server actions como capacidades invocables, **no** como endpoints HTTP
  estables inferidos automáticamente.

Los manifests internos cambian entre versiones; un parser debe abstenerse ante
un formato desconocido. No se ejecutan builds, plugins, imports ni scripts del
repositorio durante inventario. Rutas como `/admin` sólo elevan prioridad; el
nombre no implica que sean privadas o vulnerables.

## Inventario de APIs

Adapters separados pueden importar:

- OpenAPI/Swagger, conservando versión, servers, security schemes y operación;
- routers tRPC y sus middlewares/procedures desde AST o metadata entregada;
- schemas GraphQL y resolvers desde código o introspección ya proporcionada;
- handlers de Next.js y otros frameworks explícitamente soportados;
- HAR/logs del propietario después de redacción, límite de tamaño y revisión de
  licencia/privacidad.

La introspección GraphQL remota, crawling y Certificate Transparency son red,
no “offline pasivo”. Deben vivir tras el scope gate, respetar términos y poder
desactivarse por fuente. Nunca se almacenan cookies, authorization headers,
tokens, bodies completos o secretos; se conservan campos minimizados, hashes y
evidencia redactada.

## Checks seguros futuros

Sólo sobre loopback/fixtures en el MVP. Para un entorno remoto posterior:

- headers CORS/cache y tipos de contenido;
- errores verbosos con patrones redactados;
- respuesta que excede un schema o allowlist de campos;
- diferencias de status/schema entre identidades sintéticas autorizadas;
- endpoint esperado como autenticado que responde sin identidad;
- aislamiento tenant usando cuentas y datos sintéticos provistos por el dueño.

Incluso un `GET` puede tener side effects. No se enviarán métodos, cuerpos,
parámetros ni credenciales que no estén preautorizados. Se prohíben explotación,
credential stuffing, enumeración masiva, extracción de secretos, descarga de
datos reales, bypass activo y pruebas destructivas. Las respuestas se acotan,
redactan y hashean; una señal se valida sólo con evidencia humana.

## Datos y almacenamiento

El inventario de activos no debe mezclarse con advisories públicos ni con el
ledger de decisiones humanas. Requiere un store local separado con TTL y nivel
de sensibilidad. Un fixture API debería contener como mínimo:

| Campo | Función |
| --- | --- |
| framework/version | parser y compatibilidad esperada |
| language, method, route pattern | identidad declarada |
| origin | código, build, spec o tráfico del dueño |
| auth, roles, tenant | controles esperados |
| safe/vulnerable control | label privado del benchmark |
| request fixture | sintético, acotado y no secreto |
| expected status/schema/fields | oracle predeclarado |
| evidence locations | líneas, manifest o intercambio redactado |
| provenance/license | uso y redistribución permitidos |

Prioridad: fixtures propios sintéticos y proyectos con licencia clara. No
copiar endpoints privados, HAR reales o corpus de terceros a una base pública.

## MVP realista de 2–4 semanas

1. Contrato de autorización/allowlist y esquema de inventario, sin red.
2. Parser Next.js para un subconjunto versionado: App Router, Pages Router,
   route handlers, middleware y manifests conocidos.
3. Import OpenAPI 3.x y matriz `ruta × método × auth × rol × tenant`.
4. Comparador de conjuntos declared/documented/observed con abstención ante
   ambigüedad.
5. 20–40 fixtures locales safe/vulnerable con licencias y ground truth separado.
6. Checks HTTP únicamente contra un servidor fixture en loopback, con RPS,
   timeout, bytes y métodos fijados.
7. Envelope hacia Secure Skill y decisión humana; nada se marca validated solo.
8. Adapter de Secure Bench para recall/precision de inventario y candidatos,
   tiempo, abstenciones y fallos operativos.

Subdominios remotos, crawling genérico, browser automation, GraphQL remoto y
validación con cuentas multi-tenant reales quedan fuera del primer MVP.

## Cómo medirlo frente a humanos

Tareas estrechas y adjudicables:

1. enumerar rutas/métodos reales de una aplicación Next.js congelada;
2. completar correctamente su matriz auth/roles/tenant;
3. detectar discrepancias entre código, OpenAPI, manifests y HAR redactado;
4. priorizar respuestas excesivas o endpoints sin el control esperado;
5. producir evidencia reproducible por minuto de analista.

Reportar por separado recall/precision de rutas, recall/precision de
discrepancias validadas, FP/FN, minutos, wall-clock, abstenciones y cobertura de
framework. Un estudio crossover ciego debe usar un holdout nuevo y revisores
externos al corpus. Superar la mediana de una cohorte en esas tareas no equivale
a superar “al mejor humano” ni a garantizar seguridad del sistema.

## Riesgos y condiciones de avance

- legal/scope: autorización débil, activos compartidos o expirados;
- seguridad: SSRF, DNS rebinding, redirects, side effects y fuga en logs;
- exactitud: rutas dinámicas, rewrites, generación runtime y server actions;
- privacidad: HAR, tokens, PII y nombres internos;
- licencia: specs/builds/código privados y fuentes CT;
- reproducibilidad: builds y tráfico volátiles;
- coste: crawling y análisis IA innecesarios.

No se crea el crate hasta aprobar el contrato de scope, fixtures y métricas. El
primer código debe demostrar inventario offline y loopback; sólo después una
ADR separada puede autorizar un adapter de red.
