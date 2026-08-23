# MVP de SecureFlow

## Alcance

El MVP debe responder una sola pregunta:

> ¿Puede un investigador analizar un repositorio autorizado, recibir candidatos
> deterministas priorizados y validar cada uno con evidencia reproducible sin
> depender de una IA?

## Entregables

1. CLI Rust local. **Implementado en la primera vertical.**
2. Adapter de Secure Engine por proceso externo. **Implementado con límites
   de tiempo y salida.**
3. Validación de `secure-json-v1`. **Implementado.**
4. Manifiesto `secureflow-run-v1`. **Implementado; conserva hashes y deja la
   decisión humana en `pending`.**
5. Priorización determinista y deduplicación. El ordenamiento y la
   deduplicación exacta dentro de un engine ya están implementados; la
   equivalencia entre engines sigue pendiente.
6. Estados `pending`, `validated`, `rejected` y `abstained`. El modelo y el
   comando `review-run` ya los soportan con reviewer, timestamp y rationale.
7. Informe JSON y Markdown. **Implementado:** conserva provenance, accounting,
   evidencia y limitaciones, no llama candidatos “vulnerabilidades” y omite la
   rationale humana por defecto.
8. Almacenamiento local con autoridades separadas. **Ledger JSONL v2
   implementado** para decisiones humanas y **catálogo SQLite/FTS5 v1
   implementado** para registros externos. La capacidad se midió con 100k,
   500k y 1M sintéticos y con 229.644 registros reales aceptados de snapshots
   crates.io, GitHub Actions y npm. Estos conteos no equivalen a
   vulnerabilidades humanas validadas.
9. Fixtures positivos y controles seguros. Hay una prueba mínima y se validó
   la integración con un fixture vulnerable de Secure Engine. El adapter de
   Secure Bench importa result-v2 con hashes y métricas separadas, y un script
   separado ejecuta sus 7 casos vulnerables y 7 controles como diagnóstico
   local. Falta definir y congelar un corpus nuevo/holdout antes de cualquier
   ejecución publicable.
10. Ruta IA opcional, redacted y con presupuesto. **Preparación local y
    accounting de respuesta implementados; desactivada por defecto y sin cliente
    de red. El transporte real sigue pendiente.**
11. Adapter contextual de Secure Skill. **Implementado para importar y validar
    review-contract 1.1 con provenance; no ejecuta la skill ni concede autoridad
    de validación.**
12. Adapter de Secure Bench. **Implementado para importar resultados v2
    retenidos, verificar fingerprints y separar métricas; no ejecuta scanners ni
    permite rankings o claims de superioridad.**

## Orden de implementación

### Fase 1 — Contrato y adapter

- [x] cargar un binario explícito;
- [x] registrar versión y SHA-256;
- [x] ejecutar sin shell;
- [x] capturar stdout/stderr separadamente;
- [x] rechazar schema, paths o reportes inválidos;
- [x] conservar el raw sin modificar;
- [x] aislar el grupo de procesos y matarlo completo al vencer el timeout;
- [x] aplicar en Linux límites de memoria, CPU, descriptores y core dumps;
- [x] exigir Bubblewrap por defecto en Linux, con root RO y red privada;
- [ ] evaluar Landlock/VM/contenedor para perfiles que necesiten aislamiento
  más fuerte o portabilidad fuera de Linux.

### Fase 2 — Modelo y revisión

- [x] transformar candidatos a findings canónicos;
- [x] ordenar candidatos de forma determinista sin convertir el orden en una
  afirmación de validez;
- [x] deduplicar candidatos exactos por fingerprint, regla y ubicaciones;
- [x] mostrar source, sink, flujo, limitaciones y regla;
- [x] exigir decisión humana antes de marcar `validated`.

### Fase 3 — Knowledge base

- [x] comenzar con decenas de registros, no cientos de miles;
- [x] guardar fuente, licencia declarada, hash, versión y relación con el finding;
- [x] distinguir observación exacta y decisión humana mediante campos separados;
- [x] separar el ledger humano del catálogo de advisories externos;
- [x] importar OSV local, conservar revisiones y consultar alias/FTS/paquetes;
- [x] medir capacidad sintética en 100k, 500k y 1M registros;
- [x] validar adapters, licencias y rechazos con snapshots reales;
- [ ] implementar `modified_id.csv` con replay, bajas y recovery antes de llamar
  incremental al pipeline;
- [ ] medir 5–20 millones de relaciones y concurrencia antes de prometerlos;
- [ ] reconciliar claims/reglas entre engines sólo después de construir un corpus
  etiquetado para medir merges incorrectos.

### Fase 4 — IA medida

- [x] preparar sólo findings seleccionados, sin transmitirlos;
- [x] usar Luna como familia lógica por defecto;
- [x] representar escalado sólo para casos ambiguos y bajo aprobación humana;
- [x] registrar presupuestos/tokens, modelo y prompt versionado;
- [x] comprobar que la IA no cambia la decisión humana;
- [ ] medir coste y calidad reales sólo después de aprobar un transporte de
  proveedor y una política de datos.

## Criterios de aceptación

- dos ejecuciones iguales producen el mismo resultado semántico;
- una ejecución sin binario falla claramente y no simula un scan limpio;
- un reporte inválido queda como error operativo;
- un candidato sin evidencia suficiente puede quedar `abstained`;
- ningún finding se valida automáticamente;
- el código fuente no sale del equipo por defecto;
- el consumo de tokens se mide por finding y por fase;
- los repositorios originales no sufren cambios.

## Fuera de alcance

- active scanning o explotación automática;
- parches autónomos;
- despliegue o acciones contra terceros;
- dashboard web completo;
- descarga o ingestión indiscriminada de CVE/NVD/OSV;
- benchmark competitivo o leaderboard;
- soporte universal de lenguajes.
