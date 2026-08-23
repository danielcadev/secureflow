# Arquitectura inicial

## Objetivo

SecureFlow coordina herramientas especializadas sin convertirlas en una única
caja negra. Cada etapa conserva sus entradas, salidas, hashes, limitaciones y
decisiones.

## Capas propuestas

```text
secureflow-cli
    ├── scope y autorización
    ├── configuración local
    ├── consulta JSON/texto de findings, ledger y catálogo
    └── review-run que escribe un manifiesto derivado

secureflow-orchestrator
    ├── state machine de siete fases
    ├── enlaces por hash y siguiente acción fail-closed
    └── IA opcional, benchmark evaluativo y abstención explícita

secureflow-engine-adapter
    ├── Secure Engine como proceso externo
    ├── secure-json-v1
    ├── timeout, grupo de procesos y output acotado
    ├── rlimits Linux de memoria/CPU/descriptores/core
    ├── Bubblewrap requerido por defecto: root RO y red privada
    └── provenance del binario y reporte

secureflow-model
    ├── findings canónicos
    ├── source/sink/evidence
    ├── ordenamiento y deduplicación exactos por ejecución
    ├── estados humanos
    └── contratos de exportación

secureflow-secure-adapter
    ├── import estricto de review-contract 1.1
    ├── hashes de skill, contrato, licencia y payload
    ├── vínculo con run y target autorizados
    └── candidatos contextuales con autoridad humana

secureflow-knowledge
    ├── ledger JSONL v2 compatible con v1
    ├── decisiones humanas y observaciones exactas repetidas
    ├── catálogo SQLite v2 separado para registros de seguridad externos
    ├── snapshots OSV reproducibles, licencia y cuarentena
    ├── revisiones raw, fuentes, licencias y provenance hasheada
    ├── unión conservadora por aliases exactos; no por texto/IA
    ├── paquetes/rangos compactos e índices de consulta
    ├── correlación conservadora finding-paquete-advisory
    └── FTS5, canonicalización y backups reconstruibles

secureflow-ai
    ├── preparación local con Luna como familia lógica
    ├── payloads mínimos y redacted
    ├── un call, presupuestos y accounting
    ├── escalado sólo ambiguo con aprobación humana
    └── sin transporte de red en el MVP actual

secureflow-bench-adapter
    ├── Secure Bench separado de la ruta de producción
    ├── validación de result-v2 y fingerprints
    ├── TP/FN por expectativas y FP/TN por controles
    ├── protocolo prospectivo sellado con cohorte humana y blinding
    └── sin ranking, superioridad global ni claims de producción
```

## Estructura futura del repositorio

```text
secureflow/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── mvp.md
│   ├── adr/
│   └── contracts/
├── schemas/
├── crates/
│   ├── secureflow-model/
│   ├── secureflow-engine-adapter/
│   ├── secureflow-secure-adapter/
│   ├── secureflow-bench-adapter/
│   ├── secureflow-ai/
│   ├── secureflow-knowledge/
│   ├── secureflow-orchestrator/
│   └── secureflow-cli/
├── tests/
│   ├── contracts/
│   └── fixtures/
└── tools/
```

La estructura es una propuesta. No se deben crear crates adicionales hasta que
exista una frontera de responsabilidad y una prueba que justifique cada uno.

## Límites de integración

- Secure Engine sigue siendo el dueño de `secure-json-v1`.
- Secure Skill sigue siendo instalable y utilizable sin SecureFlow.
- La salida de Secure Skill se conserva en un envelope contextual separado;
  `verified` upstream no equivale a validación humana de SecureFlow.
- Secure Bench no participa en la decisión de producción.
- El adapter de benchmark sólo importa evidencia retenida; no ejecuta scanners
  ni recalcula resultados históricos.
- Los proyectos originales no se copian al monorepo.
- La primera integración es por procesos externos y contratos versionados.
- Una futura dependencia Rust directa requiere una decisión de compatibilidad,
  licencia y ciclo de release separado.

## Invariantes de seguridad

- el target debe estar autorizado antes de ejecutar una fase;
- el análisis estático no ejecuta scripts del target;
- la red está desactivada por defecto;
- ningún path exportado escapa del root lógico del target;
- los secretos nunca forman parte de un payload IA sin redacción y consentimiento;
- el investigador humano sigue siendo mejor para el juicio contextual y sólo
  una decisión humana puede validar un hallazgo;
- cada retry debe ser idempotente y conservar el intento anterior;
- un fallo operativo nunca equivale a un resultado limpio.
