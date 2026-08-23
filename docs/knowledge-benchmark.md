# Benchmarks del almacenamiento local

## Preguntas

1. ¿Hasta qué punto es suficiente el ledger JSONL para decisiones humanas?
2. ¿Puede un catálogo SQLite local normalizar y consultar 100k, 500k y 1M de
   registros sin depender de IA ni servicios externos?

Son workloads distintos. JSONL conserva un historial pequeño y auditable de
decisiones humanas. SQLite sirve advisories externos, alias, paquetes,
revisiones y texto. No se comparan productos ni se mide detección de
vulnerabilidades.

## Entorno

Fecha: 2026-08-23.

- Fedora Linux 7.1.8, x86_64;
- Rust/Cargo 1.97.1, perfil `release`;
- AMD Ryzen 7 5700X, 8 cores/16 threads;
- 15 GiB de RAM;
- resultados principales sobre NVMe con Btrfs en `/home`;
- cinco consultas por clase; se reporta la mediana.

Los resultados de `tmpfs` usados durante desarrollo no forman parte de la
tabla principal, porque serían optimistas frente a almacenamiento persistente.

## Ledger JSONL v2

Comando:

```bash
cargo run --release -p secureflow-knowledge \
  --example ledger_bench -- \
  --record-version v2 --iterations 5 100 1000 10000
```

El fixture se replica con IDs únicos. La generación/escritura no se mide; cada
muestra carga, parsea y valida todo el ledger antes del filtro.

| Registros | Tamaño | Carga + validación mediana | Máximo | Filtro exacto |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 141.500 B | 0,920 ms | 1,188 ms | 0,270 μs |
| 1.000 | 1.415.000 B | 8,717 ms | 10,197 ms | 3,650 μs |
| 10.000 | 14.150.000 B | 91,508 ms | 102,523 ms | 131,172 μs |

Decisión: conservar JSONL para el ledger pequeño, con un writer y cerca de 10k
registros. No usarlo como catálogo global ni extrapolarlo linealmente.

## Catálogo SQLite/FTS5

Comando principal:

```bash
cargo run --release -p secureflow-knowledge \
  --example catalog_bench -- \
  --root target/catalog-bench \
  100000 500000 1000000 --iterations 5
```

Cada registro es OSV sintético y acotado. El 10% comparte un alias exacto con
el registro anterior; por eso 1M registros producen 900k entidades canónicas.
Cada registro tiene un paquete/rango. No son vulnerabilidades reales.

`normalize_ms` incluye generación JSON, parseo, validación, hashing, revisiones
raw, relaciones, paquetes y deduplicación. `index_build_ms` reconstruye FTS5 y
cierra el WAL. `database_bytes` es el archivo final después del checkpoint.

| Origen | Canónicas | DB final | Normalización | FTS | Total | Registros/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100.000 | 90.000 | 206.221.312 B | 3,481 s | 0,844 s | 4,326 s | 23.117,1 |
| 500.000 | 450.000 | 1.036.513.280 B | 30,192 s | 10,157 s | 40,348 s | 12.392,2 |
| 1.000.000 | 900.000 | 2.072.891.392 B | 80,797 s | 23,939 s | 104,736 s | 9.547,8 |

| Origen | Alias exacto | FTS peor caso | Paquete exacto |
| ---: | ---: | ---: | ---: |
| 100.000 | 46,680 μs | 70,584 ms | 112,841 μs |
| 500.000 | 68,291 μs | 408,601 ms | 260,053 μs |
| 1.000.000 | 66,451 μs | 843,406 ms | 450,295 μs |

La consulta FTS busca una frase presente en todos los registros y devuelve sólo
20 resultados: es deliberadamente un caso difícil. Las búsquedas de alias y
paquete son selectivas.

El CSV exacto está en
[`docs/evidence/catalog-benchmark-2026-08-23.csv`](./evidence/catalog-benchmark-2026-08-23.csv).

## Decisión

- La escala objetivo de V1 —300k a 500k entidades canónicas— es técnicamente
  plausible en este host.
- La capacidad de 1M registros de origen está demostrada para este corpus
  sintético, con aproximadamente 2,07 GB y 104,7 s de carga inicial.
- La carga masiva sigue siendo determinista y local; ningún registro pasa por
  un modelo.
- Actualizaciones incrementales deberían procesar sólo registros nuevos o
  modificados. Todavía deben medirse con snapshots reales.
- JSONL y SQLite se mantienen separados porque resuelven autoridades y
  workloads diferentes.

## Límites y trabajo no medido

- Los records reales pueden ser mucho mayores y contener más rangos,
  referencias y revisiones.
- No se midieron todavía 5–20 millones de relaciones; el millón sintético tiene
  aproximadamente una relación primaria y un paquete por registro.
- No se midieron writers concurrentes, crash recovery bajo carga ni hardware de
  baja potencia.
- No se midió una descarga ni actualización de OSV/GHSA/NVD/RustSec.
- El máximo de 4 MiB por record puede rechazar casos reales grandes; un adapter
  debe contabilizarlos y nunca omitirlos silenciosamente.
- El benchmark no mide precisión, falsos positivos, cobertura ni calidad de
  deduplicación semántica.
- Cinco muestras de consulta no permiten presentar p95/p99.

Por tanto, la evidencia permite afirmar “catálogo local medido hasta 1M de
registros sintéticos”, no “base global de 1M vulnerabilidades” ni
“production-ready”.
