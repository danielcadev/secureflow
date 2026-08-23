# ADR 0001 — Fronteras y adapters externos

## Estado

Aceptado para el MVP.

## Decisión

SecureFlow será un workspace nuevo que integra Secure Engine, Secure Skill y
Secure Bench inicialmente mediante procesos externos y contratos versionados.
No se moverá ni copiará el código fuente de esos proyectos.

## Motivos

- conserva historial, releases y ownership de cada proyecto;
- reduce acoplamiento entre ciclos de release;
- hace visibles las versiones y hashes utilizados;
- mantiene Secure Bench fuera de la ruta de producción;
- evita mezclar accidentalmente licencias MIT, Apache-2.0 y dependencias de
  terceros;
- permite sustituir un scanner sin reescribir el orquestador.

## Consecuencias

- se necesita validar schemas y exit codes;
- el MVP debe tratar los binarios como dependencias explícitas;
- en Linux el adapter usa grupo de procesos y rlimits, pero el aislamiento de
  filesystem necesita una decisión posterior explícita;
- las pruebas de integración usarán fixtures y reportes retenidos;
- una API Rust directa queda para una decisión posterior, no para el primer
  vertical slice.

## No decidido todavía

- licencia final del repositorio SecureFlow. Cargo declara MIT de forma
  provisional, pero no se debe publicar hasta que el creador confirme la
  decisión y añada el archivo de licencia raíz correspondiente;
- SQLite frente a otro almacenamiento local después del profiling;
- UI nativa frente a una interfaz posterior;
- proveedor de IA concreto para producción.
