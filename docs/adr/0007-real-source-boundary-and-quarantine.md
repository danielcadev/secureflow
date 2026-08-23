# ADR 0007: adquisición separada, licencias por fuente y cuarentena

## Decisión

La red termina antes del parser. Cada snapshot conserva el ZIP, revisión y
hash; SecureFlow sólo acepta familias de IDs con una política y evidencia de
licencia explícitas. El resto se retiene en cuarentena con causa estable.

OSV es transporte/agregación, no una licencia global. GitHub Advisory Database,
RustSec y OpenSSF Malicious Packages permanecen fuentes distintas aun cuando
aparecen en el mismo ZIP de ecosistema.

## Consecuencias

- se puede reconstruir y auditar exactamente qué entró;
- los cambios de política son visibles y reproducibles;
- el número aceptado puede ser mucho menor que el ZIP, y eso es correcto;
- un feed de 227k registros no autoriza llamarlos 227k vulnerabilidades;
- incrementales quedan pendientes hasta tener semántica de eliminación y
  recovery equivalente al snapshot completo.
