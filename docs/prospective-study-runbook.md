# Runbook del estudio prospectivo ciego

Estado: **preparado, no ejecutado**. No existe todavía un holdout real sellado,
una cohorte reclutada ni resultados humanos. Este documento no autoriza claims
de superioridad.

## Pregunta que sí puede medirse

SecureFlow puede aspirar a superar el desempeño humano en tareas acotadas, no
a ser “mejor que todo humano siempre”. La primera pregunta defendible es:

> En un holdout autorizado de Rust y TypeScript previamente no visto, ¿mejora
> SecureFlow el recall y la precisión de hallazgos validados por minuto frente
> a revisión humana sin SecureFlow, bajo tiempo y capacidades predeclarados?

También deben reportarse los casos donde el humano sea mejor. “Siempre” es un
cuantificador universal que un corpus finito no puede demostrar.

## Diseño mínimo

- 20–40 casos inicialmente, al menos mitad vulnerables y mitad controles;
- Rust y TypeScript separados en los resultados;
- familias predeclaradas: autorización, filesystem, parser, webhook y supply
  chain; no añadir una familia después de ver resultados;
- cohorte mínima de tres revisores con experiencia documentada y distinta del
  creador del corpus;
- diseño crossover por bloques: cada caso lo revisa una condición humana y
  SecureFlow, pero ninguna persona ve dos variantes equivalentes;
- orden aleatorio comprometido antes de ejecutar y límites de tiempo iguales;
- dos adjudicadores independientes y un tercero para desacuerdos;
- labels, PoCs y respuestas esperadas fuera del árbol entregado a participantes
  y sistemas;
- publicación de crashes, abstenciones y resultados negativos.

Un resultado inicial sólo compara esa cohorte, ese corpus y esas capacidades.
Para acercarse a “mejor que un experto fuerte” se necesita una réplica con una
cohorte más experimentada y un holdout nuevo; no basta comparar contra el
propio creador o contra estudiantes sin herramientas equivalentes.

## Separación de artefactos

```text
study-root/
├── public/
│   ├── corpus-manifest.json       # IDs opacos, hashes y paths; sin labels
│   ├── provenance-manifest.json   # origen, autorización y revisión
│   ├── license-manifest.json      # licencia por caso/fixture
│   └── environment-manifest.json  # binarios, configs, recursos y red
├── private-ground-truth/          # custodio distinto; nunca entra al preflight
├── protocol-draft.json
├── sealed-protocol.json
├── submissions/                   # outputs raw, tiempo, coste y abstenciones
└── adjudication/                  # se abre sólo al terminar submissions
```

El manifest público puede indicar `case-0001`, lenguaje y hash, pero no si el
caso es vulnerable, su weakness ni la ubicación esperada. La declaración de
autorización debe conservar propietario, alcance, vigencia y restricciones sin
publicar datos privados.

## Preflight sin abrir labels

Después de congelar una release/configuración y antes de ejecutar:

```bash
cargo run -p secureflow -- benchmark-protocol-preflight \
  --draft study-root/protocol-draft.json \
  --corpus-manifest study-root/public/corpus-manifest.json \
  --provenance-manifest study-root/public/provenance-manifest.json \
  --license-manifest study-root/public/license-manifest.json \
  --environment-manifest study-root/public/environment-manifest.json \
  --output study-root/sealed-protocol.json

cargo run -p secureflow -- benchmark-protocol-validate \
  study-root/sealed-protocol.json
```

El comando comprueba que los cuatro SHA-256 reales coincidan con el draft y
entonces sella el protocolo. No inspecciona ni recibe el ground truth privado.
El protocolo aún debe publicarse o registrarse con un sello de tiempo externo
antes de los resultados para que el preregistro sea verificable por terceros.

## Ejecución

1. Congelar commit, binarios, configuración, máquina, red y presupuesto.
2. El custodio entrega sólo los casos opacos y conserva las etiquetas.
3. Registrar inicio/fin monotónicos, crashes, retries autorizados, tokens y
   coste para cada caso; un timeout no cuenta como resultado limpio.
4. Mantener raw reports y respuestas humanas por hash; no corregir outputs.
5. Cerrar todas las submissions antes de abrir labels.
6. Adjudicar evidencia y exploitabilidad sin conocer qué condición produjo el
   hallazgo cuando sea posible.
7. Calcular TP/FN y FP/TN por separado, intervalos pareados, minutos y
   abstenciones. Publicar también desacuerdos y casos negativos.

## Criterio de “mejor” para la primera réplica

Debe fijarse antes de sellar. Una opción conservadora es exigir simultáneamente:

- límite inferior del intervalo pareado de recall por encima del margen
  predeclarado;
- precisión no inferior dentro de un margen pequeño;
- reducción predeclarada de mediana de minutos de analista;
- ningún aumento oculto de crashes, abstenciones o coste;
- análisis de sensibilidad por lenguaje, familia y revisor.

Si cualquiera falla, el resultado es mixto o negativo. No se transforma en un
claim de superioridad cambiando métricas después de observarlo.

## Bloqueos actuales

- falta seleccionar y licenciar el holdout sin contaminarlo con los fixtures
  públicos ya usados;
- falta un custodio de labels y reclutar revisores/adjudicadores reales;
- falta congelar la configuración exacta de SecureFlow y comparadores;
- falta un contrato de submissions y scoring prospectivo; Secure Bench sólo
  importa hoy resultados retenidos y no debe conocer labels durante ejecución;
- falta definir tratamiento ético, consentimiento, compensación y privacidad
  de participantes.
