# Contrato `secureflow-run-v1`

## Propósito

`secureflow-run-v1` es el manifiesto local de una ejecución de SecureFlow. Une
el alcance autorizado, la provenance del análisis, los artefactos producidos,
los candidatos deterministas, la priorización y la decisión humana.

El contrato no contiene el código fuente completo. Las ubicaciones exportadas
son relativas al repositorio y los artefactos se referencian por hash.

El schema normativo está en
[`schemas/secureflow-run-v1.schema.json`](../../schemas/secureflow-run-v1.schema.json).

## Principios normativos

1. La ejecución debe tener un `target` y un `authorization` explícitos.
2. El análisis determinista ocurre antes de cualquier llamada a un modelo.
3. La IA sólo puede enriquecer o priorizar un candidato existente.
4. La IA nunca puede escribir `human_review.decision`.
5. Sólo `human_review.decision = validated` permite tratar un candidato como
   vulnerabilidad validada.
6. El investigador humano conserva el juicio superior y la autoridad final;
   SecureFlow no puede sustituirlo y debe abstenerse cuando falte evidencia.
7. `rejected` y `abstained` son resultados válidos, no errores.
8. Toda afirmación importante debe apuntar a una ubicación, artefacto o hash.
9. Los paths exportados deben ser relativos, POSIX y no contener `..`.
10. Un fallo de scanner, timeout o reporte inválido no se convierte en “limpio”.
11. La evaluación de Secure Bench permanece separada de la decisión de
    producción y no puede inyectar expectativas en el análisis.

El CLI exige un reviewer de autorización. Consentimiento escrito, política de
organización y otras bases documentadas requieren una referencia; una
autorización expirada falla antes de ejecutar el engine. Estos campos son
declaraciones auditables del operador, no una firma criptográfica ni una prueba
legal automática de permiso.

## Estados

### Ejecución

`created`, `running`, `completed`, `partial`, `failed`, `cancelled`.

### Revisión humana

`pending`, `validated`, `rejected`, `abstained`.

`abstained` significa que no hay evidencia suficiente para decidir. No debe
contarse como vulnerabilidad ni como control limpio.

La revisión local produce un manifiesto derivado: el input de una revisión no
se sobrescribe implícitamente, y una decisión ya tomada no puede cambiarse con
`review-run`.

### Validación IA

`not_requested`, `queued`, `completed`, `failed`, `skipped`.

Su estado es auxiliar y nunca sustituye la revisión humana.

## Identidad y reproducibilidad

- `run_id` identifica la ejecución.
- `target.root_sha256` identifica los bytes del árbol analizado mediante
  `secureflow-target-sha256-v2`. El stream canónico separa tipo, cantidad y
  bytes totales, y prefija longitudes de paths y contenidos para que dos árboles
  distintos no compartan la misma serialización antes de SHA-256. `.git` queda
  excluido y cualquier symlink falla cerrado.
- `target.revision` identifica el commit o snapshot cuando existe.
- `engine.binary_sha256` identifica el binario exacto.
- `engine.report_sha256` identifica el reporte recibido.
- `configuration_sha256` identifica la configuración efectiva.
- En el adapter actual, ese hash liga argumentos, timeout, límite de output,
  memoria, CPU y descriptores. No demuestra aislamiento del filesystem.
- El CLI comprueba el hash del target y del binario antes y después del proceso;
  si alguno cambia, falla sin escribir reporte o manifiesto. Es detección
  fail-closed, no un snapshot transaccional: un cambio revertido entre ambas
  mediciones podría no observarse.
- Los outputs derivados no pueden aliasar sus inputs; en Unix también se
  comparan device/inode para rechazar hardlinks. `scan` rechaza además outputs
  dentro del árbol analizado. La comprobación y la escritura no son una única
  operación atómica frente a un actor local concurrente.
- El fingerprint tiene límites fijos de 250.000 archivos, 500.000 entradas,
  16 GiB totales, 2 GiB por archivo y 256 niveles; paths no UTF-8 se rechazan.
  Estos límites previenen entradas no acotadas, pero el tiempo de hashing
  ocurre antes del timeout del engine.
- Los timestamps sirven para auditoría, pero no para identidad semántica.
- Los estados terminales (`completed`, `partial`, `failed`, `cancelled`)
  requieren `completed_at`; `created` y `running` no pueden incluirlo.
- Una decisión humana distinta de `pending` requiere reviewer, timestamp y
  rationale. Un finding `pending` no puede aparentar revisión parcial mediante
  esos campos.

En la primera vertical, el array `findings` se ordena de forma determinista por
severidad, confianza, regla, ubicación de origen, ubicación de sink e ID. Este
orden sólo ayuda a revisar; no es un score de riesgo ni una decisión humana.
Los duplicados exactos dentro de una ejecución se eliminan después de ordenar,
y `summary.duplicate_count` registra cuántos se descartaron. No se afirma
equivalencia entre engines distintos.

## Política de privacidad

El manifiesto puede vivir localmente junto con el reporte, pero una exportación
externa debe excluir:

- rutas absolutas del equipo;
- secretos, tokens y variables de entorno completas;
- contenido fuente no necesario para la evidencia;
- prompts o respuestas completas del proveedor si contienen datos no aprobados.

El payload IA debe conservar una vista redacted y su hash, además del modelo,
versión de prompt, presupuesto y consumo.

`ai_validation` es una evaluación advisory separada de `human_review`. Los
estados inactivos no pueden cargar metadata; `queued` requiere request ID,
provider, modelo, prompt y hash del payload; `completed` exige además hash de
respuesta, tokens y assessment. Los contadores del summary deben coincidir con
los estados y consumos por finding. Ningún estado IA cambia una decisión humana.

El ledger local escribe `secureflow-knowledge-record-v2` y puede importar sólo
findings con decisión humana. Guarda hashes de la rationale, referencia de
evidencia y evidencia de licencia, no sus textos completos ni código fuente.
El lector mantiene compatibilidad estricta con v1 sin migrarlo silenciosamente.

## Ejemplo mínimo

```json
{
  "contract_version": "secureflow-run-v1",
  "run_id": "sf_run_01JEXAMPLE0000000000000000",
  "status": "completed",
  "created_at": "2026-08-23T03:00:00Z",
  "completed_at": "2026-08-23T03:00:01Z",
  "target": {
    "label": "cms-nova-secure-engine-test",
    "root_sha256": "<sha256>",
    "revision": { "kind": "git", "value": "4c3de58000000000000000000000000000000000" },
    "authorization": {
      "status": "authorized",
      "basis": "repository-owner",
      "reviewer": "human"
    }
  },
  "engine": {
    "name": "secure-engine",
    "version": "0.1.10-rc2",
    "binary_sha256": "<sha256>",
    "report_schema": "secure-json-v1",
    "report_sha256": "<sha256>"
  },
  "phases": {
    "deterministic": "completed",
    "prioritization": "completed",
    "validation": "skipped",
    "evaluation": "skipped"
  },
  "findings": []
}
```
