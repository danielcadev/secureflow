# Contrato `secureflow-correlation-v1`

Vincula un finding exacto con contexto de paquete declarado por el operador y
coincidencias del catálogo por ecosistema+nombre. Conserva hash del run,
snapshots completos y reconstrucción canónica.

No evalúa rangos de versión, no afirma causalidad y no cambia la decisión
humana. Una lista vacía no prueba seguridad; una lista no vacía tampoco valida
el finding. El ID se deriva del contenido estable y no del timestamp de
creación.
