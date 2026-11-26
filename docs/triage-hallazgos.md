# Registro de triage de hallazgos · CenfoPay
- Reglas generales: `semgrep scan --config p/python --metrics=off app/` → 10 hallazgos, 151 reglas
- Reglas propias: `semgrep scan --config security/semgrep/reglas-cenfopay.yml --metrics=off app/` → 9 hallazgos, 6 reglas

**Resumen:**
- **Solo las generales** encontraron 3 fallas: MD5, inyección de comandos y YAML inseguro.
- **Solo las propias** encontraron 5 tipos de falla (7 hallazgos): las 2 inyecciones SQL, el recorrido de rutas, la contraseña en los registros y los 3 secretos embebidos.
- **En 2 líneas coinciden pero diagnostican distinto** (`__init__.py:44` y `run.py:9`).
- Las generales repiten hallazgos (10 hallazgos para 5 ubicaciones), lo que genera ruido. Las propias son más precisas (9 hallazgos para 9 puntos concretos).

> Una fila por hallazgo revisado. La **huella** es la columna `huella` de
> `reportes/hallazgos-normalizados.csv` (la genera `tools/security_gate.py`).
> Decisión: **VP** verdadero positivo · **FP** falso positivo · **RA** riesgo aceptado (con excepción y vencimiento).

| # | Huella | Herramienta | Regla / CVE | Ubicación | Severidad | Decisión | Justificación (contexto, explotabilidad, evidencia) | Acción | Responsable | Fecha |
|---|--------|-------------|-------------|-----------|-----------|----------|------------------------------------------------------|--------|-------------|-------|
| 1 | — | bandit + semgrep | B602 · subprocess-shell-true (CWE-78) | __init__.py:86 resolver() · antes | HIGH | VP | El atacante elige el host y este llegaba directo a la terminal. Se usa en un endpoint público y no había otra protección. | Corregido: lista blanca + socket, sin terminal | Karina Montero | 2026-11-25 |
| 2 | — | bandit + semgrep | B506 · avoid-pyyaml-load (CWE-502) | __init__.py:95 importar() · antes | MEDIUM | VP | El atacante envía el YAML y el lector inseguro podía ejecutar código. Endpoint en uso, sin otra protección. | Corregido: yaml.safe_load + validación | Karina Montero | 2026-11-25 |
| 3 | — | bandit + semgrep | B608 · cenfopay-sql-injection (CWE-89) | __init__.py:57 login() y :71 movimientos() · antes | MEDIUM | VP | El atacante escribe el usuario o la fecha y se pegaban en la consulta SQL. Se usa en el login, sin otra protección. Bandit le dio confianza baja, pero la prueba confirma que era real. | Corregido: consultas con «?» | Karina Montero | 2026-11-25 |
| 4 | — | bandit + semgrep | B324 · md5-used-as-password (CWE-327) | __init__.py:54 login() · antes | HIGH | VP | Las contraseñas se guardaban con MD5 sin sal; si se filtra la base, se descifran en minutos. Se usaba en cada login. | Corregido: scrypt + migración automática | Karina Montero | 2026-11-25 |
| 5 | — | bandit + semgrep | B105 · secreto-embebido (CWE-798) | config.py:10 y :13 · antes y actual | LOW | VP | No es un dato del atacante: el riesgo es que cualquiera que lea el código vea el secreto. Se usa en ejecución y aún no tiene protección. | Pendiente semana 4: mover a variable de entorno | Karina Montero | 2026-11-25 |
| 6 | — | bandit | B108 · /tmp/cenfopay.db | config.py:26 · antes | MEDIUM | FP | Es una ruta fija que el atacante no controla y solo se usa en las pruebas. | # nosec B108 con el motivo | Karina Montero | 2026-11-25 |
| 7 | — | semgrep | useless-inner-function | __init__.py, rutas de create_app() | WARNING | FP | La regla cree que esas funciones no se usan, pero Flask sí las usa como rutas. No hay dato de entrada ni riesgo. | Excepción en la política con vencimiento | Karina Montero | 2026-11-25 |
| 8 | — | bandit + semgrep | B324 · md5 | auth.py:30 · actual | HIGH | RA | MD5 solo sirve para reconocer contraseñas viejas una vez y cambiarlas a scrypt. Las nuevas nunca usan MD5. | # nosec B324 y # nosemgrep con el motivo | Karina Montero | 2026-11-25 |
| 9 | — | trivy-dependencias | CVE-2026-97687, CVE-2026-97689 (urllib3 2.7.0) · CVE-2026-114613, GHSA-6v7p-g79w-8964 (msgpack 1.1.2) · CVE-2025-47273 (setuptools 70.3.0) | Imagen: pip/_vendor/bom.cdx.json en /opt/venv y /usr/local | HIGH | VP | No venían de requirements.txt (que ya tenía urllib3 2.8.0), sino de las librerías empaquetadas dentro de pip, declaradas en su SBOM. Ni la última versión de pip las corrige, y la app no usa pip en ejecución. | Corregido: se quitó pip de la imagen final (en el venv y en la imagen base). Verificado con Trivy: 0 HIGH | Karina Montero | 2026-11-25 |

## Criterios de decisión usados
- **FP**: la regla dispara pero el flujo de datos no es explotable en este contexto (explica por qué).
- **RA**: es real, pero se acepta temporalmente: existe un control compensatorio y una fecha de vencimiento.
- Todo FP o RA se refleja en el código (`# nosemgrep: <regla>` / `# nosec <id>`) **o** en
  `security/politica-umbrales.yml > excepciones`, nunca solo en este documento.
