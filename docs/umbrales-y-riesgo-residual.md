# Justificación de umbrales de bloqueo y riesgos residuales · CenfoPay

> Este documento acompaña a `security/politica-umbrales.yml`. Cada número de la
> política debe tener aquí su razón. Se evalúa en el criterio 4 de la rúbrica del proyecto.

## 1. Contexto de riesgo de la aplicación
- Tipo de datos que maneja (ficticios en el curso, pero tratados como si fueran reales):
- Exposición (Internet / red interna / solo laboratorio):
- Marco de referencia aplicable (p. ej. PCI-DSS 6.2-6.3, Ley 8968, normativa SUGEF de TI):

## 2. Umbrales por herramienta
| Herramienta | Severidad | Umbral | Modo | Por qué este número (impacto, explotabilidad, ruido, costo de bloquear) |
|-------------|-----------|-------:|------|--------------------------------------------------------------------------|
| semgrep     | ERROR     | 0      |      |                                                                          |
| zap         | High      | 0      |      |                                                                          |
| zap         | Medium    |        |      |                                                                          |
| hadolint    | error     |        |      |                                                                          |
| trivy-so    | CRITICAL / HIGH |  |      |                                                                          |
| trivy-dependencias | CRITICAL / HIGH | |  |                                                                          |
| bandit      | HIGH      |        |      |                                                                          |
| gitleaks    | SECRETO   | 0      |      |                                                                          |
| endurecimiento | ALTA   |        |      |                                                                          |
| registros   | ALTA      | 0      |      |                                                                          |

***********************************************************

| semgrep     | ERROR     | 5      | bloquear | Límite de tolerancia: son los 5 hallazgos ERROR que había al iniciar. Se toleran las fallas heredadas, pero ningún cambio nuevo puede agregar otra. Baja a 0 en la semana 3, cuando se corrige el código |
| zap         | High      | 0      | bloquear | Una alerta High en la app encendida es explotable desde afuera; no se tolera ninguna |
| zap         | Medium    | 3      | bloquear | Límite de tolerancia: son las 3 alertas Medium que había al iniciar. Impacto moderado; se corrigen en la semana 3 |
| hadolint    | error     | 0      | bloquear | Un error en el Dockerfile depende solo de nosotros y es barato de corregir; no hay razón para tolerarlo |
| trivy-config | CRITICAL / HIGH | 0 / 0 | bloquear | Configuración insegura de la imagen (p. ej. correr como root); es configuración propia y se corrige sin depender de terceros |
| trivy-so    | CRITICAL / HIGH | 0 / 0 | bloquear (solo_con_correccion: true) | Solo detiene si existe un parche disponible que no aplicamos. Las fallas sin arreglo (p. ej. libexpat CVE-2026-115506) no bloquean: detener el cambio no reduce el riesgo; se documentan como riesgo residual |
| trivy-dependencias | CRITICAL / HIGH | sin umbral (`umbrales: {}`) | solo reporta (semana 2) | Las librerías viejas necesitan Python 3.9 y se actualizan en la semana 3. Bloquear hoy detendría todo sin poder corregirlo (p. ej. PyYAML CVE-2020-14343). Desde la semana 3 pasa a 0 |
| bandit      | HIGH      | 0      | pendiente (semana 3) | Aún comentado en la política; se activa con `semana.sh 3` |
| gitleaks    | SECRETO   | 0      | pendiente (semana 4) | Se activa con `semana.sh 4` |
| endurecimiento | ALTA   | 0      | bloquear | Asegura que se mantengan las protecciones END-01…END-12 (usuario no root, sin secretos, solo lectura). Una regresión aquí reabre riesgos ya cerrados |
| registros   | ALTA      | 0      | pendiente (semana 4) | Se activa con `semana.sh 4` |

## 3. Disparadores
| Evento | Qué corre | Por qué |
|--------|-----------|---------|
| pull_request a main | | |
| push a main | | |
| schedule semanal | | |
| workflow_dispatch | | |

## 4. Riesgos residuales (lo que queda abierto después de corregir)
| # | Riesgo | Origen (hallazgo/huella) | Por qué no se corrige ahora | Control compensatorio | Dueño | Revisión |
|---|--------|--------------------------|-----------------------------|-----------------------|-------|----------|
| 1 | | | | | | |

## 5. Excepciones aprobadas
| Herramienta | ID | Justificación | Responsable | Vence |
|-------------|----|---------------|-------------|-------|
| | | | | |
