# Inventario y clasificación de vulnerabilidades del contenedor · CenfoPay (semana 2)

## 1. Inventario (SBOM)
- Archivo: `reportes/sbom-cyclonedx.json`   · Componentes totales: _512___
- Imagen base: ___python:3.9____  · Digest: `sha256:________________`
- Sistema operativo y versión: __Debian 13.1_______  · Paquetes del SO: _478___  · Librerías Python: _33___

## 2. Clasificación (antes / después del endurecimiento)
| Origen | Severidad | Antes | Después | Con corrección | Sin corrección | En CISA KEV |
|--------|-----------|------:|--------:|---------------:|---------------:|------------:|
| SO (trivy-so) | CRITICAL | 235| |224 |11 | |
| SO (trivy-so) | HIGH | 2599| | 2216|382 | |
| Dependencias (trivy-dependencias) | CRITICAL | 1| |1 | 0| |
| Dependencias (trivy-dependencias) | HIGH | 16| | 16| | 0|
| Configuración (trivy-config / hadolint) | ALTA | | | | | |

## 3. Top 5 para priorizar
| CVE | Paquete | CVSS | EPSS | ¿KEV? | ¿Se usa la función vulnerable? | Prioridad |
|-----|---------|------|------|-------|--------------------------------|-----------|
CVE-2020-14343	|PyYAML |5.3.1	|9.8	~13,7 %	|No	|Sí (5.4)	|Sí	|Alta
CVE-2024-1135	|gunicorn |20.0.4|	7.5	~0,04 %	|No	|Sí (22.0.0)	|Sí	|Alta
CVE-2026-42010	|libgnutls30t64	|9.8|	~0,15 %	|No	|Sí (3.8.9-3+deb13u4)	|No (función RSA-PSK)	|Alta
CVE-2026-23876	|imagemagick	|9.8|	~0,04 %|No	|Sí (deb13u5)	|No	|Quitar
CVE-2026-115506	|libexpat1	|7.5|	< 1 %	|No	|No	|Indirecto	|Vigilar



## 4. Selección de la imagen base
| Criterio | Opción A | Opción B | Opción C |
|----------||||
| Imagen | `python:3.9` (actual) | | |
| Mantenida / con soporte | 
| Tamaño (MB) |
| Vulnerabilidades C/H | | | |
| Tiene shell / gestor de paquetes | | | |
| Origen verificado (oficial, firmado) | | | |
| Compatibilidad con la app | | | |
| **Decisión y justificación** | | | |
## ***********************************************
| Criterio | Opción A: python:3.9 | Opción B: python:3.9-slim-bookworm | Opción C: distroless / alpine |
|---|---|---|---|
| Tamaño | ~1 GB | ~150 MB | Menor aún |
| Paquetes del SO | 478 | Mínimos | Casi ninguno |
| Mantenida / con soporte | Python 3.9 sin soporte desde oct-2025; base Debian 13 con soporte vigente | Python 3.9 sin soporte; Debian 12 (bookworm) ya en fase LTS, con parches de seguridad más limitados | Distroless (Google) y Alpine se mantienen activamente, pero con Python 3.9 heredan el mismo problema |
| Compatibilidad con librerías Python | Total | Total (glibc) | Alpine usa musl: problemas con ruedas como psycopg2; distroless no tiene shell para depurar |
| Herramientas para un atacante | Muchas (curl, vim, netcat, compiladores) | Pocas (aún trae apt-get, END-05) | Casi ninguna |
| Decisión | Descartada | **Elegida** | Siguiente nivel de madurez |

**Justificación:** se elige la opción B porque reduce drásticamente la superficie de ataque sin romper la compatibilidad con las librerías actuales. Su limitación es el soporte: Python 3.9 está fuera de mantenimiento, por lo que queda como riesgo residual hasta la semana 3, cuando se migra a Python 3.13.


## 5. Verificación post-endurecimiento
Pega aquí la salida de `bash scripts/verificar-endurecimiento.sh cenfopay:local cenfopay-app-1`.
