# Informe de auditoría de seguridad — {{CLIENTE}}

**Fecha:** {{FECHA}}  **Auditor:** 8L4CK8Y73  **Versión de la herramienta:** bbharden {{VERSION}}
**Alcance autorizado:** {{REPOSITORIOS}} (autorización firmada el {{FECHA_AUTORIZACION}})
**Confidencial.** Distribución limitada a {{DESTINATARIOS}}.

---

## 1. Resumen ejecutivo

*(3–5 frases para la dirección, sin jerga. Rellenar tras revisar a mano.)*

- Estado general: **{{CRITICO/ALTO/MEDIO/BAJO}}**
- Hallazgos confirmados: {{N}} ({{C}} críticos, {{A}} altos, {{M}} medios, {{B}} bajos)
- Lo que hay que hacer esta semana: {{TOP 3}}
- Lo bueno que ya hacéis: {{POSITIVOS}}

## 2. Qué hacer primero

| # | Acción | Riesgo si no se hace | Esfuerzo | Responsable |
|---|---|---|---|---|
| 1 | **Rotar** {{CREDENCIAL}} (aunque se borre del código, sigue en el historial) | Acceso no autorizado a {{SERVICIO}} | 30 min | {{ }} |
| 2 | {{ }} | {{ }} | {{ }} | {{ }} |

## 3. Hallazgos confirmados

*(Uno por bloque. Pegar desde `bbharden scan --format json` y completar tras la revisión manual.)*

### {{ID}} — {{TÍTULO}} · Severidad {{ }}
- **Dónde:** `{{archivo}}:{{línea}}` (commit {{hash}} si es del historial)
- **Qué significa:** {{explicación en lenguaje llano}}
- **Cómo corregirlo:** {{pasos}}
- **Referencias orientativas:** {{OWASP CI/CD, ISO 27001 Anexo A…}} *(orientativo; no implica cumplimiento)*
- **Estado:** ☐ Pendiente ☐ En curso ☐ Resuelto

## 4. Hallazgos descartados

*(Falsos positivos revisados, con el motivo. Da confianza al cliente.)*

## 5. Inventario de software (SBOM)

Adjunto: `sbom.cdx.json` — {{N}} componentes en {{ECOSISTEMAS}}. Vulnerabilidades conocidas consultadas el {{FECHA}} en OSV.dev: {{RESULTADO / "no consultadas"}}.

## 6. Limitaciones de esta auditoría

- Análisis estático de código y configuración; **no** es un test de intrusión ni revisa sistemas en producción.
- No se verificaron las claves contra los proveedores (no se sabe si siguen activas).
- Cobertura del historial: {{COMPLETA / PARCIAL: motivo}}.
- Ninguna auditoría garantiza la ausencia de vulnerabilidades. Las referencias a normas son orientativas.

## 7. Siguientes pasos

☐ Sesión de explicación (30 min)  ☐ Pull Request de correcciones automáticas  ☐ Re-escaneo en {{30 días}}
