# Auditoría de seguridad de tu código — informe claro, arreglos priorizados

*Servicio de 8L4CK8Y73 (Manuel Pouso), especialista en ciberseguridad. Basado en la herramienta open source [BlackByte Hardener](../../README.md).*

## ¿Para quién es?

Para empresas y profesionales que **tienen código propio en repositorios** (GitHub/GitLab): agencias de desarrollo, tiendas online con desarrollo a medida, startups, SaaS pequeños, equipos que contratan freelancers. **No** es un análisis de tu web desde fuera ni un test de intrusión.

## El problema

Un secreto subido por error (una clave de AWS, un token de GitHub) puede costar miles de euros en horas. Una cuenta de CI mal configurada deja que un tercero ejecute código con tus credenciales. Casi nadie lo revisa hasta que ocurre.

## Qué recibes

| Entregable | Detalle |
|---|---|
| **Informe ejecutivo (PDF/HTML)** | Qué está mal, cuánto importa y qué arreglar primero. Sin jerga innecesaria. |
| **Lista priorizada de correcciones** | Cada hallazgo con archivo, línea, riesgo y la solución concreta. |
| **Revisión del historial de git** | Secretos que alguien subió y borró después: siguen recuperables. |
| **Inventario de software (SBOM, CycloneDX)** | La lista de librerías que usas; útil para clientes grandes y licitaciones. |
| **Correcciones listas** | `SECURITY.md`, Dependabot, `.gitignore` y fijación de versiones de GitHub Actions, en un Pull Request que tú revisas y aceptas. |
| **Sesión de 30 min** | Te explico el informe y respondo dudas. |

## Planes (propuesta orientativa — ajusta precios antes de publicarlos)

| | **Revisión puntual** | **Seguimiento mensual** |
|---|---|---|
| Qué incluye | 1 auditoría completa + informe + PR de correcciones + sesión | Re-escaneo mensual, informe de cambios, aviso inmediato si aparece algo crítico |
| Alcance | Hasta 5 repositorios | Hasta 5 repositorios |
| Precio sugerido | desde 190 € | desde 39 €/mes |

*Los precios son una propuesta de partida para validar el mercado, no tarifas fijadas.*

## Cómo trabajo (y qué no hago)

- Solo analizo **repositorios que tú me autorizas por escrito**. Nunca ataco ni exploto nada, ni toco tus sistemas en producción.
- Trabajo con acceso de **solo lectura** siempre que es posible. Si me das acceso temporal, lo revocas al terminar.
- Los secretos que encuentre **nunca aparecen completos** en el informe y no los copio ni los uso.
- Lo que encuentre es confidencial (ver [condiciones](CONDICIONES.md)).
- La herramienta puede dar falsos positivos; **reviso cada hallazgo a mano** antes de ponerlo en el informe.

## Lo que no te prometo

- Que tu código quede "seguro al 100 %": ninguna auditoría puede garantizarlo.
- Certificaciones (ISO 27001, ENS, etc.). El informe puede **orientar** hacia ellas, pero no equivale a una certificación.

## Siguiente paso

Escríbeme con el enlace a uno de tus repositorios (o dime cuántos tienes) y te digo en 24 h si encaja y qué incluiría. El primer repositorio de muestra puede ser gratuito para que veas la calidad del informe.

**Contacto:** kryptoryn@gmail.com
