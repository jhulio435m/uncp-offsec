# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js (App Router, TypeScript) con Tailwind CSS 4, en `web/`, exportado como sitio estático y publicado en Cloudflare conectado a GitHub. Mismo patrón que `aymaralang.soryntel.com`. Aislado del escáner. Elegido por el usuario.

## Users

Dos públicos, confirmados por el usuario:

- **Equipos de ciberseguridad** (red team, blue team, consultoras, áreas de TI con personal de seguridad) que usarían la plataforma ellos mismos. Acción: probar la herramienta.
- **Empresas sin equipo propio** (gerentes y responsables de TI en Perú) que contratan la auditoría hecha por Soryntel. Acción: enviar el formulario de solicitud de evaluación.

## Product Purpose

Soryntel Security es la plataforma de evaluación de seguridad de Soryntel y el servicio de auditoría que se apoya en ella. La web vende ambas cosas y debe reconocerse de inmediato como una empresa de ciberseguridad seria. El producto seguirá mejorando; la web no debe prometer lo que aún no existe.

## Positioning

Auditoría con evidencia reproducible y límites escritos. La parte automatizada usa una herramienta propia, pública y versionada (este repositorio), que valida, identifica y reporta sin obtener acceso; lo que la herramienta no puede confirmar se marca como pendiente de revisión manual en lugar de darse por seguro.

## Operating Context

- Toda evaluación parte de una autorización explícita y un alcance escrito (`config/scopes/`).
- Entregable: informe con hallazgos, evidencia, severidad, cobertura, confianza y remediación sugerida; se puede comparar contra un informe anterior.
- Contacto de Soryntel (tomado de soryntel.com y kusi.soryntel.com): contacto@soryntel.com, +51 937 730 623, WhatsApp, Telegram @Soryntel, Instagram, Facebook, libro de reclamaciones.

## Capabilities and Constraints

Servicios confirmados por el usuario:

- **Web y correo**: superficie expuesta, DNS, TLS, cabeceras, tecnologías y versiones, correlación con NVD y CISA KEV, DAST con OWASP ZAP, Nuclei con lista revisada, SPF, DKIM, DMARC, MTA-STS, DANE, SMTP y STARTTLS.
- **Red e infraestructura**: servidores, puertos, servicios, configuración y parches.
- **Código y dependencias**: SAST (Semgrep, Bandit) y SCA (Trivy, pip-audit).
- **Pentest manual**: pruebas de intrusión con explotación controlada hechas por una persona.

Límites de la herramienta (docs/assessment-scope.md), que la web debe respetar al describir la parte automatizada: no explota, no obtiene shell, no extrae ni altera datos, no hace fuerza bruta ni denegación de servicio, no evade WAF ni bloqueos, no toca terceros. Una coincidencia de CVE es evidencia para revisión, no explotabilidad. El informe nunca declara cobertura total automática de OWASP Top 10:2025.

Sin decidir: precios, plazos, certificaciones y forma de contratación. No deben aparecer.

## Brand Commitments

- Nombre: Soryntel Security. Dirección: security.soryntel.com.
- Idioma: español. Pie con "Un producto de Soryntel" y los enlaces legales de Soryntel.
- Sin referencia a la UNCP ni a ningún cliente.
- Dirección visual pedida por el usuario tras tres manos descartadas: el estándar de la categoría, ejecutado a fondo; debe parecer ciberseguridad.
- Sin decidir: si la plataforma se ofrece gratis, con licencia o por suscripción. Hoy el código es público.

## Evidence on Hand

- `docs/assessment-scope.md`: incluido y excluido.
- `docs/flujo-zap-dast.md` y `README.md`: flujo, perfiles, estados de verificación (`VALIDATED_NON_DESTRUCTIVE`, `POTENTIAL`, `MANUAL_REQUIRED`), puntuación separada de cobertura y confianza.
- Repositorio público `jhulio435m/uncp-offsec` (pendiente de renombrar), versión 0.4.0. El comando es `soryntel-security`; `uncp_offsec` queda como alias.
- No hay clientes nombrables, testimonios, cifras, certificaciones ni informes publicables: no se inventan. Cualquier extracto de informe en la web es ilustrativo y va rotulado.

## Product Principles

- Decir qué se revisa y qué no, con la misma claridad.
- Evidencia antes que alarma: nada de miedo como argumento de venta.
- Hablarle al gerente sin jerga y al técnico sin vaguedad.
- Una sola acción: solicitar la evaluación.
- No afirmar nada que el repositorio o el usuario no respalden.
