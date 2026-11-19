export const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://security.soryntel.com";
export const REPO_URL = "https://github.com/jhulio435m/uncp-offsec";
export const PLATFORM_VERSION = "0.4.0";

export const TITLE = "Soryntel Security · Auditoría y plataforma de evaluación de seguridad";
export const DESCRIPTION =
  "Auditoría de seguridad web, correo, red y código, y la plataforma con la que la hacemos. Evidencia reproducible y límites por escrito. Hecho en Perú por Soryntel.";

export const KEYWORDS = [
  "auditoría de seguridad",
  "ciberseguridad Perú",
  "pentest",
  "evaluación de vulnerabilidades",
  "seguridad de correo DMARC",
  "DAST",
  "red team",
  "Soryntel Security",
];

// Canales de Soryntel (los mismos de soryntel.com).
export const CONTACT = {
  email: "contacto@soryntel.com",
  phone: "+51 937 730 623",
  whatsapp: "https://wa.me/51937730623?text=Hola%2C%20quiero%20solicitar%20una%20auditor%C3%ADa%20de%20seguridad.",
  telegram: "https://t.me/Soryntel",
  instagram: "https://www.instagram.com/soryntel/",
  facebook: "https://www.facebook.com/profile.php?id=61593869619694",
  complaints: "https://soryntel.com/libro-de-reclamaciones",
  home: "https://soryntel.com",
};

export const RULE = "Validar, identificar, reportar: nunca obtener acceso";

export const SERVICES = [
  {
    id: "web-correo",
    name: "Web y correo",
    lead: "Lo que cualquiera ve de usted desde Internet: sitios, APIs y el dominio desde el que envía correo.",
    checks: [
      "Subdominios, DNS, TLS y cabeceras",
      "Tecnologías y versiones contra NVD y CISA KEV",
      "Pruebas dinámicas con OWASP ZAP y plantillas Nuclei revisadas",
      "SPF, DKIM, DMARC, MTA-STS, DANE y STARTTLS",
    ],
  },
  {
    id: "red",
    name: "Red e infraestructura",
    lead: "Qué servicios responden en sus servidores y en qué estado están.",
    checks: ["Puertos y servicios expuestos", "Versiones y parches pendientes", "Configuración de servidores y accesos"],
  },
  {
    id: "codigo",
    name: "Código y dependencias",
    lead: "Revisión del código que usted nos entrega y de las librerías de las que depende.",
    checks: ["Análisis estático con Semgrep y Bandit", "Dependencias vulnerables con Trivy y pip-audit", "Hallazgos ubicados por archivo y línea"],
  },
  {
    id: "pentest",
    name: "Pentest manual",
    lead: "Una persona intenta lo que una herramienta no puede confirmar, dentro de un alcance firmado.",
    checks: ["Control de acceso entre cuentas y privilegios", "Lógica de negocio", "Explotación controlada, con evidencia"],
  },
];

/** Tomado de docs/assessment-scope.md: lo que la plataforma hace y lo que excluye sin excepción. */
export const DOES = [
  "Inventaría dominios, subdominios, IP, puertos y servicios",
  "Identifica tecnologías y versiones y las correlaciona con NVD y CISA KEV",
  "Valida con pruebas acotadas y no destructivas",
  "Entrega evidencia, severidad, cobertura y remediación sugerida",
];

export const NEVER = [
  "Explotar vulnerabilidades ni ejecutar cargas de acceso",
  "Obtener shell o ejecutar comandos remotos",
  "Persistencia, movimiento lateral o escalamiento de privilegios",
  "Extraer, alterar o borrar datos",
  "Fuerza bruta de credenciales o denegación de servicio",
  "Evadir WAF, CAPTCHA, límites de tasa o bloqueos de IP",
  "Tocar a terceros, proveedores o IP fuera del alcance",
];

export const PLATFORM = [
  { name: "Alcance versionado", note: "Cada evaluación parte de un archivo de alcance. Los módulos activos solo corren si ese alcance los autoriza." },
  { name: "Tres perfiles", note: "Rápido, Completo o Personalizado, módulo por módulo: cabeceras, DNS, rastreo, puertos, Nuclei, CVE, SQLi y ZAP." },
  { name: "Sesión de prueba", note: "Evaluación autenticada con una cuenta de mínimo privilegio. Las credenciales no se guardan en el informe." },
  { name: "OpenAPI", note: "Importa la especificación de su API para evaluar las rutas declaradas, dentro del alcance." },
  { name: "Comparación", note: "Contrasta el informe de hoy con el anterior y resalta lo que cambió." },
  { name: "Reproducible", note: "Imagen de contenedor con herramientas, listas y plantillas en versiones fijadas." },
];

export const STEPS = [
  { name: "Autorización y alcance", note: "Acordamos por escrito qué activos se evalúan, qué pruebas se permiten y en qué horario." },
  { name: "Evaluación", note: "Corremos la plataforma sobre el alcance y revisamos a mano lo que ella deja pendiente." },
  { name: "Informe", note: "Hallazgos con evidencia, severidad y qué corregir primero." },
  { name: "Nueva evaluación", note: "Tras las correcciones, una nueva evaluación se compara contra el informe anterior." },
];

export type Estado = "validado" | "potencial" | "manual";

export const ESTADOS: Record<Estado, { label: string; code: string; note: string }> = {
  validado: { label: "Validado", code: "VALIDATED_NON_DESTRUCTIVE", note: "Confirmado con una prueba específica, reproducible y no destructiva." },
  potencial: { label: "Potencial", code: "POTENTIAL", note: "Hay evidencia que justifica revisarlo, pero no confirma que sea explotable." },
  manual: { label: "Revisión manual", code: "MANUAL_REQUIRED", note: "La plataforma no puede confirmarlo sola: lo revisa una persona." },
};

/** Extracto ilustrativo: muestra la forma del informe, no datos de ningún cliente. */
export const FINDINGS: { area: string; title: string; severity: "Alta" | "Media" | "Sin asignar"; estado: Estado; evidence: string; fix: string }[] = [
  {
    area: "Web",
    title: "Listado de directorio habilitado",
    severity: "Alta",
    estado: "validado",
    evidence: "El servidor devuelve el índice de la carpeta con un GET simple. Se registró la URL y la respuesta, sin descargar los archivos.",
    fix: "Desactivar el listado automático en el servidor web y retirar los archivos que no deben publicarse.",
  },
  {
    area: "Web",
    title: "Versión del servidor con CVE listado en CISA KEV",
    severity: "Alta",
    estado: "potencial",
    evidence: "La versión se identificó por la cabecera de respuesta y se correlacionó con NVD. No se intentó explotar.",
    fix: "Actualizar a una versión corregida. Si ya está parchada por el proveedor, documentarlo para cerrar el hallazgo.",
  },
  {
    area: "Código",
    title: "Dependencia con vulnerabilidad conocida",
    severity: "Alta",
    estado: "potencial",
    evidence: "El análisis de dependencias encontró una versión afectada en el archivo de bloqueo. Falta confirmar si la función vulnerable se usa.",
    fix: "Subir la dependencia a la versión corregida y volver a ejecutar el análisis.",
  },
  {
    area: "Correo",
    title: "DMARC publicado con política p=none",
    severity: "Media",
    estado: "validado",
    evidence: "El registro TXT de _dmarc existe, pero no pide rechazar ni poner en cuarentena el correo que falla la verificación.",
    fix: "Revisar los reportes, pasar a quarantine y luego a reject.",
  },
  {
    area: "Web",
    title: "Cabecera Content-Security-Policy ausente",
    severity: "Media",
    estado: "validado",
    evidence: "Ninguna de las respuestas HTML revisadas incluye la cabecera.",
    fix: "Definir una política y desplegarla primero en modo de solo reporte.",
  },
  {
    area: "Red",
    title: "Servicio de base de datos accesible desde Internet",
    severity: "Media",
    estado: "validado",
    evidence: "El puerto responde desde fuera de la red y anuncia el servicio. No se intentó iniciar sesión.",
    fix: "Limitar el acceso a las direcciones que lo necesitan o dejarlo solo en la red interna.",
  },
  {
    area: "API",
    title: "Control de acceso entre cuentas",
    severity: "Sin asignar",
    estado: "manual",
    evidence: "Sin al menos dos cuentas de prueba no se puede confirmar si un usuario ve datos de otro. Queda pendiente, no aprobado.",
    fix: "Entregar dos cuentas de prueba de mínimo privilegio para la revisión manual.",
  },
];

export const NEEDS = ["Web y correo", "Red e infraestructura", "Código y dependencias", "Pentest manual", "Usar la plataforma en mi equipo", "No estoy seguro"];

/** Qué trae el informe que genera la plataforma. */
export const REPORT_PARTS = [
  "Puntaje de postura y nivel de riesgo",
  "Señales accionables, las que requieren validación y los módulos incompletos",
  "Cada hallazgo con estado, confianza, ocurrencias, evidencia y recomendación",
  "Inventario de subdominios y servidores que responden",
  "Métricas de cobertura de la aplicación",
  "Matriz OWASP Top 10:2025 con sus límites",
];

/** Respuestas tomadas de docs/assessment-scope.md y del README. */
export const FAQ = [
  {
    q: "¿Pueden dañar o tumbar mis sistemas?",
    a: "La plataforma solo hace pruebas acotadas y no destructivas: no explota, no fuerza credenciales y no hace denegación de servicio. Las pruebas activas corren únicamente si el alcance firmado las autoriza.",
  },
  {
    q: "¿Qué necesitan de mí para empezar?",
    a: "La autorización por escrito y la lista de activos a evaluar. Si quiere que revisemos zonas con sesión, una cuenta de prueba de mínimo privilegio; para APIs ayuda la especificación OpenAPI; para código, el árbol de código que nos autorice a leer.",
  },
  {
    q: "¿Qué recibo al final?",
    a: "Un informe en HTML y en JSON con cada hallazgo, su evidencia, severidad, estado de verificación, confianza y una recomendación, más la cobertura alcanzada y lo que quedó sin evaluar.",
  },
  {
    q: "¿El informe certifica que estoy seguro?",
    a: "No. Dice qué se evaluó, qué se encontró y qué no se pudo evaluar. Un módulo sin hallazgos no prueba que algo sea seguro, y la matriz OWASP nunca declara cobertura total.",
  },
  {
    q: "¿Y si mi sitio tiene WAF o bloquea el escaneo?",
    a: "No lo evadimos. Si el sitio responde con bloqueos, el informe registra cobertura limitada y se lo decimos, para que usted decida cómo seguir.",
  },
  {
    q: "¿Qué pasa con mis credenciales y mis datos?",
    a: "Las credenciales de prueba no se guardan en el informe. La plataforma no extrae datos: de las respuestas solo conserva la evidencia necesaria para sustentar cada hallazgo.",
  },
];
