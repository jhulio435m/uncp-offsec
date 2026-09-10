# Alcance operativo: identificación y validación activa

UnCP OffSec es un escáner defensivo para activos con autorización explícita. Su
objetivo es encontrar antes que un atacante la superficie expuesta, indicios de
configuración insegura y vulnerabilidades probables o verificables mediante
pruebas acotadas y no destructivas.

## Incluido

- Inventario de dominios, subdominios, DNS, URL, IP, puertos y servicios.
- Identificación de tecnologías y versiones, correlación con NVD y CISA KEV.
- Revisión de correo, TLS, cabeceras y configuraciones web.
- Descubrimiento acotado de contenido y rutas dentro del dominio autorizado.
- Validación no destructiva mediante una lista positiva de plantillas Nuclei
  revisadas. La imagen incluye detección tecnológica, cabeceras, cookies, CORS,
  directory listing, documentación OpenAPI/Swagger y controles TLS. No ejecuta
  automáticamente la colección comunitaria completa ni plantillas de explotación.
- Detección SQLi en GET y solicitudes HTTP autorizadas POST/JSON, sin enumerar
  ni extraer datos.
- OWASP ZAP con spider tradicional, AJAX spider opcional y validación activa.
  Conserva URL, método, parámetro, payload, evidencia, confianza, CWE y WASC.
  Las rutas excluidas en el alcance se retiran del spider y del active scan.
- Nmap `-sV` y una lista cerrada de NSE de inventario/TLS; la correlación de
  vulnerabilidades usa `vulners`, que parte de la versión/CPE detectada.
- Informe de evidencia, cobertura limitada, severidad y remediación sugerida.
- Escaneo autenticado con encabezados de una cuenta de prueba de mínimo privilegio;
  las credenciales no se serializan en el informe.
- Importación de especificaciones OpenAPI HTTP(S) dentro del alcance.
- SAST local mediante Semgrep/Bandit y SCA mediante Trivy/pip-audit cuando se
  proporciona explícitamente el árbol de código autorizado.
- Matriz OWASP Top 10:2025 por categoría con estado `PARTIAL`, `INCOMPLETE`,
  `NOT_ASSESSED` o `MANUAL_REQUIRED`; nunca declara cobertura total automática.
- Evaluación anónima de rutas descubiertas mediante `GET`, `HEAD` y `OPTIONS`:
  superficies de autenticación/API, CORS, atributos de cookies, caché, exposición
  de valores con forma de JWT y métodos anunciados. El cuerpo se trunca, se usa
  solo para señales booleanas y nunca se conserva.
- Observación opcional de rate limiting con 3 a 10 solicitudes `HEAD`, permiso
  independiente y sin afirmar una vulnerabilidad cuando no aparece HTTP 429.
- Correlación de evidencia independiente por CWE, CVE y título normalizado.
- Puntuación de postura separada de cobertura y confianza. Un módulo solicitado
  que no concluye no se interpreta como seguro y puede producir `INCONCLUSIVE`.

## Excluido sin excepción

- Explotación de vulnerabilidades o ejecución de payloads de acceso.
- Obtención de shell, ejecución remota de comandos o uso de Metasploit.
- Persistencia, movimiento lateral, escalamiento de privilegios o malware.
- Extracción, alteración o eliminación de datos; volcado de bases de datos.
- Fuerza bruta de credenciales, denegación de servicio o pruebas destructivas.
- Evasión de WAF, CAPTCHA, rate limits, bloqueos de IP o rotación mediante Tor.
- Ataques a terceros, proveedores o IP fuera del alcance autorizado.

Una coincidencia de plantilla o CVE es evidencia para revisión y parcheo, no una
afirmación automática de explotabilidad. El informe debe distinguir entre una
versión correlacionada, una señal de detección y una vulnerabilidad confirmada.
Los hallazgos se consolidan por regla e incluyen cantidad de ocurrencias, muestras,
confianza y estado de verificación. Solo una prueba específica, reproducible y no
destructiva puede usar `VALIDATED_NON_DESTRUCTIVE`; un HTTP 500 aislado permanece
como `POTENTIAL`.

Sin al menos dos cuentas de prueba no se confirma IDOR/BOLA horizontal, acceso
entre propietarios ni escalamiento de privilegios. Esos casos permanecen
explícitamente como `MANUAL_REQUIRED / NO CREDENTIALS`.
