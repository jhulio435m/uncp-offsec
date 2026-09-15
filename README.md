# UnCP OffSec

Versión actual: **0.3.3**.

Herramienta de evaluación de superficie web y correo para dominios autorizados.
Combina los controles MailSec (SPF, DKIM, DMARC, SMTP, STARTTLS, MTA-STS, DANE)
con descubrimiento web, identificación de tecnologías, TLS, puertos, Nuclei y
OWASP ZAP DAST.

> Úsala solo contra activos incluidos explícitamente en tu autorización. La fase web
> realiza consultas DNS y HTTP(S); `--active` agrega SMTP, puertos TCP y Nuclei.

El límite permanente es **validar, identificar y reportar, nunca obtener acceso**. No obtiene
shells, no extrae datos, no mantiene persistencia y no evade WAF o bloqueos. La
definición completa y los criterios de evidencia están en
[`docs/assessment-scope.md`](docs/assessment-scope.md).

El recorrido integral de `scan -sub`, incluyendo descubrimiento, red, ZAP,
correlación y reporte, está en
[`docs/flujo-zap-dast.md`](docs/flujo-zap-dast.md).

## Estructura del proyecto

- `config/scopes/`: alcances de autorización versionados y plantilla para otros dominios.
- `config/examples/`: ejemplos de configuración sin credenciales.
- `docs/`: alcance operativo, flujo técnico y documentación histórica.
- `src/`: implementación instalable de MailSec y UnCP OffSec.
- `tests/`: pruebas automatizadas.
- `reports/`: resultados y cachés locales ignorados por Git; los reportes UNCP
  conservados se agrupan en `reports/uncp/`.
- `wordlists/`: listas de descubrimiento versionadas que la imagen copia sin
  descargarlas durante el build.
- `lab/`: recursos mínimos del laboratorio reproducible.

## Uso simple

Los cuatro accesos principales son:

```bash
uncp_offsec                         # asistente interactivo
uncp_offsec scan uncp.edu.pe       # dominio completo
uncp_offsec scan -sub erpcampus.uncp.edu.pe
uncp_offsec mail uncp.edu.pe       # solamente seguridad de correo
```

El asistente permite elegir dominio, subdominio, correo o análisis de un archivo
`.eml`. Para web ofrece los perfiles Rápido, Completo y Personalizado; este último
permite seleccionar cabeceras, DNS, crawling, contenido, puertos, Nmap, Nuclei,
CVE, SQLi, acceso anónimo y ZAP. Los módulos activos solo se ejecutan cuando un
scope local los autoriza.

En correo, el asistente solicita específicamente el dominio de correo y ofrece:

- **Pasivo:** MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT y DANE mediante DNS.
- **Completo:** añade SMTP, STARTTLS y comprobación de relay en puerto 25.
- **Personalizado:** permite decidir si se conecta al puerto 25 y definir selectores DKIM.

El asistente acepta nombres como `soryntel.com`; rechaza URLs, protocolos y rutas.

## Dos formas de uso

| Modo | Incluye | Uso recomendado |
| --- | --- | --- |
| Python (`.venv` o `pipx`) | CLI, MailSec e informes | Correo, `.eml`, desarrollo y equipos con herramientas web instaladas |
| Docker Compose | CLI, herramientas web, wordlist, plantillas, scope UNCP y ZAP | Escaneos web completos y ejecución reproducible |

### 1. Entorno Python local (`.venv`)

Úsalo durante el desarrollo o cuando las herramientas externas ya estén
instaladas en el equipo:

```bash
.venv/bin/uncp_offsec scan uncp.edu.pe
.venv/bin/uncp_offsec scan -sub erpcampus.uncp.edu.pe
```

El directorio `.venv` contiene Python y las dependencias del proyecto. No debe
confundirse con `.env`, que es un archivo opcional para variables de entorno y
no instala ni ejecuta el escáner. En el modo local, ZAP y las demás herramientas
externas deben estar disponibles por separado.

### 2. Docker Compose

Es el modo recomendado para el escaneo completo porque incluye las herramientas,
la wordlist, las plantillas revisadas, el scope UNCP y el contenedor compañero de
ZAP:

```bash
docker compose build
docker compose run --rm uncp-offsec scan uncp.edu.pe
docker compose run --rm uncp-offsec scan -sub erpcampus.uncp.edu.pe
docker compose run --rm uncp-offsec mail uncp.edu.pe
docker compose run --rm uncp-offsec
```

El último comando abre el asistente dentro del contenedor. Docker Compose conserva
la entrada interactiva de la terminal automáticamente.

En ambos modos el resultado se muestra en la terminal. Añade `-o` únicamente si
deseas guardar un reporte. En Docker, usa una ruta bajo `/reports`:

```bash
docker compose run --rm uncp-offsec scan -sub erpcampus.uncp.edu.pe \
  -o /reports/erpcampus.uncp.edu.pe.html
```

Nuclei no ejecuta la colección comunitaria completa: las etiquetas negativas no
garantizan que una plantilla sea inocua. La imagen usa una lista positiva y
fijada de plantillas revisadas; actualmente solo `tech-detect`, que realiza un
GET al URL base. Las CVE se correlacionan por versiones mediante NVD/Nmap.

## Instalación del CLI

El CLI nativo sirve para informes, análisis `.eml` y controles de correo. En Linux:

```bash
./scripts/install.sh
uncp_offsec doctor
```

En Windows PowerShell, con Python 3.10 o posterior en `PATH`:

```powershell
.\scripts\install.ps1
uncp_offsec doctor
```

Los scripts instalan el proyecto con `pipx`, sin requerir privilegios de administrador.

## Escaneo completo reproducible: Docker o Podman

La fase web requiere `subfinder`, `httpx`, `whatweb`, `testssl.sh`, `naabu` y
`nuclei`. Para que la instalación sea igual entre equipos, el proyecto incluye un
`Containerfile` OCI compatible con Docker y Podman. Contiene las herramientas en
versiones fijadas; es la distribución recomendada del escáner completo.
Las listas de ffuf están versionadas en `wordlists/`: rápida (1 500), estándar
(10 000) y completa (29 999). ffuf ajusta automáticamente su tasa y concurrencia
según la cantidad real de entradas. La lista completa está en
`wordlists/raft-medium-directories.txt` y
se copia a la imagen después de validar su SHA-256.

En Linux con Docker:

```bash
git clone https://github.com/jhulio435m/uncp-offsec.git
cd uncp-offsec
mkdir -p reports
docker compose build
docker compose run --rm uncp-offsec doctor --full
docker compose run --rm uncp-offsec scan uncp.edu.pe
docker compose run --rm uncp-offsec scan -sub erpcampus.uncp.edu.pe
```

Si el repositorio es privado, autentica Git previamente con GitHub CLI o una
clave SSH. `config/scopes/scope.uncp.json` forma parte de la distribución autorizada para UNCP.
Para otros dominios, crea un alcance local a partir de `config/scopes/scope.example.json`; los
otros alcances, credenciales, informes y cachés locales permanecen excluidos de Git.

### Imagen preconstruida privada

Cada etiqueta `vX.Y.Z` publica automáticamente una imagen multi-arquitectura
(`linux/amd64` y `linux/arm64`) en GitHub Container Registry. En otra máquina,
autentica Docker y usa el archivo Compose complementario para evitar la compilación:

```bash
gh auth token | docker login ghcr.io -u jhulio435m --password-stdin
docker compose -f compose.yaml -f compose.prebuilt.yaml pull uncp-offsec
docker compose -f compose.yaml -f compose.prebuilt.yaml run --rm uncp-offsec doctor
```

Para fijar una versión concreta:

```bash
UNCP_OFFSEC_VERSION=0.3.3 docker compose \
  -f compose.yaml -f compose.prebuilt.yaml run --rm uncp-offsec doctor
```

En Linux con Podman y el complemento Compose:

```bash
mkdir -p reports
podman compose build
podman compose run --rm uncp-offsec doctor
podman compose run --rm uncp-offsec scan ejemplo.com -o /reports/ejemplo.json
```

En Windows, instala Docker Desktop con backend WSL 2 y ejecuta los mismos comandos
desde PowerShell. `reports` se monta como `/reports` y los archivos quedan en el
host. Podman también funciona, pero en Windows igualmente utiliza una máquina WSL2
o Hyper-V, por lo que Docker Desktop es el recorrido más directo para el instalador.

No se recomienda distribuir inicialmente un `.exe`: PyInstaller debe compilarse por
sistema operativo y no empaqueta de forma fiable la cadena Linux/Bash/Ruby de las
herramientas externas. Un futuro `.exe` puede ser un lanzador del contenedor.

## Uso

```bash
# Correo y web: descubre y sondea hosts HTTP(S).
uncp_offsec scan empresa.com

# Agrega SMTP relay, puertos y Nuclei.
uncp_offsec scan empresa.com --active

# Ejecuta solo correo o solo web.
uncp_offsec scan empresa.com --no-web
uncp_offsec scan empresa.com --no-email

# Concentra toda la fase web en un host exacto y omite Subfinder.
uncp_offsec scan portal.empresa.com --exact-host --no-email

# Atajo: suite externa completa autorizada sobre un único subdominio.
uncp_offsec scan -sub portal.empresa.com

# Usa los resolvedores de la organización cuando sea necesario.
uncp_offsec scan empresa.com --resolvers 10.0.0.53,10.0.0.54

# Análisis forense y conversión de informe.
uncp_offsec analyze phishing.eml
uncp_offsec report report.json report.html
```

`doctor` verifica los binarios nativos y Docker/Podman sin contactar un objetivo.
Dentro de la imagen, `doctor --full` exige además todas las herramientas, la
wordlist completa, la lista positiva Nuclei, `vulners.nse` y el alcance UNCP.
Por defecto las herramientas web utilizan el resolvedor DNS del equipo/contenedor;
`--resolvers` permite una configuración explícita.

El transporte SMTP intenta primero las direcciones IPv4 y conserva IPv6 como
respaldo. Esto evita falsos fallos `Network is unreachable` en hosts Docker sin
ruta IPv6. Si tampoco existe salida IPv4 al puerto 25, la restricción pertenece al
host, firewall, ISP o proveedor cloud: el módulo queda `TOOL_INCOMPLETE` y el
resultado es inconcluso. `network_mode: host` y los proxies HTTP no evitan un
bloqueo de salida aguas arriba.

Naabu utiliza TCP connect, omite host discovery y activa `exclude-cdn`: cuando
detecta una IP compartida de CDN/WAF limita el sondeo a 80/443. Esto evita gastar
la ventana top-1000 midiendo el borde de Cloudflare en vez del origen autorizado.

Durante el escaneo se muestra la herramienta o etapa activa, el objetivo, un
indicador animado, el avance global, el tiempo transcurrido y la duración de cada
etapa terminada. El porcentaje representa etapas completadas; una etapa larga como
ffuf, ZAP o Nmap puede conservar el mismo porcentaje mientras su indicador y tiempo
siguen actualizándose.

### Objetivo exacto

Usa `--exact-host` cuando la autorización o la ventana de trabajo se limite a un
solo host, por ejemplo `ejemplo.uncp.edu.pe`. Este modo no ejecuta Subfinder ni
añade dominios hermanos: la resolución DNS, HTTP probing, Katana, ffuf, SQLMap,
Naabu/Nmap, Nuclei, ZAP y el enriquecimiento seleccionado reciben únicamente ese
host. `--all-sources` no tiene efecto en este modo.

Para UNCP no necesitas escribir el perfil, el scope ni la lista de módulos. Usa
directamente el atajo y añade `-o` solo si deseas guardar el reporte:

```bash
docker compose run --rm uncp-offsec scan -sub erpcampus.uncp.edu.pe
docker compose run --rm uncp-offsec scan -sub erpcampus.uncp.edu.pe \
  -o /reports/erpcampus.uncp.edu.pe.html
```

#### Atajo `-sub`

`-sub` (o `--sub`) ejecuta sobre un único subdominio el paquete web e infraestructura:
HTTP(S), tecnologías, cabeceras, DNS, TLS, crawling, puertos, Nmap seguro, Nuclei
y correlación CVE. Omite MailSec porque MX, SPF, DKIM, DMARC, MTA-STS y relay se
evalúan sobre el dominio de correo, no sobre cada subdominio. También habilita ffuf
cuando encuentra la wordlist incluida en la imagen. SQLi de detección, Nmap-vuln, ZAP y evaluación anónima se
habilitan únicamente cuando el alcance concede sus permisos específicos.

El atajo activa `--no-tool-time-limit`: testssl.sh, Katana, ffuf, Naabu, Nmap y
Nuclei terminan por sí mismos, sin el límite externo del CLI. ZAP conserva
`dast_max_minutes` del archivo de alcance porque esa ventana forma parte de la
autorización activa. Interrumpir manualmente el proceso todavía conserva como
incompleta cualquier evidencia parcial disponible.

El nivel de riesgo se deriva del puntaje de la evidencia observada. La cobertura
y la confianza se informan por separado: un módulo incompleto reduce ambos
indicadores y queda advertido en el reporte, pero no reemplaza el nivel de riesgo
por `INCONCLUSIVE`. Esa etiqueta se reserva para una ejecución sin fases evaluables.

En Compose, ZAP es un contenedor compañero fijado por versión. Se inicia y espera
automáticamente al ejecutar `uncp-offsec`; su API no se publica hacia el host.

```bash
uncp_offsec scan -sub www.uncp.edu.pe
```

El CLI busca un único `scope*.json` local que autorice el host. Si no existe o hay
más de uno con igual especificidad, exige `--scope FILE`. Sin `-o`, el resultado
solo se muestra en la terminal. Para guardar un informe, indícalo expresamente:

```bash
uncp_offsec scan -sub www.uncp.edu.pe -o reports/www.uncp.edu.pe.html
```

Dentro de Compose también basta el comando corto; el alcance UNCP ya está
empaquetado y el directorio actual se monta en `/work`:

```bash
docker compose run --rm uncp-offsec scan -sub www.uncp.edu.pe
docker compose run --rm uncp-offsec scan -sub www.uncp.edu.pe \
  -o /reports/www.uncp.edu.pe.html
```

### Perfiles y alcance autorizado

`standard` es el perfil predeterminado: realiza descubrimiento, consultas DNS y
sondas HTTP(S) acotadas. `passive` deja explícito que no se habilitarán relay SMTP,
puertos ni Nuclei. Cualquier módulo activo requiere un archivo JSON de autorización
y uno de los perfiles `active-authorized`, `active-validation` o `lab`. Esta
configuración manual solo es necesaria para una organización distinta de UNCP:

```bash
cp config/scopes/scope.example.json config/scopes/scope.local.json
# Edita domains y confirma allow_active: true solo para una prueba aprobada.
docker compose run --rm uncp-offsec scan ejemplo.com \
  --profile active-authorized --scope /work/config/scopes/scope.local.json \
  -o /reports/ejemplo.html --format html
```

Para resaltar cambios desde un informe JSON anterior, añade `--compare`:

```bash
uncp_offsec scan ejemplo.com --compare reports/anterior.json -o reports/nuevo.html --format html
```

Nmap puede ejecutar una lista cerrada de NSE de identificación/TLS con
`--nmap-safe-scripts`. `--nmap-vuln-authorized` requiere además
`allow_nmap_vuln: true` y añade únicamente `vulners`, que correlaciona las
versiones/CPE identificadas con CVE públicas sin lanzar exploits.

El alcance admite `"assessment_mode": "identification-only"` y
`"assessment_mode": "active-validation"`. Este último habilita la validación
activa no destructiva autorizada, pero no explotación, persistencia, extracción
de datos ni evasión. Ambos modos se limitan a los dominios declarados y sus
subdominios. Si un host responde
`403`, `429` o `503`, el informe registra cobertura limitada; el escáner no intenta
sortear WAF, CAPTCHA ni bloqueos de IP. Coordina una allowlist o ventana de pruebas
con el responsable del activo.

### Inventario y CVE

El JSON/HTML conserva los subdominios, URL, IP, CDN/WAF, tecnologías, versiones
explícitas y CVE asociados por activo. El enriquecimiento CVE es opcional y solo
consulta versiones exactas detectadas; no afirma una CVE por el nombre de un
producto. Las coincidencias se agrupan por CVE/producto/versión y se etiquetan
`VERSION_CORRELATED`: son exposiciones potenciales hasta confirmar paquete,
módulos y configuración en el servidor. Usa NVD y marca las CVE presentes en CISA
KEV. La caché es obligatoria:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --cves \
  --cve-cache /reports/.cve-cache -o /reports/ejemplo.html --format html
```

Para mayor capacidad de la API de NVD, define `NVD_API_KEY` en el entorno antes de
ejecutar el contenedor; la clave no se incluye en el informe ni en archivos del proyecto.

Para añadir DNS estructurado y cabeceras de seguridad al inventario:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --dns-inventory --headers \
  -o /reports/ejemplo.html --format html
```

Katana y ffuf son módulos activos: requieren `active-authorized`, un alcance que
permita pruebas activas y, para ffuf, una wordlist aprobada. No son parte del
perfil estándar; el atajo `-sub` los configura automáticamente y elimina su
deadline externo:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-authorized \
  --scope /work/config/scopes/scope.local.json --crawl --content-discovery \
  --wordlist /opt/uncp-tools/wordlists/raft-medium-directories.txt \
  -o /reports/ejemplo.html --format html
```

La imagen incorpora `raft-medium-directories.txt` de SecLists para pruebas
autorizadas. También puedes sustituirla por una wordlist específica del alcance
montada en `/work`.

La detección SQLi automatizada usa Katana para obtener candidatos GET con parámetros
y acepta solicitudes HTTP POST/JSON mediante `--sqlmap-request`. SQLMap permanece
en modo de detección, sin enumeración ni extracción. Requiere que el
alcance establezca `allow_sqli_detection: true`; también respeta `sqli_max_targets`
y `exclude_paths`:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-authorized \
  --scope /work/config/scopes/scope.local.json --sqli-detection \
  -o /reports/ejemplo.html --format html
```

Para analizar parámetros POST/JSON, añade una solicitud HTTP cruda capturada por
el propietario. La opción es repetible y el encabezado `Host` debe pertenecer al alcance:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/config/scopes/scope.local.json --sqlmap-request /work/request-search.txt \
  -o /reports/ejemplo.json
```

### OWASP ZAP DAST

ZAP se ejecuta como servicio interno sin publicar su API al host. El alcance debe
establecer `allow_dast: true`; `--zap-ajax` requiere además
`allow_ajax_spider: true`. Las URL de Katana se importan como semillas y
`dast_max_minutes` reparte el plazo entre spider, AJAX spider y active scan:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/config/scopes/scope.local.json --crawl --dast --zap-ajax \
  -o /reports/ejemplo.json
```

El resultado separa puntuación, cobertura y confianza. Un módulo solicitado que
no concluye no recibe crédito; con cobertura inferior al 70% el veredicto es
`INCONCLUSIVE`.

#### Sesión autenticada y APIs

Para cubrir rutas protegidas, entrega encabezados de una cuenta de prueba con
privilegios mínimos en un archivo JSON. El escáner los pasa a Katana, ffuf y ZAP,
pero nunca incluye sus valores en JSON/HTML. Usa tokens de corta duración y elimina
el archivo al terminar:

```bash
cp config/examples/auth-headers.example.json auth-headers.local.json
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/config/scopes/scope.local.json --crawl --dast --zap-ajax \
  --auth-headers /work/auth-headers.local.json \
  --api-spec-url https://api.ejemplo.com/openapi.json \
  -o /reports/autenticado.html --format html
```

La especificación OpenAPI debe estar publicada mediante HTTP(S), pertenecer al
alcance y se importa al árbol de sitios de ZAP antes del análisis activo.

#### SAST y SCA

Si el propietario dispone del código, `--sast` ejecuta Semgrep o Bandit y `--sca`
ejecuta Trivy o pip-audit. La imagen incluye Bandit y pip-audit; Semgrep y Trivy
se usan automáticamente cuando están instalados. Estos módulos complementan DAST:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --no-email \
  --source /work --sast --sca -o /reports/codigo.html --format html
```

Cada informe incorpora la matriz **OWASP Top 10:2025**, sus módulos de evidencia
y las limitaciones. `PARTIAL` significa que existe evidencia automatizada relevante,
no que la categoría completa esté cubierta. Control de acceso, diseño, lógica de
negocio, registro/alertas y flujos entre roles siguen requiriendo pruebas manuales.

#### Evaluación anónima sin cuentas

Cuando todavía no existen cuentas de prueba, `--anonymous-assessment` clasifica las
URL descubiertas por Katana y revisa superficies de login, registro, recuperación,
OAuth, API, recursos sensibles e identificadores públicos. Solo envía `GET` con
lectura truncada y `OPTIONS`; no ejecuta los métodos de cambio anunciados por el
servidor. Requiere `allow_anonymous_assessment: true` en el alcance:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --no-email \
  --profile active-validation --scope /work/config/scopes/scope.local.json \
  --crawl --anonymous-assessment --headers --dast --zap-ajax \
  -o /reports/anonimo.html --format html
```

La opción adicional `--rate-limit-check` requiere
`allow_rate_limit_check: true`; realiza entre 3 y 10 solicitudes `HEAD` lentas y
solo registra si observó HTTP 429. La ausencia de 429 en esa muestra nunca se
declara vulnerabilidad. El informe mide URL, rutas, parámetros, APIs, superficies
de autenticación e identificadores; los formularios aparecen como `UNMEASURED`
hasta disponer de telemetría de navegador estructurada.

Las señales repetidas se correlacionan por CWE, CVE o título entre motores. La
correlación aumenta la prioridad de revisión, pero no convierte automáticamente
una señal en vulnerabilidad confirmada. Sin cuentas, IDOR/BOLA horizontal,
escalamiento entre roles y autorización de contenido privado continúan como
`MANUAL_REQUIRED`.

## Opciones principales

| Opción | Descripción |
|---|---|
| `--active` | Agrega SMTP relay, escaneo TCP y Nuclei |
| `--no-email` / `--no-web` | Omite una fase |
| `--ports` / `--nuclei` | Habilita solo esa comprobación activa |
| `--dast` / `--zap-ajax` | Ejecuta ZAP activo y su spider de navegador |
| `--sqlmap-request` | Añade una solicitud POST/JSON autorizada a SQLMap |
| `--auth-headers` | Sesión de prueba mediante encabezados JSON no persistidos en el informe |
| `--api-spec-url` | Importa una especificación OpenAPI autorizada en ZAP |
| `--source --sast --sca` | Analiza código y dependencias locales |
| `--anonymous-assessment` | Evalúa exposición anónima mediante métodos HTTP seguros |
| `--rate-limit-check` | Observación acotada de HTTP 429; permiso independiente |
| `--all-sources` | Habilita todas las fuentes OSINT de subfinder |
| `-sub` / `--sub` | Suite externa completa autorizada para un subdominio exacto |
| `--resolvers` | DNS para herramientas web, separados por coma |
| `--timeout` / `--tls-timeout` | Límites de red en segundos |
| `-o`, `--format` | Guarda JSON o HTML |

## Desarrollo

### Laboratorio local vulnerable

Juice Shop puede iniciarse en una red Docker aislada y queda accesible únicamente
desde el equipo local en `http://127.0.0.1:8088`:

```bash
docker compose --profile lab up -d juice-shop lab-proxy zap
docker compose --profile lab ps
```

Dentro de la red Compose, el escáner usa `juice-shop.local` y el alcance
preparado en `config/scopes/scope.lab.json`. El laboratorio se detiene con:

```bash
docker compose --profile lab down
```

```bash
python -m pip install -e ".[dev]"
ruff check src tests
pytest
```

`requirements.lock` fija las dependencias Python usadas por la imagen. Actualízalo
con una herramienta de bloqueo, reconstruye la imagen y valida `doctor --full`,
Ruff y pytest antes de publicar una nueva versión. Las versiones externas y los
hashes de los recursos descargados viven en `Containerfile`. El workflow de GitHub
repite estas comprobaciones antes de publicar una imagen multi-arquitectura.
