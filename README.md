# UnCP OffSec

Versión actual: **0.2.0**.

Herramienta de evaluación de superficie web y correo para dominios autorizados.
Combina los controles MailSec (SPF, DKIM, DMARC, SMTP, STARTTLS, MTA-STS, DANE)
con descubrimiento web, identificación de tecnologías, TLS, puertos, Nuclei y
OWASP ZAP DAST.

> Úsala solo contra activos incluidos explícitamente en tu autorización. La fase web
> realiza consultas DNS y HTTP(S); `--active` agrega SMTP, puertos TCP y Nuclei.

El límite permanente es **validar, identificar y reportar, nunca obtener acceso**. No obtiene
shells, no extrae datos, no mantiene persistencia y no evade WAF o bloqueos. La
definición completa y los criterios de evidencia están en
[`ASSESSMENT_SCOPE.md`](ASSESSMENT_SCOPE.md).

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

En Linux con Docker:

```bash
git clone https://github.com/jhulio435m/uncp-offsec.git
cd uncp-offsec
mkdir -p reports
docker compose build
docker compose run --rm uncp-offsec doctor
docker compose run --rm uncp-offsec scan ejemplo.com -o /reports/ejemplo.json
```

Si el repositorio es privado, autentica Git previamente con GitHub CLI o una
clave SSH. Crea el alcance local a partir de `scope.example.json`; los alcances,
credenciales, informes y cachés locales están excluidos deliberadamente de Git.

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
UNCP_OFFSEC_VERSION=0.2.0 docker compose \
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

# Usa los resolvedores de la organización cuando sea necesario.
uncp_offsec scan empresa.com --resolvers 10.0.0.53,10.0.0.54

# Análisis forense y conversión de informe.
uncp_offsec analyze phishing.eml
uncp_offsec report report.json report.html
```

`doctor` verifica los binarios nativos y Docker/Podman sin contactar un objetivo.
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

```bash
docker compose run --rm uncp-offsec scan ejemplo.uncp.edu.pe \
  --exact-host --no-email \
  --profile active-authorized --scope /work/scope.uncp.json \
  --active --nmap --nmap-safe-scripts --nmap-vuln-authorized \
  --dns-inventory --headers --crawl --content-discovery \
  --wordlist /opt/uncp-tools/wordlists/raft-medium-directories.txt \
  --sqli-detection --anonymous-assessment --rate-limit-check \
  --dast --zap-ajax --cves --cve-cache /reports/.cve-cache \
  -o /reports/ejemplo.uncp.edu.pe.json
```

El host exacto debe seguir estando permitido por el archivo de alcance. Omite
`--no-email` si también deseas evaluar la postura de correo de ese subdominio.

### Perfiles y alcance autorizado

`standard` es el perfil predeterminado: realiza descubrimiento, consultas DNS y
sondas HTTP(S) acotadas. `passive` deja explícito que no se habilitarán relay SMTP,
puertos ni Nuclei. Cualquier módulo activo requiere un archivo JSON de autorización
y uno de los perfiles `active-authorized`, `active-validation` o `lab`:

```bash
cp scope.example.json scope.local.json
# Edita domains y confirma allow_active: true solo para una prueba aprobada.
docker compose run --rm uncp-offsec scan ejemplo.com \
  --profile active-authorized --scope /work/scope.local.json \
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

El alcance usa siempre `"assessment_mode": "identification-only"` y se limita a
los dominios declarados y sus subdominios. Si un host responde
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
permita pruebas activas y, para ffuf, una wordlist aprobada. Ambos usan límites
conservadores y no son parte del perfil estándar:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-authorized \
  --scope /work/scope.local.json --crawl --content-discovery \
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
  --scope /work/scope.local.json --sqli-detection \
  -o /reports/ejemplo.html --format html
```

Para analizar parámetros POST/JSON, añade una solicitud HTTP cruda capturada por
el propietario. La opción es repetible y el encabezado `Host` debe pertenecer al alcance:

```bash
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/scope.local.json --sqlmap-request /work/request-search.txt \
  -o /reports/ejemplo.json
```

### OWASP ZAP DAST

ZAP se ejecuta como servicio interno sin publicar su API al host. El alcance debe
establecer `allow_dast: true`; `--zap-ajax` requiere además
`allow_ajax_spider: true`. Las URL de Katana se importan como semillas y
`dast_max_minutes` reparte el plazo entre spider, AJAX spider y active scan:

```bash
docker compose --profile dast up -d zap
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/scope.local.json --crawl --dast --zap-ajax \
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
cp auth-headers.example.json auth-headers.local.json
docker compose run --rm uncp-offsec scan ejemplo.com --profile active-validation \
  --scope /work/scope.local.json --crawl --dast --zap-ajax \
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
  --profile active-validation --scope /work/scope.local.json \
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
preparado en `scope.lab.json`. El laboratorio se detiene con:

```bash
docker compose --profile lab down
```

```bash
python -m pip install -e ".[dev]"
ruff check src tests
pytest
```

`requirements.lock` fija las dependencias Python usadas por la imagen. Actualízalo
con una herramienta de bloqueo, reconstruye la imagen y valida `doctor`, Ruff y
pytest antes de publicar una nueva versión. Las versiones externas viven en
`Containerfile`.
