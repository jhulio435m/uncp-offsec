# Guia de uso de la imagen Docker de UnCP OffSec

**Version:** 0.3.3  
**Imagen:** `ghcr.io/jhulio435m/uncp-offsec:0.3.3`

Esta guia explica como descargar y ejecutar la imagen preconstruida en Linux y
Windows. Los usuarios no compilan el proyecto: Docker descarga la imagen
publicada en GitHub Container Registry (GHCR).

> Antes de distribuirla, tanto el repositorio como el paquete `uncp-offsec` de
> GHCR deben tener visibilidad publica. La visibilidad del paquete se configura
> en GitHub, en **Profile > Packages > uncp-offsec > Package settings > Change
> visibility > Public**.

## Que incluye la imagen

- CLI y asistente interactivo de UnCP OffSec.
- Scope autorizado para `uncp.edu.pe`.
- Subfinder, HTTPX, WhatWeb, testssl.sh, Naabu, Nmap y Nuclei.
- Katana, ffuf, SQLMap, Semgrep, Bandit, Trivy y pip-audit.
- Wordlists rapida, estandar y completa para ffuf.
- Plantillas Nuclei revisadas y el script `vulners.nse`.

Para el flujo completo se usa Docker Compose porque ZAP se ejecuta como un
contenedor complementario.

## Linux

### 1. Requisitos

- Git.
- Docker Engine activo.
- Docker Compose v2 (`docker compose version`).

### 2. Descargar la configuracion

```bash
git clone https://github.com/jhulio435m/uncp-offsec.git
cd uncp-offsec
mkdir -p reports
```

El repositorio aporta los archivos Compose, la configuracion de ZAP y el montaje
del directorio `reports/`. No se compilara la imagen.

### 3. Seleccionar y descargar la imagen

```bash
export UNCP_OFFSEC_VERSION=0.3.3
docker compose -f compose.yaml -f compose.prebuilt.yaml pull uncp-offsec zap
```

### 4. Verificar la instalacion

```bash
docker compose -f compose.yaml -f compose.prebuilt.yaml run \
  --rm --no-build uncp-offsec doctor --full
```

`--no-build` garantiza que Compose utilice la imagen descargada y no intente
construirla localmente.

### 5. Abrir el asistente

```bash
docker compose -f compose.yaml -f compose.prebuilt.yaml run \
  --rm --no-build uncp-offsec
```

Si ya construiste la imagen localmente, el comando tradicional sigue siendo
valido:

```bash
docker compose run --rm uncp-offsec
```

Para conservar un comando corto usando exclusivamente la imagen descargada,
configura una vez los archivos Compose:

```bash
export COMPOSE_FILE=compose.yaml:compose.prebuilt.yaml
docker compose run --rm --no-build uncp-offsec
```

### 6. Ejecutar un escaneo UNCP

```bash
docker compose -f compose.yaml -f compose.prebuilt.yaml run \
  --rm --no-build uncp-offsec \
  scan -sub visitasautoridades.uncp.edu.pe \
  -o /reports/visitasautoridades.uncp.edu.pe.html
```

El reporte se guarda en:

```text
uncp-offsec/reports/visitasautoridades.uncp.edu.pe.html
```

## Windows con PowerShell

### 1. Requisitos

- Git para Windows.
- Docker Desktop iniciado y configurado para contenedores Linux.
- Docker Compose incluido con Docker Desktop.

### 2. Descargar la configuracion

```powershell
git clone https://github.com/jhulio435m/uncp-offsec.git
cd uncp-offsec
New-Item -ItemType Directory -Force reports | Out-Null
```

### 3. Seleccionar y descargar la imagen

```powershell
$env:UNCP_OFFSEC_VERSION = "0.3.3"
docker compose -f compose.yaml -f compose.prebuilt.yaml pull uncp-offsec zap
```

### 4. Verificar la instalacion

```powershell
docker compose -f compose.yaml -f compose.prebuilt.yaml run --rm --no-build uncp-offsec doctor --full
```

### 5. Abrir el asistente

```powershell
docker compose -f compose.yaml -f compose.prebuilt.yaml run --rm --no-build uncp-offsec
```

Si ya construiste la imagen localmente, el comando tradicional sigue siendo
valido:

```powershell
docker compose run --rm uncp-offsec
```

Para conservar un comando corto con la imagen descargada:

```powershell
$env:COMPOSE_FILE = "compose.yaml;compose.prebuilt.yaml"
docker compose run --rm --no-build uncp-offsec
```

### 6. Ejecutar un escaneo UNCP

```powershell
docker compose -f compose.yaml -f compose.prebuilt.yaml run `
  --rm --no-build uncp-offsec `
  scan -sub visitasautoridades.uncp.edu.pe `
  -o /reports/visitasautoridades.uncp.edu.pe.html
```

El reporte se guarda en:

```text
uncp-offsec\reports\visitasautoridades.uncp.edu.pe.html
```

## Descargar solo la imagen

Si solo se necesita comprobar la imagen o usar funciones que no dependan de ZAP:

```bash
docker pull ghcr.io/jhulio435m/uncp-offsec:0.3.3
docker run --rm ghcr.io/jhulio435m/uncp-offsec:0.3.3 doctor --full
docker run --rm ghcr.io/jhulio435m/uncp-offsec:0.3.3 --help
```

Para escaneos web completos debe preferirse Docker Compose, ya que administra el
contenedor ZAP, la red interna y el directorio de reportes.

## NVD API Key opcional

La clave NVD no es obligatoria. Permite consultar la API con limites mas amplios.
Quien disponga de una puede crear un archivo `.env` en la raiz:

```env
NVD_API_KEY=SU_CLAVE
```

El archivo `.env` esta excluido de Git. No debe publicarse ni incorporarse en la
imagen.

## Actualizar a una nueva version

Linux:

```bash
cd uncp-offsec
git pull
export UNCP_OFFSEC_VERSION=0.3.3
docker compose -f compose.yaml -f compose.prebuilt.yaml pull
```

Windows PowerShell:

```powershell
cd uncp-offsec
git pull
$env:UNCP_OFFSEC_VERSION = "0.3.3"
docker compose -f compose.yaml -f compose.prebuilt.yaml pull
```

## Solucion de problemas

### `denied` o `unauthorized` al descargar

Confirma que el paquete GHCR tenga visibilidad **Public**. Hacer publico solamente
el repositorio no garantiza que el paquete asociado tambien sea publico.

### Compose intenta construir una imagen

Verifica que se hayan indicado ambos archivos:

```text
-f compose.yaml -f compose.prebuilt.yaml
```

y que el comando `run` incluya `--no-build`.

### Docker no esta disponible

- Linux: inicia Docker con `sudo systemctl start docker`.
- Windows: abre Docker Desktop y espera a que indique que el motor esta activo.

### No aparece el reporte

Usa una ruta interna bajo `/reports/`, porque ese directorio esta montado en la
carpeta local `reports/`.

## Limites y autorizacion

El scope incluido habilita exclusivamente los objetivos autorizados bajo
`uncp.edu.pe`. Tener la imagen o el archivo de scope no reemplaza la autorizacion
institucional. El scanner valida e informa; no obtiene acceso, no mantiene
persistencia, no extrae datos y no evade controles defensivos.
