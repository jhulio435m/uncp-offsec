---
name: Soryntel Security
description: Equipo rojo. Negro mate, blanco y un único rojo de señal; rótulos condensados a escala de cartel.
colors:
  negro: "#0b0b0c"
  negro-alto: "#17171a"
  blanco: "#ffffff"
  rojo: "#e11d2e"
  rojo-claro: "#ff5a67"
  gris: "#a3a8b3"
  gris-linea: "#34373e"
  gris-papel: "#5a5f6a"
  linea-clara: "#d7d9de"
typography:
  display:
    fontFamily: "Big Shoulders Variable, Arial Narrow, sans-serif"
    fontSize: "clamp(2.2rem, min(11.4vw, 21vh), 11.5rem)"
    fontWeight: 900
    lineHeight: 0.9
    letterSpacing: "-0.005em"
  headline:
    fontFamily: "Big Shoulders Variable, Arial Narrow, sans-serif"
    fontSize: "clamp(2.6rem, 6.4vw, 5.75rem)"
    fontWeight: 900
    lineHeight: 0.9
  title:
    fontFamily: "Big Shoulders Variable, Arial Narrow, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "0.02em"
  body:
    fontFamily: "Hanken Grotesk Variable, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "JetBrains Mono Variable, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    letterSpacing: "0.06em"
rounded:
  none: "0px"
spacing:
  margen: "clamp(1rem, 4.5vw, 4.5rem)"
  seccion: "clamp(4.5rem, 9vw, 8.5rem)"
  ancho: "84rem"
  cabecera: "68px"
components:
  boton-rojo:
    backgroundColor: "{colors.rojo}"
    textColor: "{colors.blanco}"
    typography: "{typography.title}"
    rounded: "{rounded.none}"
    padding: "0.5rem 1.75rem"
    height: "3.6rem"
  boton-rojo-hover:
    backgroundColor: "{colors.blanco}"
    textColor: "{colors.negro}"
  boton-linea:
    backgroundColor: "{colors.negro}"
    textColor: "{colors.blanco}"
    rounded: "{rounded.none}"
    height: "3.6rem"
  filtro:
    backgroundColor: "{colors.negro}"
    textColor: "{colors.gris}"
    height: "2.75rem"
  filtro-activo:
    backgroundColor: "{colors.blanco}"
    textColor: "{colors.negro}"
  campo:
    backgroundColor: "{colors.negro-alto}"
    textColor: "{colors.blanco}"
    rounded: "{rounded.none}"
    height: "3.1rem"
---

# Design System: Soryntel Security

## Overview

Una marca ofensiva que escribe su propio límite. Dice en grande lo que encuentra y, con el mismo peso, lo que nunca hace. Directa y sin adornos: negro, blanco y rojo. Nada de capuchas, verde de terminal, candados, escudos ni mapas de ataques.

## Colors

- **Negro** es el fondo; **negro-alto** marca filas activas y campos.
- **Blanco** es texto y, en las secciones de reglas y plataforma, el fondo completo. La alternancia negro/blanco es a escala de sección.
- **Rojo** es uno solo y significa acción o prohibición: botón principal, la barra bajo «ellos», la regla del servicio y el titular de «La plataforma nunca». No decora: barras, números y viñetas son blancos. Como texto sobre negro se usa `rojo-claro`, que sí alcanza contraste.
- **Severidad**: `rojo-claro` para alta y blanco para media, solo dentro de la tabla de hallazgos.
- **Grises**: `gris` para texto secundario sobre negro, `gris-papel` sobre blanco, `gris-linea` y `linea-clara` para las líneas.

## Typography

- **Big Shoulders** en mayúsculas, peso 800 a 900, para titulares, rótulos, botones y nombres de servicio.
- **Hanken Grotesk** para lectura, en minúsculas.
- **JetBrains Mono** solo para datos: área, severidad, estado y códigos del informe. Las etiquetas van en Hanken.

Autoalojadas con `@fontsource-variable`.

## Layout

Filas a todo el ancho separadas por líneas finas. Cada sección abre con titular a la izquierda y párrafo a la derecha. Los servicios son filas de tres columnas (nombre, qué es, qué se revisa), no tarjetas. «La plataforma nunca» es una banda negra de borde a borde con una regla por fila, a la misma escala que los nombres de servicio. El sitio se reparte en páginas (inicio, auditoría, reglas, informe, plataforma, preguntas, solicitar); cada página interior abre con su barra de sección y un título a escala de cartel, y cierra con la misma llamada a solicitar. La portada llena la primera pantalla y termina en una banda de cinco celdas: los cuatro servicios y la regla en rojo.

Bajo 980 px las filas pasan a dos columnas y la banda a una rejilla 2×2 con la regla debajo; bajo 760 px se oculta la navegación y todo va a una columna; bajo 520 px el formulario y las listas quedan en una columna.

## Elevation & Depth

Plano. Sin sombras ni desenfoques. La jerarquía sale del tamaño, del contraste negro/blanco y de las líneas.

## Shapes

Todo recto, sin radios. Líneas de 1 px para separar y de 3 px para abrir un bloque. Marcadores cuadrados: lleno (validado), contorno (potencial), base (revisión manual).

## Components

- **Botones**: rojo (acción principal), contorno blanco (secundaria), negro sobre secciones blancas. El rojo pasa a blanco al pasar el cursor.
- **Banda de portada**: celdas enlazadas a cada servicio y a las reglas.
- **Tabla de hallazgos**: filtros por estado de verificación con `aria-pressed`; cada fila es un botón que abre evidencia, remediación y el código de estado del informe. Siempre lleva el aviso de extracto ilustrativo.
- **Formulario**: campos sobre `negro-alto`, opciones como casillas de fila completa, confirmación de autoridad con borde discontinuo, errores en `rojo-claro` bajo cada campo y una alternativa por correo o WhatsApp si el envío falla.
- **Foco**: contorno de 3 px, blanco sobre negro y negro sobre blanco.
- **Mapa de superficie** (portada): ilustración vectorial en bucle de 12 s. Se trazan las conexiones, una línea roja barre los activos y cada uno queda marcado con su estado; el pie cambia al pasar el cursor o el foco.
- **Diagramas** (`.vz`): recuadro de línea fina con datos en mono. Tres marcas en todo el sitio: cuadro blanco (correcto), rojo (hallazgo), contorno (por revisar). Los renglones aparecen a su turno y el ciclo se repite; la rejilla de puertos se barre de izquierda a derecha. Cada frente de auditoría tiene el suyo: cabeceras y cadena de correo, puertos, código y dependencias, matriz de accesos. Siempre con datos de ejemplo y rotulados.
- **Índice de frentes** (inicio): filas enlazadas con nombre, entrada y flecha; al pasar el cursor se hunden hacia dentro.
- **Preguntas**: `details` de fila completa con la pregunta en rótulo y una cruz que pasa a raya al abrir; solo una abierta a la vez.
- **Navegación**: siete páginas; el enlace de la página activa lleva filete rojo. En teléfono baja a una segunda fila deslizable.
- **Barra de sección**: fija bajo la cabecera mientras dura la sección, con número y nombre a la izquierda y un rótulo a la derecha, en mono.
- **Coreografía de scroll**: al entrar cada sección se traza su línea superior de izquierda a derecha, la barra de sección entra desde ambos lados y el contenido aparece escalonado (80 ms entre elementos). Solo se activa con JavaScript; sin él, o con `prefers-reduced-motion`, todo está visible desde el inicio.
- **Movimiento**: además, la barra roja del titular se traza una vez al cargar.

## Do's and Don'ts

- Sí: decir qué se revisa y qué no con el mismo peso visual.
- Sí: rotular como ilustrativo cualquier dato de ejemplo.
- Sí: rojo solo para acción, prohibición o hallazgo.
- No: tarjetas con icono, degradados, brillos ni radios.
- No: clientes, cifras, precios o certificaciones que no existan.
- No: mono fuera de los datos.
