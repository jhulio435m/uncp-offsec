# Plan v0.2: evaluación anónima

## Mejora operativa: ejecución enfocada

- [x] Añadir `--exact-host` para omitir Subfinder y entregar solo el host indicado
  a todos los módulos web posteriores.
- [x] Conservar la validación del archivo de alcance para cualquier prueba activa.
- [x] Registrar `target_mode` en JSON y HTML para diferenciar un inventario de
  dominio de una evaluación de host exacto.
- [x] Sustituir la barra opaca por progreso con etapa/herramienta, objetivo,
  animación, tiempo transcurrido y duración por etapa.
- [x] Probar que el modo exacto no invoca el descubrimiento de subdominios.

## Objetivo

Mejorar la cobertura sin credenciales manteniendo el modo de identificación:
solo solicitudes HTTP seguras y acotadas, sin fuerza bruta, cambios de estado,
extracción de datos ni evasión.

## Entregables

1. Inventario de superficies de autenticación, API y rutas sensibles.
2. Comprobaciones `HEAD`, `GET` con respuesta truncada y `OPTIONS` dentro del alcance.
3. Revisión de CORS, caché, cookies, tokens expuestos y métodos anunciados.
4. Prueba de rate limiting de baja intensidad, habilitada expresamente en el alcance.
5. Métricas de URL, rutas, parámetros, API e identificadores observados.
6. Correlación de señales por CWE, CVE y título entre motores.
7. Semgrep y Trivy multilenguaje dentro de la imagen reproducible.
8. Matriz OWASP que mantenga A01/IDOR multirrol como no evaluado sin cuentas.
9. Pruebas unitarias, integración en Juice Shop e informe JSON/HTML.

## Criterios de aceptación

- Ninguna solicitud `POST`, `PUT`, `PATCH` o `DELETE` es enviada por el módulo.
- Redirecciones fuera del origen no se siguen.
- Cuerpos de respuesta no se almacenan y su lectura está limitada.
- Los tokens y cookies nunca aparecen en el informe.
- Una cabecera `Allow` no confirma autorización: se reporta como señal potencial.
- La ausencia de rate limiting tras pocas solicitudes no se reporta como vulnerabilidad.
