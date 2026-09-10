# Flujo de OWASP ZAP DAST

Este diagrama explica la fase DAST ejecutada después del descubrimiento web,
puertos, servicios y versiones. ZAP analiza la aplicación desde el exterior;
no revisa su código fuente.

```mermaid
flowchart TD
    A[URLs y host exacto descubiertos] --> B{¿El alcance permite DAST?}
    B -- No --> B1[Omitir ZAP y registrar cobertura no autorizada]
    B -- Sí --> C{¿El servicio ZAP está disponible?}
    C -- No --> C1[Registrar cobertura incompleta]
    C -- Sí --> D[Crear una sesión ZAP limpia]

    D --> E[Seleccionar hasta 5 hosts autorizados]
    E --> F{¿Hay cabeceras de sesión?}
    F -- Sí --> F1[Aplicarlas solo al origen autorizado]
    F -- No --> G[Continuar como usuario anónimo]
    F1 --> H
    G --> H{¿Hay una especificación OpenAPI autorizada?}
    H -- Sí --> H1[Importar rutas y operaciones de la API]
    H -- No --> I[Continuar con las rutas descubiertas]
    H1 --> I

    I --> J[Excluir rutas sensibles configuradas]
    J --> J1["/logout · /delete · /payment · /admin"]
    J1 --> K[Importar hasta 200 URLs descubiertas por Katana]
    K --> L[Spider tradicional]
    L --> L1[Seguir enlaces, formularios y rutas del mismo subárbol]

    L1 --> M{¿AJAX Spider está autorizado?}
    M -- Sí --> M1[Navegar contenido generado por JavaScript]
    M -- No --> N[Continuar]
    M1 --> N

    N --> O[Escaneo activo]
    O --> O1[Enviar variaciones controladas de parámetros y cabeceras]
    O1 --> O2[Observar errores, reflejos y cambios de respuesta]
    O2 --> P[Recopilar alertas de ZAP]

    P --> Q[Descartar alertas marcadas como falso positivo]
    Q --> R[Agrupar ocurrencias por regla]
    R --> S[Conservar URL, método, parámetro, evidencia, CWE y confianza]
    S --> T{¿Terminó dentro del plazo?}
    T -- No --> T1[Marcar cobertura incompleta]
    T -- Sí --> U[Marcar módulo evaluado]
    T1 --> V[Correlación con TLS, Nmap, Nuclei y CVE]
    U --> V
    V --> W[Informe HTML o JSON]
```

## Qué significa cada recorrido

- **Spider tradicional:** encuentra páginas enlazadas, formularios y rutas HTML.
- **AJAX Spider:** utiliza navegación compatible con JavaScript para descubrir
  contenido dinámico y aplicaciones SPA.
- **Escaneo activo:** modifica solicitudes de forma controlada para buscar señales
  de inyección, XSS, traversal, cookies inseguras, divulgación de información y
  otras reglas disponibles en ZAP.
- **Correlación:** compara las alertas con los resultados de otros motores. Una
  coincidencia aumenta la prioridad de revisión, pero no confirma por sí sola una
  vulnerabilidad.

## Límites implementados

- Requiere `allow_dast: true` en el archivo de alcance.
- El AJAX Spider requiere además `allow_ajax_spider: true`.
- Usa como máximo cinco hosts; con `-sub` recibe únicamente el subdominio exacto.
- Importa como máximo 200 semillas de Katana por host.
- El spider tradicional limita cada recorrido a 200 elementos hijos.
- El plazo predeterminado es de 10 minutos y puede configurarse con
  `dast_max_minutes` entre 1 y 60 minutos.
- Las rutas de `exclude_paths` no se entregan al spider ni al escaneo activo.
- Las cabeceras de autenticación se aplican solamente al origen objetivo y se
  eliminan de ZAP al terminar.
- Si vence el plazo o falla la API de ZAP, el resultado se declara incompleto.

## Interpretación de resultados

Una alerta de ZAP es evidencia para revisión, no una vulnerabilidad confirmada.
El informe la clasifica inicialmente como:

- `POTENTIAL`: señal con evidencia o confianza limitada.
- `PROBABLE`: confianza alta y evidencia concreta.
- `FALSE POSITIVE`: ZAP la marcó como falso positivo y el escáner la descarta.

La confirmación final requiere reproducir la condición de manera controlada y
verificar el comportamiento del servidor sin extraer datos ni explotar el sistema.
