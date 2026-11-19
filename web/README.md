# Web de Soryntel Security

Página de [security.soryntel.com](https://security.soryntel.com): vende el servicio de auditoría de Soryntel y presenta la plataforma de evaluación. Next.js (App Router) con Tailwind CSS 4, exportada como sitio estático y servida por un Worker de Cloudflare que también recibe el formulario.

```sh
npm install
npm run dev              # http://localhost:3000 (sin el endpoint del formulario)
npm run build            # genera out/
npx wrangler dev         # http://localhost:8787, sitio + /api/solicitud
```

- Páginas (`src/app/`): inicio, `/auditoria`, `/reglas`, `/informe`, `/plataforma`, `/preguntas` y `/solicitar`. Cabecera y pie compartidos en `src/app/layout.tsx` y `src/components/site-chrome.tsx`
- Contenido (servicios, reglas, hallazgos de ejemplo, preguntas, contacto): `src/content/site.ts`
- Diagramas animados (registro de evaluación, cabeceras y correo, puertos, código, accesos): `src/components/visuals.tsx`; mapa de la portada: `src/components/surface-map.tsx`
- Coreografía de scroll y barras de sección: `src/components/choreo.tsx`
- Tabla de hallazgos: `src/components/findings.tsx`; formulario: `src/components/request-form.tsx`
- Endpoint del formulario: `worker/index.ts`
- Estilos y tokens: `src/app/globals.css`. Diseño: `../DESIGN.md` y `../PRODUCT.md`

Las rutas son archivos estáticos (`auditoria.html`, etc.): un servidor de archivos simple no las resuelve sin extensión, así que para verlas en local usa `npx wrangler dev`.

Los hallazgos y los diagramas usan datos de ejemplo y están rotulados así. La web no nombra clientes ni publica cifras, precios o certificaciones.

## Formulario

`POST /api/solicitud` valida la solicitud y la envía al chat de Soryntel en Telegram, igual que soryntel.com y kusi.soryntel.com. Necesita dos secretos en el Worker:

```sh
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_CHAT_ID
```

Sin ellos responde 503 y el formulario ofrece correo y WhatsApp como alternativa. Opcionales: `TURNSTILE_SECRET_KEY` (antispam) y `ALLOWED_ORIGINS`.

## Despliegue

`wrangler.jsonc` define el Worker `soryntel-security`, los archivos de `out/` y el dominio `security.soryntel.com`.

```sh
npm run deploy   # build + wrangler deploy
```

Para desplegar en cada push, conecta el Worker al repositorio en el panel de Cloudflare (Settings → Builds) con root directory `web`, build command `npm run build` y deploy command `npx wrangler deploy`. La versión de Node sale de `.node-version`.
