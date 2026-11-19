// Worker de Soryntel Security: sirve el sitio estático y atiende POST /api/solicitud.
// Valida la solicitud de la web y la envía al chat autorizado de Soryntel en
// Telegram (mismo canal que usan soryntel.com y kusi.soryntel.com). No guarda
// ni registra el contenido.
//
// Secretos del Worker (no van en el repositorio):
//   wrangler secret put TELEGRAM_BOT_TOKEN
//   wrangler secret put TELEGRAM_CHAT_ID
// Opcional: TURNSTILE_SECRET_KEY, ALLOWED_ORIGINS=https://otro.dominio,...

interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  ALLOWED_ORIGINS?: string;
  TURNSTILE_SECRET_KEY?: string;
}

// Un secreto mal cargado no puede desviar solicitudes a otro destino.
const AUTHORIZED_CHAT_ID = "7963455215";

const NEEDS = new Set([
  "Web y correo",
  "Red e infraestructura",
  "Código y dependencias",
  "Pentest manual",
  "Usar la plataforma en mi equipo",
  "No estoy seguro",
]);

const DEFAULT_ORIGINS = ["https://security.soryntel.com", "http://localhost:8787", "http://127.0.0.1:8787"];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
const SUSPICIOUS = /(<\s*script|javascript:|data:text\/html|on\w+\s*=|<\s*iframe|<\s*object)/i;
const MAX_BODY_BYTES = 8 * 1024;

function allowedOrigin(origin: string, env: Env) {
  const extra = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  return [...DEFAULT_ORIGINS, ...extra].includes(origin);
}

function reply(body: unknown, status: number, origin: string, env: Env) {
  const headers: Record<string, string> = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    Vary: "Origin",
  };
  if (origin && allowedOrigin(origin, env)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type";
  }
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
}

const clean = (value: unknown, max: number) =>
  String(value ?? "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .trim()
    .slice(0, max);

const escapeHtml = (value: string) => value.replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c] ?? c);

async function solicitud(request: Request, env: Env) {
  const origin = request.headers.get("Origin") ?? "";
  if (request.method === "OPTIONS") return reply(null, 204, origin, env);
  if (request.method !== "POST") return reply({ ok: false, error: "Método no permitido." }, 405, origin, env);
  if (origin && !allowedOrigin(origin, env)) return reply({ ok: false, error: "Origen no permitido." }, 403, origin, env);
  if (!request.headers.get("Content-Type")?.includes("application/json")) {
    return reply({ ok: false, error: "Formato no válido." }, 415, origin, env);
  }
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) return reply({ ok: false, error: "Solicitud demasiado grande." }, 413, origin, env);

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw);
  } catch {
    return reply({ ok: false, error: "Formato no válido." }, 400, origin, env);
  }

  // Campo trampa: las personas no lo ven; los bots suelen llenarlo.
  if (clean(payload.sitio, 200)) return reply({ ok: true }, 200, origin, env);

  const needs = (Array.isArray(payload.necesidades) ? payload.necesidades : []).map((n) => clean(n, 60)).filter((n) => NEEDS.has(n));
  const data = {
    nombre: clean(payload.nombre, 120),
    organizacion: clean(payload.organizacion, 120),
    correo: clean(payload.correo, 120).toLowerCase(),
    activos: clean(payload.activos, 300),
    mensaje: clean(payload.mensaje, 800),
  };
  const errors: Record<string, string> = {};
  if (data.nombre.length < 2) errors.nombre = "Escriba su nombre.";
  if (data.organizacion.length < 2) errors.organizacion = "Indique su empresa o equipo.";
  if (!EMAIL.test(data.correo)) errors.correo = "Escriba un correo válido.";
  if (!needs.length) errors.necesidades = "Marque al menos una opción.";
  if (payload.autorizado !== true) errors.autorizado = "Necesitamos esta confirmación para evaluar cualquier activo.";
  if (SUSPICIOUS.test(Object.values(data).join(" "))) errors.mensaje = "El texto contiene contenido no permitido.";
  if (Object.keys(errors).length) return reply({ ok: false, errors }, 422, origin, env);

  // Antispam: si hay secreto de Turnstile, el token es obligatorio.
  if (env.TURNSTILE_SECRET_KEY) {
    const form = new FormData();
    form.append("secret", env.TURNSTILE_SECRET_KEY);
    form.append("response", clean(payload.turnstileToken, 2048));
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) form.append("remoteip", ip);
    const check = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form })
      .then((r) => r.json() as Promise<{ success?: boolean }>)
      .catch(() => ({ success: false }));
    if (!check.success) {
      return reply({ ok: false, errors: { turnstileToken: "Confirme que no es un robot e inténtelo de nuevo." } }, 422, origin, env);
    }
  }

  if (!env.TELEGRAM_BOT_TOKEN || env.TELEGRAM_CHAT_ID !== AUTHORIZED_CHAT_ID) {
    return reply({ ok: false, error: "El canal de solicitudes no está disponible." }, 503, origin, env);
  }

  const text = [
    "<b>Nueva solicitud · Soryntel Security</b>",
    `<b>Nombre:</b> ${escapeHtml(data.nombre)}`,
    `<b>Empresa o equipo:</b> ${escapeHtml(data.organizacion)}`,
    `<b>Correo:</b> ${escapeHtml(data.correo)}`,
    `<b>Necesita:</b> ${escapeHtml(needs.join(", "))}`,
    `<b>Activos:</b> ${escapeHtml(data.activos || "No indicados")}`,
    `<b>Mensaje:</b> ${escapeHtml(data.mensaje || "Sin mensaje")}`,
    "<b>Declara tener autoridad sobre los activos:</b> sí",
  ].join("\n");

  const sent = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, parse_mode: "HTML", disable_web_page_preview: true }),
  }).catch(() => null);

  if (!sent?.ok) return reply({ ok: false, error: "No se pudo enviar la solicitud." }, 502, origin, env);
  return reply({ ok: true }, 200, origin, env);
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/solicitud") return solicitud(request, env);
    if (pathname.startsWith("/api/")) return new Response("No encontrado", { status: 404 });
    return env.ASSETS.fetch(request);
  },
};

export default worker;
