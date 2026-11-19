"use client";

import { useState } from "react";
import { CONTACT, NEEDS } from "@/content/site";

type Status = "idle" | "sending" | "sent" | "failed";

/** Solicitud de evaluación: valida en el navegador, envía a /api/solicitud y, si falla, ofrece el correo. */
export function RequestForm() {
  const [status, setStatus] = useState<Status>("idle");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [problem, setProblem] = useState("");

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const data = {
      nombre: String(form.get("nombre") ?? "").trim(),
      organizacion: String(form.get("organizacion") ?? "").trim(),
      correo: String(form.get("correo") ?? "").trim(),
      activos: String(form.get("activos") ?? "").trim(),
      mensaje: String(form.get("mensaje") ?? "").trim(),
      necesidades: form.getAll("necesidades").map(String),
      autorizado: form.get("autorizado") === "on",
      sitio: String(form.get("sitio") ?? ""),
    };

    const found: Record<string, string> = {};
    if (data.nombre.length < 2) found.nombre = "Escriba su nombre.";
    if (data.organizacion.length < 2) found.organizacion = "Indique su empresa o equipo.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.correo)) found.correo = "Escriba un correo válido.";
    if (!data.necesidades.length) found.necesidades = "Marque al menos una opción.";
    if (!data.autorizado) found.autorizado = "Necesitamos esta confirmación para evaluar cualquier activo.";
    setErrors(found);
    if (Object.keys(found).length) {
      const first = e.currentTarget.querySelector<HTMLElement>(`[name="${Object.keys(found)[0]}"]`);
      first?.focus();
      return;
    }

    setStatus("sending");
    setProblem("");
    try {
      const res = await fetch("/api/solicitud", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
      const body = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string; errors?: Record<string, string> };
      if (res.ok && body.ok) return setStatus("sent");
      const known = ["nombre", "organizacion", "correo", "necesidades", "mensaje", "autorizado"];
      if (body.errors && Object.keys(body.errors).every((k) => known.includes(k))) {
        setErrors(body.errors);
        return setStatus("idle");
      }
      // Un error que el formulario no sabe mostrar junto a un campo va al aviso general.
      if (body.errors) return (setProblem(Object.values(body.errors).join(" ")), setStatus("failed"));
      setProblem(body.error ?? "No se pudo enviar la solicitud.");
    } catch {
      setProblem("No hay conexión con el servidor.");
    }
    setStatus("failed");
  }

  if (status === "sent") {
    return (
      <div className="enviado" role="status">
        <h3>Solicitud recibida.</h3>
        <p>Le escribiremos al correo que indicó para acordar el alcance. No evaluamos nada antes de tener su autorización por escrito.</p>
      </div>
    );
  }

  const err = (name: string) =>
    errors[name] ? (
      <span className="error" id={`e-${name}`}>
        {errors[name]}
      </span>
    ) : null;
  const aria = (name: string) => ({ "aria-invalid": errors[name] ? true : undefined, "aria-describedby": errors[name] ? `e-${name}` : undefined });

  return (
    <form className="solicitud" onSubmit={submit} noValidate>
      <div className="campos">
        <label>
          <span>Nombre</span>
          <input name="nombre" autoComplete="name" required {...aria("nombre")} />
          {err("nombre")}
        </label>
        <label>
          <span>Empresa o equipo</span>
          <input name="organizacion" autoComplete="organization" required {...aria("organizacion")} />
          {err("organizacion")}
        </label>
        <label>
          <span>Correo de trabajo</span>
          <input name="correo" type="email" autoComplete="email" inputMode="email" required {...aria("correo")} />
          {err("correo")}
        </label>
        <label>
          <span>
            Qué quiere evaluar <small>opcional</small>
          </span>
          <input name="activos" placeholder="Por ejemplo: miempresa.com y su correo" />
        </label>
      </div>

      <fieldset {...aria("necesidades")}>
        <legend>Qué necesita</legend>
        <div className="opciones">
          {NEEDS.map((n) => (
            <label key={n} className="opcion">
              <input type="checkbox" name="necesidades" value={n} />
              <span>{n}</span>
            </label>
          ))}
        </div>
        {err("necesidades")}
      </fieldset>

      <label>
        <span>
          Algo más que debamos saber <small>opcional</small>
        </span>
        <textarea name="mensaje" rows={4} maxLength={800} />
        {err("mensaje")}
      </label>

      <label className="trampa" aria-hidden="true">
        Sitio web
        <input name="sitio" tabIndex={-1} autoComplete="off" />
      </label>

      <label className="opcion confirmar">
        <input type="checkbox" name="autorizado" required {...aria("autorizado")} />
        <span>Tengo autoridad sobre los activos que quiero evaluar, o puedo conseguir la autorización de quien la tiene.</span>
      </label>
      {err("autorizado")}

      <div className="enviar">
        <button type="submit" className="boton boton-rojo" disabled={status === "sending"}>
          {status === "sending" ? "Enviando…" : "Enviar solicitud"}
        </button>
        <p>Solo usamos estos datos para responderle.</p>
      </div>

      {status === "failed" && (
        <p className="fallo" role="alert">
          {problem} Escríbanos a <a href={`mailto:${CONTACT.email}?subject=Solicitud%20de%20auditor%C3%ADa`}>{CONTACT.email}</a> o por{" "}
          <a href={CONTACT.whatsapp}>WhatsApp</a> y le respondemos por ahí.
        </p>
      )}
    </form>
  );
}
