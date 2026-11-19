import type { Metadata } from "next";
import { Cierre, PageHead } from "@/components/blocks";
import { Ceja } from "@/components/choreo";
import { DOES, NEVER, STEPS } from "@/content/site";

export const metadata: Metadata = {
  title: "Reglas",
  description: "El límite escrito de la plataforma: valida, identifica y reporta, nunca obtiene acceso. Y cómo es el proceso de una auditoría.",
  alternates: { canonical: "/reglas" },
};

export default function Page() {
  return (
    <>
      <PageHead n="01" name="Reglas" side="Alcance por escrito" title="Las reglas van por escrito.">
        Nada se evalúa sin autorización y sin un alcance firmado. La plataforma tiene un límite fijo: valida, identifica
        y reporta.
      </PageHead>

      <section className="seccion seccion-clara" data-seccion="">
        <Ceja n="02" name="Lo que hace" side="Sin dañar" />
        <div className="ancho">
          <ul className="hace">
            {DOES.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="nunca" data-seccion="" aria-labelledby="nunca-titulo">
        <h2 id="nunca-titulo" className="ancho">
          La plataforma nunca
        </h2>
        <ul>
          {NEVER.map((n) => (
            <li key={n}>
              <span className="ancho">{n}</span>
            </li>
          ))}
        </ul>
        <p className="ancho excepcion">
          La explotación solo ocurre en el pentest manual: la hace una persona, sobre los activos, en el horario y con
          las pruebas que usted autorizó por escrito.
        </p>
      </section>

      <section className="seccion" data-seccion="">
        <Ceja n="03" name="Proceso" side="Cuatro pasos" />
        <div className="ancho">
          <div className="titular">
            <h2>Cómo es trabajar con nosotros.</h2>
            <p>Cuatro pasos, en este orden. El primero es el que nos permite hacer los demás.</p>
          </div>
          <ol className="pasos">
            {STEPS.map((s) => (
              <li key={s.name}>
                <h3>{s.name}</h3>
                <p>{s.note}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <Cierre next={{ href: "/preguntas", label: "Preguntas frecuentes" }} />
    </>
  );
}
