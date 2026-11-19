import type { Metadata } from "next";
import { Cierre, PageHead } from "@/components/blocks";
import { Ceja } from "@/components/choreo";
import { ScanLog } from "@/components/visuals";
import { PLATFORM, PLATFORM_VERSION, REPO_URL } from "@/content/site";

export const metadata: Metadata = {
  title: "Plataforma",
  description: "La plataforma de evaluación con la que Soryntel audita, de código público, para equipos de ciberseguridad.",
  alternates: { canonical: "/plataforma" },
};

export default function Page() {
  return (
    <>
      <PageHead n="01" name="Plataforma" side={`Versión ${PLATFORM_VERSION}`} title="La misma herramienta, en manos de su equipo.">
        Si ya tiene equipo de seguridad, use la plataforma con la que auditamos. El código es público: puede leer
        exactamente qué hace cada módulo antes de apuntarlo a nada.
      </PageHead>

      <section className="seccion" data-seccion="">
        <Ceja n="02" name="En marcha" side="Registro de ejemplo" />
        <div className="ancho">
          <ScanLog />
        </div>
      </section>

      <section className="seccion seccion-clara" data-seccion="">
        <Ceja n="03" name="Capacidades" side="Para quien la opera" />
        <div className="ancho">
          <ul className="capacidades">
            {PLATFORM.map((p) => (
              <li key={p.name}>
                <h3>{p.name}</h3>
                <p>{p.note}</p>
              </li>
            ))}
          </ul>
          <div className="plataforma-pie">
            <a href={REPO_URL} className="boton boton-negro">
              Ver el código en GitHub
            </a>
            <p>Versión {PLATFORM_VERSION}. La seguimos ampliando; cuéntenos qué necesita su equipo.</p>
          </div>
        </div>
      </section>

      <Cierre next={{ href: "/reglas", label: "Leer las reglas" }} />
    </>
  );
}
