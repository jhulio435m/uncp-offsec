import type { Metadata } from "next";
import { Cierre, PageHead } from "@/components/blocks";
import { AccessMatrix, CodeScan, PortGrid, WebMail } from "@/components/visuals";
import { SERVICES } from "@/content/site";

export const metadata: Metadata = {
  title: "Auditoría",
  description: "Auditoría de seguridad en cuatro frentes: web y correo, red e infraestructura, código y dependencias, y pentest manual.",
  alternates: { canonical: "/auditoria" },
};

const VISUAL: Record<string, React.ReactNode> = {
  "web-correo": <WebMail />,
  red: <PortGrid />,
  codigo: <CodeScan />,
  pentest: <AccessMatrix />,
};

export default function Page() {
  return (
    <>
      <PageHead n="01" name="Auditoría" side="Cuatro frentes" title="Cuatro frentes, un solo informe.">
        Puede pedir uno o todos. En cada uno le decimos qué revisamos y, al terminar, qué encontramos, con qué evidencia
        y qué corregir primero.
      </PageHead>

      {SERVICES.map((s, i) => (
        <section key={s.id} id={s.id} className="frente" data-seccion="">
          <div className="ancho frente-fila">
            <div>
              <p className="frente-n">
                {i + 1} / {SERVICES.length}
              </p>
              <h2>{s.name}</h2>
              <p className="frente-entrada">{s.lead}</p>
              <ul className="rayas">
                {s.checks.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
            {VISUAL[s.id]}
          </div>
        </section>
      ))}
      <p className="ancho aviso aviso-pagina">Los diagramas usan datos de ejemplo: los dominios y direcciones no existen.</p>

      <Cierre next={{ href: "/reglas", label: "Leer las reglas" }} />
    </>
  );
}
