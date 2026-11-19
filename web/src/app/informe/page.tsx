import type { Metadata } from "next";
import { Cierre, PageHead } from "@/components/blocks";
import { Ceja } from "@/components/choreo";
import { Findings } from "@/components/findings";
import { REPORT_PARTS } from "@/content/site";

export const metadata: Metadata = {
  title: "Informe",
  description: "Cómo es el informe de una auditoría: hallazgos con evidencia, severidad, estado de verificación, cobertura y confianza.",
  alternates: { canonical: "/informe" },
};

export default function Page() {
  return (
    <>
      <PageHead n="01" name="Informe" side="El entregable" title="Un hallazgo sin evidencia no es un hallazgo.">
        El informe separa lo confirmado de lo probable y de lo que todavía necesita a una persona. Una coincidencia con
        un CVE es motivo para revisar, no una afirmación de que es explotable.
      </PageHead>

      <section className="seccion" data-seccion="">
        <Ceja n="02" name="Hallazgos" side="Extracto ilustrativo" />
        <div className="ancho">
          <Findings />
        </div>
      </section>

      <section className="seccion" data-seccion="">
        <Ceja n="03" name="Medidas" side="Qué significa cada número" />
        <div className="ancho">
          <dl className="medidas">
            <div>
              <dt>Postura</dt>
              <dd>El nivel de riesgo que sale de la evidencia observada.</dd>
            </div>
            <div>
              <dt>Cobertura</dt>
              <dd>Cuánto de lo pedido se llegó a evaluar. Un módulo que no termina no cuenta como seguro.</dd>
            </div>
            <div>
              <dt>Confianza</dt>
              <dd>Qué tan sólida es la evidencia detrás de cada resultado.</dd>
            </div>
            <div>
              <dt>OWASP Top 10:2025</dt>
              <dd>Una matriz por categoría que dice qué quedó parcial, incompleto o sin evaluar. Nunca declara cobertura total.</dd>
            </div>
          </dl>
          <div className="titular contenido-informe">
            <h2>Qué trae.</h2>
            <ul className="rayas">
              {REPORT_PARTS.map((r) => (
                <li key={r}>{r}</li>
              ))}
              <li>Se entrega en HTML y en JSON</li>
            </ul>
          </div>
        </div>
      </section>

      <Cierre next={{ href: "/auditoria", label: "Ver qué auditamos" }} />
    </>
  );
}
