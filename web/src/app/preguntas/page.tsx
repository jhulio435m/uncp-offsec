import type { Metadata } from "next";
import { Cierre, PageHead } from "@/components/blocks";
import { FAQ, SITE_URL } from "@/content/site";

export const metadata: Metadata = {
  title: "Preguntas",
  description: "Lo que conviene saber antes de autorizar una auditoría de seguridad: riesgos, requisitos, entregable y límites.",
  alternates: { canonical: "/preguntas" },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "@id": `${SITE_URL}/preguntas`,
  mainEntity: FAQ.map((f) => ({ "@type": "Question", name: f.q, acceptedAnswer: { "@type": "Answer", text: f.a } })),
};

export default function Page() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <PageHead n="01" name="Preguntas" side="Antes de autorizar" title="Lo que conviene saber antes de autorizar.">
        Las respuestas salen del alcance operativo de la plataforma, que es público.
      </PageHead>
      <section className="preguntas-seccion" data-seccion="">
        <div className="ancho preguntas">
          {FAQ.map((f) => (
            <details key={f.q} name="preguntas">
              <summary>{f.q}</summary>
              <p>{f.a}</p>
            </details>
          ))}
        </div>
      </section>
      <Cierre next={{ href: "/reglas", label: "Leer las reglas" }} />
    </>
  );
}
