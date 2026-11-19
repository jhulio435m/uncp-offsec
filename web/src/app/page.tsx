import type { Metadata } from "next";
import Link from "next/link";
import { Cierre } from "@/components/blocks";
import { Ceja } from "@/components/choreo";
import { SurfaceMap } from "@/components/surface-map";
import { ScanLog } from "@/components/visuals";
import { CONTACT, DESCRIPTION, NEVER, RULE, SERVICES, SITE_URL } from "@/content/site";

export const metadata: Metadata = { alternates: { canonical: "/" } };

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": "https://soryntel.com/#organization",
      name: "Soryntel",
      url: "https://soryntel.com",
      email: CONTACT.email,
      telephone: CONTACT.phone,
      sameAs: [CONTACT.instagram, CONTACT.facebook, CONTACT.telegram],
    },
    {
      "@type": "WebSite",
      "@id": `${SITE_URL}/#website`,
      name: "Soryntel Security",
      url: `${SITE_URL}/`,
      description: DESCRIPTION,
      inLanguage: "es",
      publisher: { "@id": "https://soryntel.com/#organization" },
    },
    {
      "@type": "Service",
      "@id": `${SITE_URL}/#servicio`,
      name: "Auditoría de seguridad",
      serviceType: "Auditoría de ciberseguridad",
      description: DESCRIPTION,
      provider: { "@id": "https://soryntel.com/#organization" },
      areaServed: { "@type": "Country", name: "Perú" },
      url: `${SITE_URL}/auditoria`,
      hasOfferCatalog: {
        "@type": "OfferCatalog",
        name: "Auditorías",
        itemListElement: SERVICES.map((s) => ({ "@type": "Offer", itemOffered: { "@type": "Service", name: s.name, description: s.lead } })),
      },
    },
  ],
};

export default function Page() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />

      <section className="portada">
        <div className="ancho portada-cuerpo">
          <h1>
            Lo encontramos <br />
            antes que <span className="marca-roja">ellos</span>.
          </h1>
          <div className="portada-fila">
            <div>
              <p className="entrada">
                Auditoría de seguridad para su empresa y la plataforma con la que la hacemos, abierta para que su equipo
                también la use.
              </p>
              <p className="acciones">
                <Link href="/solicitar" className="boton boton-rojo">
                  Solicitar auditoría
                </Link>
                <Link href="/plataforma" className="boton boton-linea">
                  Ver la plataforma
                </Link>
              </p>
            </div>
            <SurfaceMap />
          </div>
        </div>
        <ul className="banda" aria-label="Qué auditamos y con qué regla">
          {SERVICES.map((s) => (
            <li key={s.id}>
              <Link href={`/auditoria#${s.id}`}>{s.name}</Link>
            </li>
          ))}
          <li className="banda-regla">
            <Link href="/reglas">{RULE}</Link>
          </li>
        </ul>
      </section>

      <section className="seccion" data-seccion="">
        <Ceja n="01" name="Evaluación" side="Registro de ejemplo" />
        <div className="ancho">
          <div className="titular">
            <h2>Vea lo que ve un atacante.</h2>
            <p>
              Recorremos lo que su empresa expone, anotamos cada señal y la marcamos según lo que se pudo comprobar. Así
              se lee una evaluación mientras corre.
            </p>
          </div>
          <ScanLog />
        </div>
      </section>

      <section className="seccion" data-seccion="">
        <Ceja n="02" name="Auditoría" side="Cuatro frentes" />
        <div className="ancho">
          <div className="titular">
            <h2>Cuatro frentes, un solo informe.</h2>
            <p>Puede pedir uno o todos. Cada uno tiene su página con lo que se revisa y cómo se ve.</p>
          </div>
          <ul className="indice">
            {SERVICES.map((s) => (
              <li key={s.id}>
                <Link href={`/auditoria#${s.id}`}>
                  <h3>{s.name}</h3>
                  <p>{s.lead}</p>
                  <span aria-hidden="true">→</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="nunca" data-seccion="" aria-labelledby="nunca-titulo">
        <h2 id="nunca-titulo" className="ancho">
          La plataforma nunca
        </h2>
        <ul>
          {NEVER.slice(0, 4).map((n) => (
            <li key={n}>
              <span className="ancho">{n}</span>
            </li>
          ))}
        </ul>
        <p className="ancho excepcion">
          Son cuatro de las siete reglas que la plataforma no rompe. <Link href="/reglas">Léalas todas</Link>.
        </p>
      </section>

      <Cierre next={{ href: "/informe", label: "Ver cómo es el informe" }} />
    </>
  );
}
