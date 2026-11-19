import { Ceja, Choreo } from "@/components/choreo";
import { Findings } from "@/components/findings";
import { RequestForm } from "@/components/request-form";
import { SurfaceMap } from "@/components/surface-map";
import {
  CONTACT,
  DESCRIPTION,
  DOES,
  FAQ,
  NEVER,
  PLATFORM,
  PLATFORM_VERSION,
  REPORT_PARTS,
  REPO_URL,
  RULE,
  RUN,
  SERVICES,
  SITE_URL,
  STEPS,
} from "@/content/site";

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
      url: `${SITE_URL}/`,
      hasOfferCatalog: {
        "@type": "OfferCatalog",
        name: "Auditorías",
        itemListElement: SERVICES.map((s) => ({ "@type": "Offer", itemOffered: { "@type": "Service", name: s.name, description: s.lead } })),
      },
    },
    {
      "@type": "SoftwareApplication",
      "@id": `${SITE_URL}/#plataforma`,
      name: "Soryntel Security (plataforma de evaluación)",
      applicationCategory: "SecurityApplication",
      softwareVersion: PLATFORM_VERSION,
      url: `${SITE_URL}/#plataforma`,
      publisher: { "@id": "https://soryntel.com/#organization" },
    },
    {
      "@type": "FAQPage",
      "@id": `${SITE_URL}/#preguntas`,
      mainEntity: FAQ.map((f) => ({ "@type": "Question", name: f.q, acceptedAnswer: { "@type": "Answer", text: f.a } })),
    },
  ],
};

export default function Page() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <Choreo />
      <a href="#contenido" className="saltar">
        Saltar al contenido
      </a>

      <header className="cabecera">
        <div className="ancho cabecera-fila">
          <a href="#inicio" className="marca">
            Soryntel <b>Security</b>
          </a>
          <nav aria-label="Navegación principal">
            <a href="#auditoria">Auditoría</a>
            <a href="#reglas">Reglas</a>
            <a href="#informe">Informe</a>
            <a href="#plataforma">Plataforma</a>
            <a href="#preguntas">Preguntas</a>
          </nav>
          <a href="#solicitar" className="boton boton-chico boton-rojo">
            Solicitar
          </a>
        </div>
      </header>

      <main id="contenido">
        <section id="inicio" className="portada">
          <div className="ancho portada-cuerpo">
            <h1>
              Lo encontramos <br />
              antes que <span className="marca-roja">ellos</span>.
            </h1>
            <div className="portada-fila">
              <div>
                <p className="entrada">
                  Auditoría de seguridad para su empresa y la plataforma con la que la hacemos, abierta para que su
                  equipo también la use.
                </p>
                <p className="acciones">
                  <a href="#plataforma" className="boton boton-rojo">
                    Ver la plataforma
                  </a>
                  <a href="#solicitar" className="boton boton-linea">
                    Solicitar auditoría
                  </a>
                </p>
              </div>
              <SurfaceMap />
            </div>
          </div>
          <ul className="banda" aria-label="Qué auditamos y con qué regla">
            {SERVICES.map((s) => (
              <li key={s.id}>
                <a href={`#${s.id}`}>{s.name}</a>
              </li>
            ))}
            <li className="banda-regla">
              <a href="#reglas">{RULE}</a>
            </li>
          </ul>
        </section>

        <section id="auditoria" className="seccion" data-seccion="">
          <Ceja n="01" name="Auditoría" side="Cuatro frentes" />
          <div className="ancho">
            <div className="titular">
              <h2>Cuatro frentes, un solo informe.</h2>
              <p>
                Puede pedir uno o todos. En cada uno le decimos qué revisamos y, al terminar, qué encontramos, con qué
                evidencia y qué corregir primero.
              </p>
            </div>
            <ul className="frentes">
              {SERVICES.map((s) => (
                <li key={s.id} id={s.id}>
                  <h3>{s.name}</h3>
                  <p>{s.lead}</p>
                  <ul>
                    {s.checks.map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="reglas" className="seccion seccion-clara" data-seccion="">
          <Ceja n="02" name="Reglas" side="Alcance por escrito" />
          <div className="ancho">
            <div className="titular">
              <h2>Las reglas van por escrito.</h2>
              <p>
                Nada se evalúa sin autorización y sin un alcance firmado. La plataforma tiene un límite fijo: valida,
                identifica y reporta. Esto es lo que hace; debajo, lo que no hace nunca.
              </p>
            </div>
            <ul className="hace">
              {DOES.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </div>
        </section>

        <section className="nunca" aria-labelledby="nunca-titulo" data-seccion="">
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

        <section id="informe" className="seccion" data-seccion="">
          <Ceja n="03" name="Informe" side="Extracto ilustrativo" />
          <div className="ancho">
            <div className="titular">
              <h2>Un hallazgo sin evidencia no es un hallazgo.</h2>
              <p>
                El informe separa lo confirmado de lo probable y de lo que todavía necesita a una persona. Una
                coincidencia con un CVE es motivo para revisar, no una afirmación de que es explotable.
              </p>
            </div>
            <Findings />
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

            <div className="entregable">
              <div>
                <h3>Así sale el informe.</h3>
                <p>
                  Esta es una captura del informe HTML que genera la plataforma. Baje por la página y
                  recórralo.
                </p>
                <ul>
                  {REPORT_PARTS.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
                <p className="aviso">
                  Generado con datos de ejemplo: el dominio <code>empresa.example</code> y sus direcciones no existen.
                </p>
              </div>
              <figure className="ventana" tabIndex={0} aria-label="Informe de ejemplo generado por la plataforma. Se puede desplazar.">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src="/media/informe-ejemplo.webp"
                  width="980"
                  height="2503"
                  loading="lazy"
                  alt="Informe de la plataforma: puntaje de postura 61 de 100, seis señales accionables, hallazgos de correo y web con su estado de verificación, inventario de activos y matriz OWASP Top 10:2025."
                />
              </figure>
            </div>
          </div>
        </section>

        <section id="proceso" className="seccion seccion-linea" data-seccion="">
          <Ceja n="04" name="Proceso" side="Cuatro pasos" />
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

        <section id="plataforma" className="seccion seccion-clara" data-seccion="">
          <Ceja n="05" name="Plataforma" side={`Versión ${PLATFORM_VERSION}`} />
          <div className="ancho">
            <div className="titular">
              <h2>La misma herramienta, en manos de su equipo.</h2>
              <p>
                Si ya tiene equipo de seguridad, use la plataforma con la que auditamos. El código es público: puede
                leer exactamente qué hace cada módulo antes de apuntarlo a nada.
              </p>
            </div>
            <ul className="capacidades">
              {PLATFORM.map((p) => (
                <li key={p.name}>
                  <h3>{p.name}</h3>
                  <p>{p.note}</p>
                </li>
              ))}
            </ul>
            <div className="arranque">
              <div>
                <h3>Pruébela en su equipo.</h3>
                <p>
                  Con Docker tiene el entorno completo en una orden. Apúntela solo a activos que esté autorizado a
                  evaluar: los módulos activos exigen un archivo de alcance.
                </p>
              </div>
              <pre className="consola" tabIndex={0} aria-label="Comandos para ejecutar la plataforma">
                <code>
                  {RUN.map(([cmd, note]) => (
                    <span key={cmd} className="consola-linea">
                      <span>{cmd}</span>
                      {note && <i># {note}</i>}
                    </span>
                  ))}
                </code>
              </pre>
            </div>
            <div className="plataforma-pie">
              <a href={REPO_URL} className="boton boton-negro">
                Ver el código en GitHub
              </a>
              <p>
                Versión {PLATFORM_VERSION}. Se ejecuta en contenedor o con Python. La seguimos ampliando;{" "}
                <a href="#solicitar">cuéntenos qué necesita su equipo</a>.
              </p>
            </div>
          </div>
        </section>

        <section id="preguntas" className="seccion" data-seccion="">
          <Ceja n="06" name="Preguntas" side="Antes de autorizar" />
          <div className="ancho">
            <div className="titular">
              <h2>Lo que conviene saber antes de autorizar.</h2>
              <p>Las respuestas salen del alcance operativo de la plataforma, que es público.</p>
            </div>
            <div className="preguntas">
              {FAQ.map((f) => (
                <details key={f.q} name="preguntas">
                  <summary>{f.q}</summary>
                  <p>{f.a}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section id="solicitar" className="seccion" data-seccion="">
          <Ceja n="07" name="Solicitar" side="Le respondemos por correo" />
          <div className="ancho solicitar">
            <div>
              <h2>Solicite su evaluación.</h2>
              <p>
                Cuéntenos qué quiere revisar. Le respondemos para acordar el alcance; no tocamos nada antes de tener su
                autorización por escrito.
              </p>
              <ul className="contacto">
                <li>
                  <span>Correo</span>
                  <a href={`mailto:${CONTACT.email}`}>{CONTACT.email}</a>
                </li>
                <li>
                  <span>WhatsApp</span>
                  <a href={CONTACT.whatsapp}>{CONTACT.phone}</a>
                </li>
                <li>
                  <span>Telegram</span>
                  <a href={CONTACT.telegram}>@Soryntel</a>
                </li>
              </ul>
            </div>
            <RequestForm />
          </div>
        </section>
      </main>

      <footer className="pie">
        <div className="ancho pie-fila">
          <a href={CONTACT.home} className="pie-soryntel">
            Un producto de
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/brand/soryntel.svg" alt="Soryntel" width="96" height="40" />
          </a>
          <nav aria-label="Enlaces del pie">
            <a href={REPO_URL}>GitHub</a>
            <a href={CONTACT.instagram}>Instagram</a>
            <a href={CONTACT.facebook}>Facebook</a>
            <a href={CONTACT.complaints}>Libro de reclamaciones</a>
          </nav>
          <p>© 2026 Soryntel</p>
        </div>
      </footer>
    </>
  );
}
