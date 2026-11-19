import type { Metadata } from "next";
import { Ceja } from "@/components/choreo";
import { RequestForm } from "@/components/request-form";
import { CONTACT } from "@/content/site";

export const metadata: Metadata = {
  title: "Solicitar auditoría",
  description: "Solicite una evaluación de seguridad a Soryntel. Le respondemos para acordar el alcance.",
  alternates: { canonical: "/solicitar" },
};

export default function Page() {
  return (
    <section className="seccion pagina" data-seccion="">
      <Ceja n="01" name="Solicitar" side="Le respondemos por correo" />
      <div className="ancho solicitar">
        <div>
          <h1 className="titulo-pagina">Solicite su evaluación.</h1>
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
  );
}
