import Link from "next/link";
import { Ceja } from "./choreo";

/** Cabecera de una página interior: barra de sección, título y entrada. */
export function PageHead({ n, name, side, title, children }: { n: string; name: string; side: string; title: string; children: React.ReactNode }) {
  return (
    <section className="seccion pagina" data-seccion="">
      <Ceja n={n} name={name} side={side} />
      <div className="ancho titular">
        <h1 className="titulo-pagina">{title}</h1>
        <p>{children}</p>
      </div>
    </section>
  );
}

/** Cierre común: la acción de la web, con un enlace secundario a otra página. */
export function Cierre({ next }: { next?: { href: string; label: string } }) {
  return (
    <section className="cierre">
      <div className="ancho">
        <h2>¿Lo revisamos?</h2>
        <p className="acciones">
          <Link href="/solicitar" className="boton boton-rojo">
            Solicitar auditoría
          </Link>
          {next && (
            <Link href={next.href} className="boton boton-linea">
              {next.label}
            </Link>
          )}
        </p>
      </div>
    </section>
  );
}
