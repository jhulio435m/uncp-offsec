import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Página no encontrada", robots: { index: false, follow: true }, alternates: { canonical: null } };

export default function NotFound() {
  return (
    <div className="portada ancho">
      <h1>
        Aquí no hay <span className="marca-roja">nada</span>.
      </h1>
      <p className="entrada">La dirección no corresponde a ninguna página de Soryntel Security.</p>
      <p className="acciones">
        <Link href="/" className="boton boton-rojo">
          Volver al inicio
        </Link>
      </p>
    </div>
  );
}
