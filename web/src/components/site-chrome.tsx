"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export const ROUTES = [
  { href: "/auditoria", label: "Auditoría" },
  { href: "/reglas", label: "Reglas" },
  { href: "/informe", label: "Informe" },
  { href: "/plataforma", label: "Plataforma" },
  { href: "/preguntas", label: "Preguntas" },
];

export function Header() {
  const path = usePathname().replace(/\/$/, "") || "/";
  return (
    <header className="cabecera">
      <div className="ancho cabecera-fila">
        <Link href="/" className="marca">
          Soryntel <b>Security</b>
        </Link>
        <nav aria-label="Navegación principal">
          {ROUTES.map((r) => (
            <Link key={r.href} href={r.href} aria-current={path === r.href ? "page" : undefined}>
              {r.label}
            </Link>
          ))}
        </nav>
        <Link href="/solicitar" className="boton boton-chico boton-rojo" aria-current={path === "/solicitar" ? "page" : undefined}>
          Solicitar
        </Link>
      </div>
    </header>
  );
}
