"use client";

import { usePathname } from "next/navigation";
import { useEffect } from "react";

/**
 * Coreografía de scroll: marca cada sección con data-in la primera vez que
 * entra en pantalla, en cada página. El CSS hace el resto (línea que se traza,
 * barra de sección y contenido escalonado). Sin JavaScript o con movimiento
 * reducido, todo el contenido está visible desde el inicio.
 */
export function Choreo() {
  const path = usePathname();
  useEffect(() => {
    const sections = document.querySelectorAll<HTMLElement>("[data-seccion]:not([data-in])");
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) {
      sections.forEach((s) => s.setAttribute("data-in", ""));
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.setAttribute("data-in", "");
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.05 },
    );
    sections.forEach((s) => observer.observe(s));
    return () => observer.disconnect();
  }, [path]);
  return null;
}

/** Barra fija de sección: número y nombre a la izquierda, rótulo a la derecha. */
export function Ceja({ n, name, side }: { n: string; name: string; side: string }) {
  return (
    <div className="ceja" aria-hidden="true">
      <div className="ancho">
        <span>
          <b>{n}</b> / {name}
        </span>
        <span>{side}</span>
      </div>
    </div>
  );
}
