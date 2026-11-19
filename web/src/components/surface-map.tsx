"use client";

import { useState } from "react";

type Estado = "validado" | "hallazgo" | "potencial" | "manual";

// Superficie de ejemplo: un dominio y los activos que cuelgan de él.
const NODES: { id: string; x: number; y: number; estado: Estado; note: string }[] = [
  { id: "www", x: 250, y: 36, estado: "hallazgo", note: "Listado de directorio habilitado · alta · validado" },
  { id: "correo", x: 250, y: 120, estado: "validado", note: "DMARC con política p=none · media · validado" },
  { id: "api", x: 250, y: 204, estado: "manual", note: "Control de acceso entre cuentas · revisión manual" },
  { id: "tienda", x: 450, y: 36, estado: "potencial", note: "Versión con CVE en CISA KEV · alta · potencial" },
  { id: "vpn", x: 450, y: 120, estado: "validado", note: "Sin hallazgos en lo evaluado" },
  { id: "bd", x: 450, y: 204, estado: "hallazgo", note: "Base de datos accesible desde Internet · media · validado" },
];

const ROOT = { x: 44, y: 120 };
const CYCLE = 12; // segundos
const DEFAULT = "Ejemplo ilustrativo: un dominio, sus activos y cómo queda marcado cada uno.";

/** Momento del ciclo en que la línea de barrido pasa por x. */
const at = (x: number) => CYCLE * (0.14 + (0.3 * x) / 600);

/**
 * Ilustración animada de la portada: se trazan las conexiones, una línea barre
 * la superficie y cada activo queda marcado con su estado. Al pasar el cursor
 * o el foco por un activo, el pie dice qué se encontró.
 */
export function SurfaceMap() {
  const [active, setActive] = useState<string | null>(null);
  const current = NODES.find((n) => n.id === active);

  return (
    <figure className="mapa">
      <svg viewBox="0 0 600 240" role="group" aria-label="Mapa de ejemplo de una superficie evaluada">
        {/* Conexiones en codo desde el dominio hasta cada activo. */}
        {NODES.map((n, i) => {
          const from = n.x === 250 ? ROOT.x : 250;
          const mid = from + (n.x - from) / 2;
          const y0 = n.x === 250 ? ROOT.y : n.y;
          return (
            <path
              key={n.id}
              className="mapa-linea"
              d={`M${from + 7} ${y0} H${mid} V${n.y} H${n.x - 7}`}
              pathLength={1}
              style={{ animationDelay: `${i * 0.12}s` }}
              data-on={active === n.id || undefined}
            />
          );
        })}

        <line className="mapa-barrido" x1="0" y1="8" x2="0" y2="232" />

        <g className="mapa-raiz">
          <rect x={ROOT.x - 9} y={ROOT.y - 9} width="18" height="18" />
          <text x={ROOT.x - 9} y={ROOT.y + 30}>
            empresa.pe
          </text>
        </g>

        {NODES.map((n) => (
          <g
            key={n.id}
            className="mapa-nodo"
            data-estado={n.estado}
            data-on={active === n.id || undefined}
            tabIndex={0}
            role="img"
            aria-label={`${n.id}: ${n.note}`}
            onPointerEnter={() => setActive(n.id)}
            onPointerLeave={() => setActive(null)}
            onFocus={() => setActive(n.id)}
            onBlur={() => setActive(null)}
          >
            <rect className="mapa-zona" x={n.x - 22} y={n.y - 30} width="110" height="52" />
            <rect className="mapa-base" x={n.x - 7} y={n.y - 7} width="14" height="14" />
            <g className="mapa-marca" style={{ animationDelay: `${at(n.x).toFixed(2)}s` }}>
              {n.estado === "manual" ? <rect x={n.x - 7} y={n.y + 4} width="14" height="3" /> : <rect x={n.x - 7} y={n.y - 7} width="14" height="14" />}
              {n.estado === "hallazgo" && <rect className="mapa-aro" x={n.x - 13} y={n.y - 13} width="26" height="26" />}
            </g>
            <text x={n.x + 14} y={n.y - 12}>
              {n.id}
            </text>
          </g>
        ))}
      </svg>
      <figcaption aria-live="polite">{current ? `${current.id} · ${current.note}` : DEFAULT}</figcaption>
    </figure>
  );
}
