"use client";

import { useState } from "react";
import { ESTADOS, FINDINGS, type Estado } from "@/content/site";

const FILTERS: (Estado | "todos")[] = ["todos", "validado", "potencial", "manual"];

/** Extracto de informe: filtra por estado de verificación y abre la evidencia de cada hallazgo. */
export function Findings() {
  const [filter, setFilter] = useState<Estado | "todos">("todos");
  const [open, setOpen] = useState<number | null>(0);
  const rows = FINDINGS.map((f, i) => ({ ...f, i })).filter((f) => filter === "todos" || f.estado === filter);

  return (
    <div className="hallazgos">
      <div className="filtros" role="group" aria-label="Filtrar por estado de verificación">
        {FILTERS.map((f) => (
          <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}>
            {f === "todos" ? "Todos" : ESTADOS[f].label}
            <span>{f === "todos" ? FINDINGS.length : FINDINGS.filter((x) => x.estado === f).length}</span>
          </button>
        ))}
      </div>
      <p className="filtro-nota" aria-live="polite">
        {filter === "todos" ? "Cada hallazgo declara cómo se verificó. Abra uno para ver su evidencia." : ESTADOS[filter].note}
      </p>

      <ul className="tabla">
        <li className="tabla-cabeza" aria-hidden="true">
          <span>Área</span>
          <span>Hallazgo</span>
          <span>Severidad</span>
          <span>Estado</span>
        </li>
        {rows.map((f) => {
          const isOpen = open === f.i;
          return (
            <li key={f.i} data-open={isOpen || undefined}>
              <button type="button" className="fila" aria-expanded={isOpen} aria-controls={`h-${f.i}`} onClick={() => setOpen(isOpen ? null : f.i)}>
                <span className="dato">{f.area}</span>
                <span className="fila-titulo">{f.title}</span>
                <span className="dato" data-sev={f.severity}>
                  {f.severity}
                </span>
                <span className="dato" data-estado={f.estado}>
                  {ESTADOS[f.estado].label}
                </span>
              </button>
              <div className="detalle" id={`h-${f.i}`} hidden={!isOpen}>
                <dl>
                  <div>
                    <dt>Evidencia</dt>
                    <dd>{f.evidence}</dd>
                  </div>
                  <div>
                    <dt>Qué hacer</dt>
                    <dd>{f.fix}</dd>
                  </div>
                  <div>
                    <dt>Estado en el informe</dt>
                    <dd>
                      <code>{ESTADOS[f.estado].code}</code>
                    </dd>
                  </div>
                </dl>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="aviso">Extracto ilustrativo. Muestra la forma del informe; no corresponde a ningún cliente.</p>
    </div>
  );
}
