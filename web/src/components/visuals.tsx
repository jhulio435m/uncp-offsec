// Diagramas de la web: muestran qué mira cada frente de auditoría.
// Todos usan datos de ejemplo (dominios .example, IP de documentación) y se
// animan solo con CSS; con movimiento reducido quedan en su estado final.

type Mark = "ok" | "falla" | "duda";

function Cuadro({ mark }: { mark: Mark }) {
  return <i className="vz-cuadro" data-mark={mark} aria-hidden="true" />;
}

const LABEL: Record<Mark, string> = { ok: "correcto", falla: "hallazgo", duda: "por revisar" };

/** Registro de una evaluación: lo que la plataforma va anotando mientras corre. */
const LOG: { mod: string; text: string; mark?: Mark }[] = [
  { mod: "alcance", text: "empresa.example autorizado · perfil completo" },
  { mod: "dns", text: "4 subdominios · 3 responden por HTTPS" },
  { mod: "tls", text: "www · TLS 1.2 y 1.3 · certificado vigente", mark: "ok" },
  { mod: "cabeceras", text: "tienda · falta Content-Security-Policy", mark: "falla" },
  { mod: "cve", text: "tienda · Apache 2.4.49 coincide con CVE-2021-41773 (KEV)", mark: "duda" },
  { mod: "puertos", text: "192.0.2.14 · 3306/tcp mysql accesible desde Internet", mark: "falla" },
  { mod: "correo", text: "SPF correcto · DKIM correcto · DMARC p=none", mark: "falla" },
  { mod: "acceso", text: "api · control entre cuentas: requiere revisión manual", mark: "duda" },
  { mod: "informe", text: "6 señales accionables · cobertura 84 %" },
];

export function ScanLog() {
  return (
    <figure className="vz vz-log">
      <ol>
        {LOG.map((l, i) => (
          <li key={i} style={{ "--n": i } as React.CSSProperties}>
            <span className="vz-mod">{l.mod}</span>
            <span>{l.text}</span>
            {l.mark ? (
              <span className="vz-estado" data-mark={l.mark}>
                <Cuadro mark={l.mark} />
                {LABEL[l.mark]}
              </span>
            ) : (
              <span />
            )}
          </li>
        ))}
      </ol>
      <figcaption>Registro de ejemplo. El dominio y las direcciones no existen.</figcaption>
    </figure>
  );
}

/** Web y correo: cabeceras de respuesta y cadena de autenticación del correo. */
const HEADERS: [string, Mark][] = [
  ["Strict-Transport-Security", "ok"],
  ["Content-Security-Policy", "falla"],
  ["X-Content-Type-Options", "ok"],
  ["X-Frame-Options", "ok"],
  ["Set-Cookie · Secure, HttpOnly", "duda"],
];
const MAIL: [string, string, Mark][] = [
  ["SPF", "-all", "ok"],
  ["DKIM", "firma válida", "ok"],
  ["DMARC", "p=none", "falla"],
  ["MTA-STS", "sin política", "duda"],
];

export function WebMail() {
  return (
    <figure className="vz vz-webmail">
      <div>
        <p className="vz-titulo">GET https://tienda.empresa.example</p>
        <ul className="vz-lista">
          {HEADERS.map(([name, mark], i) => (
            <li key={name} style={{ "--n": i } as React.CSSProperties}>
              <Cuadro mark={mark} />
              <span>{name}</span>
              <em>{LABEL[mark]}</em>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <p className="vz-titulo">correo de empresa.example</p>
        <ol className="vz-cadena">
          {MAIL.map(([name, value, mark], i) => (
            <li key={name} data-mark={mark} style={{ "--n": i + 5 } as React.CSSProperties}>
              <b>{name}</b>
              <span>{value}</span>
            </li>
          ))}
        </ol>
      </div>
    </figure>
  );
}

/** Red: rejilla de puertos barrida de izquierda a derecha; quedan marcados los abiertos. */
const OPEN: Record<number, [string, Mark]> = { 9: ["22 ssh", "ok"], 27: ["80 http", "ok"], 44: ["443 https", "ok"], 70: ["3306 mysql", "falla"], 88: ["8080 http-alt", "duda"] };
const COLS = 24;

export function PortGrid() {
  return (
    <figure className="vz vz-puertos">
      <p className="vz-titulo">192.0.2.14 · puertos TCP</p>
      <div className="vz-rejilla" aria-hidden="true">
        {Array.from({ length: COLS * 4 }, (_, i) => (
          <i key={i} data-mark={OPEN[i]?.[1]} style={{ "--c": i % COLS } as React.CSSProperties} />
        ))}
      </div>
      <ul className="vz-lista vz-lista-fila">
        {Object.values(OPEN).map(([name, mark]) => (
          <li key={name}>
            <Cuadro mark={mark} />
            <span>{name}</span>
            <em>{mark === "ok" ? "esperado" : mark === "falla" ? "expuesto" : "por revisar"}</em>
          </li>
        ))}
      </ul>
    </figure>
  );
}

/** Código: un archivo con una línea señalada y sus dependencias. */
const CODE = [62, 40, 78, 54, 88, 46, 70, 30, 58];
const DEPS: [string, string, Mark][] = [
  ["django", "4.2.11", "ok"],
  ["requests", "2.19.0", "falla"],
  ["pyyaml", "5.3", "duda"],
  ["cryptography", "42.0.5", "ok"],
];

export function CodeScan() {
  return (
    <figure className="vz vz-codigo">
      <div>
        <p className="vz-titulo">app/consultas.py</p>
        <ol className="vz-lineas" aria-hidden="true">
          {CODE.map((w, i) => (
            <li key={i} data-flag={i === 4 || undefined} style={{ "--w": `${w}%`, "--n": i } as React.CSSProperties} />
          ))}
        </ol>
        <p className="vz-nota">línea 41 · consulta SQL armada con texto del usuario</p>
      </div>
      <div>
        <p className="vz-titulo">dependencias</p>
        <ul className="vz-lista">
          {DEPS.map(([name, version, mark], i) => (
            <li key={name} style={{ "--n": i + 4 } as React.CSSProperties}>
              <Cuadro mark={mark} />
              <span>
                {name} <small>{version}</small>
              </span>
              <em>{mark === "ok" ? "al día" : mark === "falla" ? "vulnerable" : "por revisar"}</em>
            </li>
          ))}
        </ul>
      </div>
    </figure>
  );
}

/** Pentest manual: quién puede leer qué. La celda roja es lo que una persona confirma. */
const RES = ["pedido A", "pedido B", "factura A", "factura B", "panel"];
const WHO: [string, Mark[]][] = [
  ["cuenta A", ["ok", "duda", "ok", "duda", "duda"]],
  ["cuenta B", ["falla", "ok", "duda", "ok", "duda"]],
  ["sin sesión", ["duda", "duda", "duda", "duda", "duda"]],
];

export function AccessMatrix() {
  return (
    <figure className="vz vz-acceso">
      <p className="vz-titulo">quién puede leer qué</p>
      <table>
        <thead>
          <tr>
            <td />
            {RES.map((r) => (
              <th key={r} scope="col">
                {r}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {WHO.map(([who, cells], r) => (
            <tr key={who}>
              <th scope="row">{who}</th>
              {cells.map((m, c) => (
                <td key={c} style={{ "--n": r * 5 + c } as React.CSSProperties}>
                  <i className="vz-cuadro" data-mark={m === "duda" ? "no" : m} aria-label={m === "ok" ? "acceso propio" : m === "falla" ? "acceso indebido" : "denegado"} role="img" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="vz-nota">la cuenta B lee un pedido de la cuenta A</p>
    </figure>
  );
}
