"""Informe HTML autónomo de la evaluación combinada (correo + web).

La interfaz del informe está en español. Los títulos y el detalle de cada
hallazgo los escribe el módulo que lo produjo.
"""

from __future__ import annotations

import html as html_mod
import re
from pathlib import Path
from typing import Any

# Clase visual por severidad y por nivel de riesgo (ver el CSS del informe).
_SEV_COLORS = {
    "CRITICAL": "critica",
    "HIGH": "alta",
    "MEDIUM": "media",
    "LOW": "baja",
    "INFO": "info",
    "PASS": "ok",
}

_RISK_COLORS = {
    "INCONCLUSIVE": "info",
    "CRITICAL": "critica",
    "HIGH": "alta",
    "MEDIUM": "media",
    "LOW": "baja",
    "GOOD": "ok",
}

_SEV_ES = {
    "CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja",
    "INFO": "Informativa", "PASS": "Correcto",
    "INCOMPLETE": "Incompleto", "NO CANDIDATES": "Sin candidatos",
}

_RISK_ES = {
    "INCONCLUSIVE": "No concluyente", "CRITICAL": "Crítico", "HIGH": "Alto",
    "MEDIUM": "Medio", "LOW": "Bajo", "GOOD": "Bueno", "UNKNOWN": "Desconocido",
}

# Estado de verificación: se muestra en español junto al código que usa el JSON.
_STATUS_ES = {
    "VALIDATED_NON_DESTRUCTIVE": "Validado",
    "CONFIRMED": "Confirmado",
    "POTENTIAL": "Potencial",
    "OBSERVED": "Observado",
    "STATIC_SIGNAL": "Señal estática",
    "VERSION_CORRELATED": "Versión correlacionada",
    "TOOL_INCOMPLETE": "Herramienta incompleta",
    "NO_CANDIDATES": "Sin candidatos",
    "MANUAL_REQUIRED": "Revisión manual",
    "PARTIAL": "Parcial",
    "INCOMPLETE": "Incompleto",
    "NOT_ASSESSED": "Sin evaluar",
}

_CONFIDENCE_ES = {"HIGH": "alta", "MEDIUM": "media", "LOW": "baja", "UNSPECIFIED": "sin especificar"}

_MODE_ES = {
    "identification-only": "solo identificación",
    "active-validation": "validación activa",
    "exact-host": "host exacto",
    "domain-discovery": "descubrimiento por dominio",
}


def _status(value: Any) -> str:
    """Estado en español seguido de su código, p. ej. «Validado (VALIDATED_NON_DESTRUCTIVE)»."""
    code = str(value or "OBSERVED").upper()
    label = _STATUS_ES.get(code)
    return f"{_esc(label)} ({_esc(code)})" if label else _esc(code)

_EMAIL_LABELS = {
    "mx": "MX",
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "smtp": "SMTP",
    "starttls": "STARTTLS",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "dane": "DANE",
    "relay": "Relay abierto",
}

# Nombre visible de los módulos web; los que no están aquí se muestran tal cual.
_WEB_LABELS = {
    "discovery": "Descubrimiento de subdominios",
    "subdomains": "Descubrimiento de subdominios",
    "crawl": "Rastreo",
    "content_discovery": "Descubrimiento de contenido",
    "dns_inventory": "Inventario DNS",
    "probe": "Sondeo HTTP",
    "tech": "Tecnologías",
    "headers": "Cabeceras de seguridad",
    "tls": "TLS",
    "ports": "Puertos",
    "nmap": "Nmap",
    "content": "Descubrimiento de contenido",
    "nuclei": "Nuclei",
    "vulns": "Nuclei",
    "cve": "CVE por versión",
    "cves": "CVE por versión",
    "sqli": "Inyección SQL",
    "dast": "DAST (OWASP ZAP)",
    "zap": "DAST (OWASP ZAP)",
    "anonymous": "Acceso anónimo",
    "correlation": "Correlación de evidencia",
    "sast": "Código (SAST)",
    "sca": "Dependencias (SCA)",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _esc(s: Any) -> str:
    return html_mod.escape(_ANSI_RE.sub("", str(s)), quote=True)


def _badge(sev: str) -> str:
    key = str(sev).upper()
    return f'<span class="badge {_SEV_COLORS.get(key, "info")}">{_esc(_SEV_ES.get(key, sev))}</span>'


def _worst(module: dict) -> str:
    worst = "INFO"
    for f in module.get("findings", []):
        sev = str(f.get("severity", "INFO")).upper()
        if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(worst, 5):
            worst = sev
    return worst


def _module_status(module: dict) -> tuple[str, str]:
    if any(
        str(finding.get("verification_status", "")).upper() == "NO_CANDIDATES"
        for finding in module.get("findings", [])
    ):
        return "NO CANDIDATES", "info"
    incomplete = any(
        str(finding.get("verification_status", "")).upper() == "TOOL_INCOMPLETE"
        for finding in module.get("findings", [])
    )
    if module.get("assessed") is False or incomplete:
        return "INCOMPLETE", "info"
    severity = _worst(module)
    return severity, _SEV_COLORS.get(severity, "info")


def _detail(value: Any) -> str:
    text = str(value or "")
    escaped = _esc(text)
    if len(text) <= 600:
        return f'<div class="detail">{escaped}</div>'
    return (
        '<details class="evidence"><summary>Ver la evidencia completa '
        f'({len(text.splitlines())} líneas)</summary><div class="detail">{escaped}</div></details>'
    )


def _phase_section(phase: dict, title: str, labels: dict) -> str:
    if not phase:
        return ""
    modules = phase.get("modules", [])
    risk = phase.get("risk", {})
    categories = (risk.get("categories") or [])[:-1]
    total = phase.get("total_score", 0)
    coverage = phase.get("coverage_score")
    confidence = phase.get("confidence")
    coverage_text = (
        f" &middot; módulos completados {float(coverage):.0f}%"
        + (f" &middot; confianza {_esc(_CONFIDENCE_ES.get(str(confidence).upper(), confidence))}" if confidence else "")
        if coverage is not None
        else ""
    )

    summary_rows = ""
    for m in modules:
        name = labels.get(m.get("name", ""), m.get("name", ""))
        status, color = _module_status(m)
        summary_rows += (
            f'<tr><td><b>{_esc(name)}</b></td>'
            f'<td><span class="badge {color}">{_esc(_SEV_ES.get(status, status))}</span></td></tr>'
        )

    score_rows = ""
    for c in categories:
        name = c.get("name", "")
        score = float(c.get("score", 0))
        maxv = float(c.get("max", 0))
        pct = (score / maxv * 100) if maxv else 0
        bar_color = "#ffffff" if pct >= 75 else ("#a3a8b3" if pct >= 45 else "#e11d2e")
        score_rows += (
            f'<tr><td>{_esc(name)}</td>'
            f'<td style="width:45%"><div class="bar-outer">'
            f'<div class="bar-inner" style="width:{pct:.0f}%;background:{bar_color}"></div>'
            f'</div></td>'
            f'<td style="text-align:right"><b>{score:.1f}</b> / {maxv:.0f}</td></tr>'
        )

    detail_rows = ""
    for m in modules:
        findings = m.get("findings", [])
        if not findings:
            continue
        detail_rows += (
            f'<tr><td colspan="2" class="cat"><b>{_esc(labels.get(m.get("name", ""), m.get("name", "")))}</b></td></tr>'
        )
        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            rec = f.get("recommendation") or ""
            detail_rows += (
                "<tr>"
                f'<td>{_badge(sev)}</td>'
                f'<td><b>{_esc(f.get("title", ""))}</b>'
                f'<div class="dim">Estado: {_status(f.get("verification_status", "OBSERVED"))} &middot; Confianza: {_esc(_CONFIDENCE_ES.get(str(f.get("confidence", "UNSPECIFIED")).upper(), f.get("confidence", "")))} &middot; Ocurrencias: {_esc(f.get("occurrence_count", 1))}</div>'
                + _detail(f.get("detail", ""))
                + (f'<div class="rec"><b>Qué hacer:</b> {_esc(rec)}</div>' if rec else "")
                + "</td></tr>"
            )

    return f"""
    <h2 class="phase">{_esc(title)} <span class="tot">puntaje {total:.0f}/100{coverage_text}</span></h2>
    <table>
      <tr><th>Módulo</th><th>Estado</th></tr>
      {summary_rows}
    </table>
    {f'<h3>Desglose del puntaje</h3><table><tr><th>Categoría</th><th></th><th></th></tr>{score_rows}</table>' if score_rows else ''}
    <h3>Observaciones y hallazgos</h3>
    <table>
      <tr><th style="width:120px">Severidad</th><th>Hallazgo</th></tr>
      {detail_rows}
    </table>
    """


def _owasp_coverage(phase: dict) -> str:
    rows = phase.get("owasp_coverage") or []
    if not rows:
        return ""
    body = "".join(
        "<tr>"
        f"<td><b>{_esc(row.get('id', ''))}</b><br>{_esc(row.get('name', ''))}</td>"
        f"<td>{_status(row.get('status', ''))}</td>"
        f"<td>{_esc(', '.join(row.get('evidence_modules') or []) or 'Ninguno')}</td>"
        f"<td>{_esc(row.get('next_step') or ' '.join(row.get('limitations') or []) or 'La evidencia automatizada no demuestra ausencia de fallas.')}</td>"
        "</tr>" for row in rows
    )
    auth = "con sesión de prueba" if phase.get("authenticated") else "sin autenticación"
    return f"""
    <h2 class="phase">Cobertura OWASP Top 10:2025 <span class="tot">{auth}</span></h2>
    <p class="dim">«Parcial» significa que se reunió alguna evidencia relevante; nunca que toda la categoría sea segura.</p>
    <table><tr><th>Categoría</th><th>Estado</th><th>Módulos con evidencia</th><th>Validación pendiente</th></tr>{body}</table>
    """


def _coverage_metrics(phase: dict) -> str:
    metrics = phase.get("coverage_metrics") or {}
    if not metrics:
        return ""
    labels = (
        ("unique_urls", "URL únicas"), ("unique_paths", "Rutas únicas"),
        ("unique_parameters", "Parámetros"), ("api_endpoints", "Rutas de API"),
        ("auth_endpoints", "Rutas de autenticación"), ("sensitive_endpoints", "De aspecto sensible"),
        ("identifier_endpoints", "Rutas con identificador"), ("forms", "Formularios"),
    )
    cards = "".join(f'<td><b>{_esc(metrics.get(key, 0))}</b><br><span class="dim">{_esc(label)}</span></td>' for key, label in labels)
    return f"<h3>Métricas de cobertura de la aplicación</h3><table><tr>{cards}</tr></table>"


def _asset_inventory(phase: dict) -> str:
    """Render persisted web inventory without hiding it in terminal-only output."""
    subdomains = phase.get("subdomains") or []
    hosts = phase.get("live_hosts") or []
    exact_host = phase.get("target_mode") == "exact-host"
    if not subdomains and not hosts:
        return ""
    subdomain_rows = "".join(f"<li><code>{_esc(host)}</code></li>" for host in subdomains)
    host_rows = "".join(
        "<tr>"
        f'<td><a href="{_esc(host.get("url", ""))}">{_esc(host.get("url", ""))}</a></td>'
        f'<td>{_esc(host.get("ip", ""))}</td>'
        f'<td>{_esc(host.get("status", ""))}</td>'
        f'<td>{_esc(host.get("cdn", ""))}</td>'
        f'<td>{_esc(", ".join(f"{name} {version}" for name, version in (host.get("tech_versions") or {}).items()) or ", ".join(host.get("tech") or []))}</td>'
        f'<td>{_esc(", ".join(cve.get("id", "") for cve in host.get("cves") or []))}</td>'
        f'<td>{_esc(", ".join(sorted((host.get("headers") or {}).keys())))}</td>'
        "</tr>"
        for host in hosts
    )
    scope_text = (
        f"Modo de host exacto: {len(hosts)} punto(s) HTTP(S) que responden. No se buscaron subdominios, a propósito."
        if exact_host else
        f"{len(subdomains)} subdominio(s) descubiertos y {len(hosts)} servidor(es) HTTP(S) que responden."
    )
    discovery = "" if exact_host else f'<details><summary>Subdominios descubiertos ({len(subdomains)})</summary><ul>{subdomain_rows}</ul></details>'
    return f"""
    <h3>Inventario de activos</h3>
    <p class="dim">{scope_text}</p>
    {discovery}
    <details><summary>Servidores HTTP(S) activos ({len(hosts)})</summary>
      <table><tr><th>URL</th><th>IP</th><th>Código HTTP</th><th>CDN/WAF</th><th>Tecnología detectada</th><th>CVE por versión exacta</th><th>Cabeceras observadas</th></tr>{host_rows}</table>
    </details>
    """


def _dns_inventory(phase: dict) -> str:
    records = phase.get("dns_records") or {}
    if not records:
        return ""
    def render_records(values_by_type: dict) -> str:
        return "; ".join(
            f"{record_type}: {', '.join(values)}" for record_type, values in values_by_type.items()
        )

    rows = "".join(
        f"<tr><td><code>{_esc(host)}</code></td><td>{_esc(render_records(values_by_type))}</td></tr>"
        for host, values_by_type in sorted(records.items())
    )
    return f"<h3>Inventario DNS</h3><table><tr><th>Host</th><th>Registros</th></tr>{rows}</table>"


def _comparison(data: dict) -> str:
    comparison = data.get("comparison") or {}
    if not comparison:
        return ""
    rows = "".join(f"<tr><td>{_esc(name.replace('_', ' '))}</td><td>{_esc(', '.join(values) or 'Ninguno')}</td></tr>" for name, values in sorted(comparison.items()))
    return f"<h2 class=\"phase\">Cambios desde el informe anterior</h2><table><tr><th>Cambio</th><th>Activos</th></tr>{rows}</table>"


def _executive_summary(data: dict) -> str:
    phases = [phase for phase in (data.get("email") or {}, data.get("web") or {}) if phase]
    modules = [module for phase in phases for module in phase.get("modules", [])]
    findings = [finding for module in modules for finding in module.get("findings", [])]
    actionable = [
        finding for finding in findings
        if str(finding.get("severity", "INFO")).upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        and str(finding.get("verification_status", "OBSERVED")).upper() != "TOOL_INCOMPLETE"
    ]
    potential = sum(
        str(finding.get("verification_status", "")).upper() == "POTENTIAL"
        for finding in actionable
    )
    incomplete_modules = sorted({
        str(module.get("name", "unknown")) for module in modules
        if module.get("assessed") is False or any(
            str(finding.get("verification_status", "")).upper() == "TOOL_INCOMPLETE"
            for finding in module.get("findings", [])
        )
    })
    warning = ""
    if incomplete_modules:
        warning = (
            '<div class="notice"><b>Límite de cobertura:</b> '
            + _esc(", ".join(incomplete_modules))
            + " no terminó. Que no tenga hallazgos no significa que sea seguro.</div>"
        )
    return f"""
    <div class="cards">
      <div><b>{len(actionable)}</b><span>señales accionables</span></div>
      <div><b>{potential}</b><span>requieren validación</span></div>
      <div><b>{len(incomplete_modules)}</b><span>módulos incompletos</span></div>
    </div>
    {warning}
    """


def render(payload: Any) -> str:
    """Render a combined report dict to a standalone HTML page."""
    if isinstance(payload, dict) and "overall" not in payload:
        from .json import build as _build

        payload = _build(payload)
    data = payload if not hasattr(payload, "to_dict") else payload.to_dict()

    domain = data.get("domain", "unknown")
    timestamp = data.get("timestamp", "n/a")
    overall = data.get("overall", {})
    total = float(overall.get("total", 0))
    risk = str(overall.get("risk_level", "UNKNOWN")).upper()
    risk_color = _RISK_COLORS.get(risk, "info")

    email = data.get("email") or {}
    web = data.get("web") or {}
    email_section = _phase_section(email, "Seguridad del correo", _EMAIL_LABELS)
    web_section = _phase_section(
        web, "Aplicación web e infraestructura", _WEB_LABELS
    )
    inventory = _asset_inventory(web)
    dns_inventory = _dns_inventory(web)
    owasp_coverage = _owasp_coverage(web)
    coverage_metrics = _coverage_metrics(web)
    comparison = _comparison(data)
    execution = data.get("execution") or {}
    profile = execution.get("profile", "standard")
    scope = execution.get("scope")
    assessment_mode = execution.get("assessment_mode", "identification-only")
    target_mode = execution.get("target_mode", "domain-discovery")
    elapsed = execution.get("elapsed_seconds")
    elapsed_text = f" &middot; Duración: {float(elapsed):.0f} s" if elapsed is not None else ""
    exact_host = target_mode == "exact-host"
    report_kind = "Evaluación web de un host exacto" if exact_host and not email else "Evaluación combinada de correo y web" if email and web else "Evaluación web" if web else "Evaluación de correo"
    score_label = "Postura web" if web and not email else "Postura del correo" if email and not web else "Postura general"
    target_note = (
        "Este informe cubre solo el host indicado y las URL que pertenecen a él. No evalúa otros subdominios ni la postura de correo de la organización."
        if exact_host and not email else
        "El puntaje resume solo las fases y los módulos que aparecen en este informe."
    )
    executive_summary = _executive_summary(data)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Soryntel Security · {_esc(domain)}</title>
<style>
  :root {{ --negro:#0b0b0c; --alto:#17171a; --linea:#34373e; --gris:#a3a8b3; --rojo:#e11d2e; --rojo-claro:#ff5a67; }}
  body {{ font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',sans-serif; background:var(--negro); color:#fff; margin:0; padding:2rem; line-height:1.5; }}
  .wrap {{ max-width:1000px; margin:0 auto; }}
  .marca {{ font-size:.8rem; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }}
  .marca b {{ color:var(--rojo-claro); }}
  h1 {{ font-size:2.2rem; line-height:1.05; margin:.6rem 0 .4rem 0; overflow-wrap:anywhere; }}
  .sub {{ color:var(--gris); font-size:.85rem; margin-bottom:1.5rem; }}
  h2.phase {{ font-size:1.25rem; margin-top:2.5rem; padding-top:1.2rem; border-top:1px solid #fff; }}
  h2.phase .tot {{ float:right; color:var(--gris); font-size:.85rem; font-weight:400; }}
  h3 {{ font-size:.95rem; color:var(--gris); margin:1.4rem 0 .5rem 0; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; padding:.55rem .8rem; font-size:.75rem; font-weight:600; color:var(--gris); border-bottom:1px solid var(--linea); }}
  td {{ padding:.65rem .8rem; border-bottom:1px solid var(--linea); font-size:.9rem; vertical-align:top; }}
  td.cat {{ background:var(--alto); }}
  .badge {{ display:inline-block; padding:.12rem .5rem; font-size:.72rem; font-weight:700; border:1px solid var(--linea); color:var(--gris); }}
  .badge.critica {{ background:var(--rojo); border-color:var(--rojo); color:#fff; }}
  .badge.alta {{ background:var(--rojo-claro); border-color:var(--rojo-claro); color:var(--negro); }}
  .badge.media {{ background:#fff; border-color:#fff; color:var(--negro); }}
  .badge.baja {{ border-color:#fff; color:#fff; }}
  .badge.ok {{ border-color:#fff; color:#fff; }}
  .detail {{ color:var(--gris); margin-top:.3rem; white-space:pre-wrap; overflow-wrap:anywhere; }}
  .rec {{ margin-top:.35rem; }}
  .bar-outer {{ background:var(--alto); height:10px; overflow:hidden; }}
  .bar-inner {{ height:10px; min-width:2px; }}
  .total {{ margin-top:1.5rem; border:1px solid #fff; padding:1.4rem; display:flex; flex-wrap:wrap; align-items:baseline; gap:.5rem 1.5rem; }}
  .total .etiqueta {{ color:var(--gris); font-size:.85rem; flex:1 0 100%; }}
  .total .big {{ font-size:3rem; font-weight:800; line-height:1; }}
  .total .risk {{ font-size:1rem; padding:.3rem .8rem; }}
  .dim {{ color:var(--gris); }}
  .context, .notice {{ margin:1rem 0; padding:.8rem 1rem; background:var(--alto); border:1px solid var(--linea); }}
  .notice {{ border-color:var(--rojo-claro); }}
  .cards {{ display:grid; grid-template-columns:repeat(3,1fr); gap:0; margin:1rem 0; border:1px solid var(--linea); }}
  .cards div {{ padding:1rem; }}
  .cards div + div {{ border-left:1px solid var(--linea); }}
  .cards b {{ display:block; font-size:1.8rem; line-height:1.1; }}
  .cards span {{ color:var(--gris); font-size:.8rem; }}
  details {{ margin:.6rem 0; background:var(--alto); padding:.7rem .9rem; }}
  details.evidence {{ margin-top:.4rem; }}
  summary {{ cursor:pointer; font-weight:600; }}
  ul {{ columns:2; padding-left:1.2rem; }}
  code {{ font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace; font-size:.85em; }}
  a {{ color:#fff; }}
  .pie {{ margin-top:3rem; padding-top:1rem; border-top:1px solid var(--linea); color:var(--gris); font-size:.8rem; }}
  @media (max-width:640px) {{ body {{ padding:1rem; }} ul {{ columns:1; }} h2.phase .tot {{ float:none; display:block; margin-top:.3rem; }} }}
  @media print {{ body {{ background:#fff; color:#000; }} .dim,.sub,.detail,th,h3,.cards span {{ color:#444; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="marca">Soryntel <b>Security</b></div>
  <h1>{_esc(domain)}</h1>
  <div class="sub">{_esc(report_kind)} &middot; Generado: {_esc(timestamp)} &middot; Perfil: {_esc(profile)} &middot; Modo: {_esc(_MODE_ES.get(assessment_mode, assessment_mode))} &middot; Objetivo: {_esc(_MODE_ES.get(target_mode, target_mode))}{f' &middot; Alcance: {_esc(scope)}' if scope else ''}{elapsed_text}</div>
  <div class="context"><b>Límite de la evaluación:</b> {_esc(target_note)}</div>

  <div class="total">
    <div class="etiqueta">{_esc(score_label)}</div>
    <div class="big">{total:.0f} / 100</div>
    <div class="badge risk {risk_color}">Riesgo: {_esc(_RISK_ES.get(risk, risk))}</div>
  </div>

  {executive_summary}

  {email_section}
  {web_section}
  {inventory}
  {dns_inventory}
  {coverage_metrics}
  {owasp_coverage}
  {comparison}

  <div class="pie">Soryntel Security valida, identifica y reporta; nunca obtiene acceso. Un módulo sin hallazgos no demuestra que algo sea seguro.</div>
</div>
</body>
</html>"""


def write(payload: Any, path: Path) -> None:
    path.write_text(render(payload), encoding="utf-8")
