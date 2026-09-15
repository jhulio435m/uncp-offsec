"""Standalone HTML report for the combined (email + web) scan."""

from __future__ import annotations

import html as html_mod
import re
from pathlib import Path
from typing import Any

_SEV_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#7f8c8d",
    "PASS": "#27ae60",
}

_RISK_COLORS = {
    "INCONCLUSIVE": "#7f8c8d",
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "GOOD": "#27ae60",
}

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
    "relay": "Open Relay",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _esc(s: Any) -> str:
    return html_mod.escape(_ANSI_RE.sub("", str(s)), quote=True)


def _badge(sev: str) -> str:
    color = _SEV_COLORS.get(str(sev).upper(), "#666")
    return f'<span class="badge" style="background:{color}">{_esc(sev)}</span>'


def _worst(module: dict) -> str:
    worst = "INFO"
    for f in module.get("findings", []):
        sev = str(f.get("severity", "INFO")).upper()
        if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(worst, 5):
            worst = sev
    return worst


def _module_status(module: dict) -> tuple[str, str]:
    incomplete = any(
        str(finding.get("verification_status", "")).upper() == "TOOL_INCOMPLETE"
        for finding in module.get("findings", [])
    )
    if module.get("assessed") is False or incomplete:
        return "INCOMPLETE", "#7f8c8d"
    severity = _worst(module)
    return severity, _SEV_COLORS.get(severity, "#666")


def _detail(value: Any) -> str:
    text = str(value or "")
    escaped = _esc(text)
    if len(text) <= 600:
        return f'<div class="detail">{escaped}</div>'
    return (
        '<details class="evidence"><summary>Show full evidence '
        f'({len(text.splitlines())} lines)</summary><div class="detail">{escaped}</div></details>'
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
        f" &middot; coverage {float(coverage):.0f}% &middot; confidence {_esc(confidence)}"
        if coverage is not None
        else ""
    )

    summary_rows = ""
    for m in modules:
        name = labels.get(m.get("name", ""), m.get("name", ""))
        status, color = _module_status(m)
        summary_rows += (
            f'<tr><td><b>{_esc(name)}</b></td>'
            f'<td><span class="badge" style="background:{color}">{_esc(status)}</span></td></tr>'
        )

    score_rows = ""
    for c in categories:
        name = c.get("name", "")
        score = float(c.get("score", 0))
        maxv = float(c.get("max", 0))
        pct = (score / maxv * 100) if maxv else 0
        bar_color = "#27ae60" if pct >= 75 else ("#f1c40f" if pct >= 45 else "#c0392b")
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
                f'<div class="dim">Status: {_esc(f.get("verification_status", "OBSERVED"))} &middot; Confidence: {_esc(f.get("confidence", "UNSPECIFIED"))} &middot; Occurrences: {_esc(f.get("occurrence_count", 1))}</div>'
                + _detail(f.get("detail", ""))
                + (f'<div class="rec"><b>Recommended:</b> {_esc(rec)}</div>' if rec else "")
                + "</td></tr>"
            )

    return f"""
    <h2 class="phase">{_esc(title)} <span class="tot">score {total:.0f}/100{coverage_text}</span></h2>
    <table>
      <tr><th>Module</th><th>Status</th></tr>
      {summary_rows}
    </table>
    <h3>Score breakdown</h3>
    <table>
      <tr><th>Category</th><th></th><th></th></tr>
      {score_rows}
    </table>
    <h3>All observations and findings</h3>
    <table>
      <tr><th style="width:110px">Severity</th><th>Finding</th></tr>
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
        f"<td>{_esc(row.get('status', ''))}</td>"
        f"<td>{_esc(', '.join(row.get('evidence_modules') or []) or 'None')}</td>"
        f"<td>{_esc(' '.join(row.get('limitations') or []) or 'Automated evidence is still not proof of absence.')}</td>"
        "</tr>" for row in rows
    )
    auth = "authenticated" if phase.get("authenticated") else "unauthenticated"
    return f"""
    <h2 class="phase">OWASP Top 10:2025 coverage <span class="tot">{auth}</span></h2>
    <p class="dim">PARTIAL means the scanner collected some relevant evidence; it never means the whole category is secure.</p>
    <table><tr><th>Category</th><th>Status</th><th>Evidence modules</th><th>Limitations</th></tr>{body}</table>
    """


def _coverage_metrics(phase: dict) -> str:
    metrics = phase.get("coverage_metrics") or {}
    if not metrics:
        return ""
    labels = (
        ("unique_urls", "Unique URLs"), ("unique_paths", "Unique paths"),
        ("unique_parameters", "Parameters"), ("api_endpoints", "API endpoints"),
        ("auth_endpoints", "Auth endpoints"), ("sensitive_endpoints", "Sensitive-looking"),
        ("identifier_endpoints", "Identifier paths"), ("forms", "Forms"),
    )
    cards = "".join(f'<td><b>{_esc(metrics.get(key, 0))}</b><br><span class="dim">{_esc(label)}</span></td>' for key, label in labels)
    return f"<h3>Application coverage metrics</h3><table><tr>{cards}</tr></table>"


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
        f"Exact target mode: {len(hosts)} responding HTTP(S) endpoint(s). Subdomain discovery was intentionally not performed."
        if exact_host else
        f"{len(subdomains)} discovered subdomain(s) and {len(hosts)} responding HTTP(S) host(s)."
    )
    discovery = "" if exact_host else f'<details><summary>Discovered subdomains ({len(subdomains)})</summary><ul>{subdomain_rows}</ul></details>'
    return f"""
    <h3>Asset inventory</h3>
    <p class="dim">{scope_text}</p>
    {discovery}
    <details><summary>Live HTTP(S) hosts ({len(hosts)})</summary>
      <table><tr><th>URL</th><th>IP</th><th>Status</th><th>CDN/WAF</th><th>Detected technology</th><th>Exact-version CVEs</th><th>Observed headers</th></tr>{host_rows}</table>
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
    return f"<h3>DNS inventory</h3><table><tr><th>Host</th><th>Records</th></tr>{rows}</table>"


def _comparison(data: dict) -> str:
    comparison = data.get("comparison") or {}
    if not comparison:
        return ""
    rows = "".join(f"<tr><td>{_esc(name.replace('_', ' '))}</td><td>{_esc(', '.join(values) or 'None')}</td></tr>" for name, values in sorted(comparison.items()))
    return f"<h2 class=\"phase\">Changes since previous report</h2><table><tr><th>Change</th><th>Assets</th></tr>{rows}</table>"


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
            '<div class="notice"><b>Coverage limitation:</b> '
            + _esc(", ".join(incomplete_modules))
            + " did not complete. Their absence of findings must not be interpreted as secure.</div>"
        )
    return f"""
    <div class="cards">
      <div><b>{len(actionable)}</b><span>actionable signals</span></div>
      <div><b>{potential}</b><span>require validation</span></div>
      <div><b>{len(incomplete_modules)}</b><span>incomplete modules</span></div>
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
    risk_color = _RISK_COLORS.get(risk, "#666")

    email = data.get("email") or {}
    web = data.get("web") or {}
    email_section = _phase_section(email, "Email security", _EMAIL_LABELS)
    web_section = _phase_section(
        web, "Web application and infrastructure", {}
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
    elapsed_text = f" &middot; Duration: {float(elapsed):.3f}s" if elapsed is not None else ""
    exact_host = target_mode == "exact-host"
    report_kind = "Exact-host web assessment" if exact_host and not email else "Combined email and web assessment" if email and web else "Web assessment" if web else "Email assessment"
    score_label = "WEB POSTURE SCORE" if web and not email else "EMAIL POSTURE SCORE" if email and not web else "OVERALL POSTURE SCORE"
    target_note = (
        "This report covers only the named host and the URLs retained on that host. It does not assess sibling subdomains or organizational email posture."
        if exact_host and not email else
        "The score summarizes only the phases and modules shown in this report."
    )
    executive_summary = _executive_summary(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UnCP OffSec - {_esc(domain)}</title>
<style>
  body {{ font-family:-apple-system,'Segoe UI',Roboto,sans-serif; background:#0f1430; color:#e8ecf8; margin:0; padding:2rem; }}
  .wrap {{ max-width:980px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 .2rem 0; }}
  .sub {{ color:#9aa3c0; font-size:.85rem; margin-bottom:1.5rem; }}
  h2.phase {{ font-size:1.1rem; margin-top:2rem; padding-top:1.2rem; border-top:1px solid #232b56; }}
  h2.phase .tot {{ float:right; color:#9aa3c0; font-size:.85rem; font-weight:400; }}
  h3 {{ font-size:.95rem; color:#9aa3c0; margin:1.2rem 0 .4rem 0; }}
  table {{ width:100%; border-collapse:collapse; background:#161d3c; border-radius:8px; overflow:hidden; }}
  th {{ background:#1d2650; text-align:left; padding:.55rem .8rem; font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  td {{ padding:.6rem .8rem; border-top:1px solid #232b56; font-size:.9rem; vertical-align:top; }}
  td.cat {{ background:#1d2650; }}
  .badge {{ color:#fff; padding:.15rem .55rem; border-radius:99px; font-size:.72rem; font-weight:700; }}
  .detail {{ color:#9aa3c0; margin-top:.25rem; white-space:pre-wrap; }}
  .rec {{ color:#7fd0ff; margin-top:.15rem; }}
  .bar-outer {{ background:#0b1030; border-radius:6px; height:14px; overflow:hidden; }}
  .bar-inner {{ height:14px; border-radius:6px; min-width:2px; }}
  .total {{ margin-top:1.5rem; background:#161d3c; border-radius:8px; padding:1.2rem; text-align:center; }}
  .total .big {{ font-size:1.6rem; font-weight:800; }}
  .total .risk {{ display:inline-block; color:#fff; padding:.3rem 1rem; border-radius:99px; font-weight:800; margin-top:.4rem; }}
  .login {{ color:#8890b0; font-size:.8rem; margin-top:.4rem; }}
  .dim {{ color:#9aa3c0; }}
  .context, .notice {{ margin:1rem 0; padding:.8rem 1rem; border-radius:8px; background:#172344; border-left:4px solid #5aa9e6; }}
  .notice {{ border-left-color:#f1c40f; background:#292641; }}
  .cards {{ display:grid; grid-template-columns:repeat(3,1fr); gap:.7rem; margin:1rem 0; }}
  .cards div {{ background:#161d3c; padding:.9rem; border-radius:8px; }}
  .cards b {{ display:block; font-size:1.35rem; }}
  .cards span {{ color:#9aa3c0; font-size:.8rem; }}
  details.evidence {{ background:#101735; margin-top:.4rem; }}
  details {{ margin:.6rem 0; background:#161d3c; padding:.7rem .9rem; border-radius:8px; }}
  summary {{ cursor:pointer; font-weight:600; }}
  ul {{ columns:2; padding-left:1.2rem; }}
  code, a {{ color:#9ed7ff; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>UnCP OffSec - <b>{_esc(domain)}</b></h1>
  <div class="sub">{_esc(report_kind)} &middot; Generated: {_esc(timestamp)} &middot; Profile: {_esc(profile)} &middot; Mode: {_esc(assessment_mode)} &middot; Target: {_esc(target_mode)}{f' &middot; Scope: {_esc(scope)}' if scope else ''}{elapsed_text}</div>
  <div class="context"><b>Assessment boundary:</b> {_esc(target_note)}</div>

  <div class="total">
    <div>{_esc(score_label)}</div>
    <div class="big">{total:.0f} / 100</div>
    <div class="risk" style="background:{risk_color}">RISK: {_esc(risk)}</div>
  </div>

  {executive_summary}

  {email_section}
  {web_section}
  {inventory}
  {dns_inventory}
  {coverage_metrics}
  {owasp_coverage}
  {comparison}
</div>
</body>
</html>"""


def write(payload: Any, path: Path) -> None:
    path.write_text(render(payload), encoding="utf-8")
