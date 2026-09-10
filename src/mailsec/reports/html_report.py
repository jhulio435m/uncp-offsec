"""Standalone HTML report generator (no external templates)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .json_report import build

_SEV_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#7f8c8d",
    "PASS": "#27ae60",
}

_RISK_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "GOOD": "#27ae60",
}

_MODULE_LABELS = {
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

_SEV_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "PASS": 5,
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _status_badge(sev: str) -> str:
    color = _SEV_COLORS.get(str(sev).upper(), "#666")
    return f'<span class="badge" style="background:{color}">{_esc(sev)}</span>'


def render(payload: Any) -> str:
    data = build(payload)

    domain = data.get("domain", "unknown")
    timestamp = data.get("timestamp", "n/a")
    risk = data.get("risk", {})
    total = risk.get("total", data.get("total_score", 0))
    risk_level = risk.get("risk_level", data.get("risk_level", "UNKNOWN"))
    risk_color = _RISK_COLORS.get(str(risk_level).upper(), "#666")

    mx_hosts = data.get("mx_hosts", [])
    modules = data.get("modules", [])
    categories = (risk.get("categories") or [])[:-1]

    # Summary table rows
    summary_rows = ""
    for m in modules:
        name = _MODULE_LABELS.get(m.get("name", ""), m.get("name", ""))
        worst = "INFO"
        for f in m.get("findings", []):
            sev = str(f.get("severity", "INFO")).upper()
            if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(worst, 5):
                worst = sev
        summary_rows += (
            f"<tr><td><b>{_esc(name)}</b></td>"
            f"<td>{_status_badge(worst)}</td></tr>"
        )

    # Findings detail
    detail_rows = ""
    for m in modules:
        actionable = [f for f in m.get("findings", []) if f.get("severity") not in ("PASS", "INFO")]
        if not actionable:
            continue
        detail_rows += (
            f'<tr><td colspan="3" class="cat">'
            f"<b>{_esc(_MODULE_LABELS.get(m.get('name', ''), m.get('name', '')))}</b>"
            f"</td></tr>"
        )
        for f in actionable:
            sev = str(f.get("severity", "INFO")).upper()
            rec = f.get("recommendation") or ""
            ref = f.get("rfc_ref") or ""
            detail_rows += (
                "<tr>"
                f'<td>{_status_badge(sev)}</td>'
                f'<td><b>{_esc(f.get("title", ""))}</b>'
                f'<div class="detail">{_esc(f.get("detail", "") or "")}</div>'
                + (f'<div class="rec"><b>Recommended:</b> {_esc(rec)}</div>' if rec else "")
                + (f'<div class="ref">Ref: {_esc(ref)}</div>' if ref else "")
                + "</td></tr>"
            )

    # Score category bars
    score_rows = ""
    for c in categories:
        name = c.get("name", "")
        score = float(c.get("score", 0))
        maxv = float(c.get("max", 0))
        pct = (score / maxv * 100) if maxv else 0
        bar_color = "#27ae60" if pct >= 75 else ("#f1c40f" if pct >= 45 else "#c0392b")
        score_rows += (
            f'<tr><td>{_esc(name)}</td>'
            f'<td style="width:40%"><div class="bar-outer">'
            f'<div class="bar-inner" style="width:{pct:.0f}%;background:{bar_color}"></div>'
            f"</div></td>"
            f'<td style="text-align:right"><b>{score:.1f}</b> / {maxv:.0f}</td></tr>'
        )

    mx_html = ""
    if mx_hosts:
        mx_html = "<div class='meta'>MX records:</div><ul>"
        for m in sorted(mx_hosts, key=lambda x: x.get("preference", 100)):
            mx_html += f"<li><b>{_esc(m.get('preference'))}</b> {_esc(m.get('hostname'))}</li>"
        mx_html += "</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailSec Auditor - {_esc(domain)}</title>
<style>
  body {{ font-family:-apple-system,'Segoe UI',Roboto,sans-serif; background:#0f1430; color:#e8ecf8; margin:0; padding:2rem; }}
  .wrap {{ max-width:980px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 .2rem 0; }}
  .sub {{ color:#9aa3c0; font-size:.85rem; margin-bottom:1.5rem; }}
  .meta {{ color:#9aa3c0; font-size:.85rem; }}
  ul {{ margin:.2rem 0 1rem 0; }}
  table {{ width:100%; border-collapse:collapse; background:#161d3c; border-radius:8px; overflow:hidden; }}
  th {{ background:#1d2650; text-align:left; padding:.55rem .8rem; font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  td {{ padding:.6rem .8rem; border-top:1px solid #232b56; font-size:.9rem; vertical-align:top; }}
  td.cat {{ background:#1d2650; }}
  .badge {{ color:#fff; padding:.15rem .55rem; border-radius:99px; font-size:.72rem; font-weight:700; }}
  .detail {{ color:#9aa3c0; margin-top:.25rem; white-space:pre-wrap; }}
  .rec {{ color:#7fd0ff; margin-top:.15rem; }}
  .ref {{ color:#555d85; font-size:.75rem; margin-top:.1rem; }}
  .bar-outer {{ background:#0b1030; border-radius:6px; height:14px; overflow:hidden; }}
  .bar-inner {{ height:14px; border-radius:6px; min-width:2px; }}
  .total {{ margin-top:1.5rem; background:#161d3c; border-radius:8px; padding:1.2rem; text-align:center; }}
  .total .big {{ font-size:1.6rem; font-weight:800; }}
  .total .risk {{ display:inline-block; color:#fff; padding:.3rem 1rem; border-radius:99px; font-weight:800; margin-top:.4rem; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Mail Security Assessment</h1>
  <div class="sub">Target: <b>{_esc(domain)}</b> &middot; Generated: {_esc(timestamp)}</div>
  {mx_html}
  <h2 style="font-size:1rem">DNS &amp; Authentication</h2>
  <table>
    <tr><th>Control</th><th>Status</th></tr>
    {summary_rows}
  </table>

  <h2 style="font-size:1rem">Score Breakdown</h2>
  <table>
    <tr><th>Category</th><th></th><th></th></tr>
    {score_rows}
  </table>

  <div class="total">
    <div>TOTAL SCORE</div>
    <div class="big">{total:.0f} / 100</div>
    <div class="risk" style="background:{risk_color}">RISK: {_esc(risk_level)}</div>
  </div>

  <h2 style="font-size:1rem">Findings</h2>
  <table>
    <tr><th style="width:110px">Severity</th><th>Finding</th></tr>
    {detail_rows}
  </table>
</div>
</body>
</html>"""


def write(payload: Any, path: Path) -> None:
    path.write_text(render(payload), encoding="utf-8")