"""Terminal report rendering with rich."""

from __future__ import annotations

import html

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import ModuleResult, ScanResult, Severity
from ..modules.eml_analyzer import EMLAnalysis

console = Console()

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold magenta",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
    Severity.PASS: "green",
}

_RISK_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold white on magenta",
    "MEDIUM": "bold black on yellow",
    "LOW": "bold white on blue",
    "GOOD": "bold black on green",
}


def _severity_text(sev: Severity) -> str:
    return f"[{_SEV_STYLE[sev]}]{sev.value}[/]"


def _module_status_text(mr: ModuleResult) -> str:
    if not mr.findings:
        return _severity_text(Severity.INFO)
    worst = max((f.severity for f in mr.findings), key=lambda s: s.weight * -1)
    return _severity_text(worst)


def _render_summary(result: ScanResult) -> None:
    table = Table(show_header=True, header_style="bold", border_style="grey50")
    table.add_column("Module", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Name", style="dim")

    name_map = {
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
    status: dict[str, str] = {}
    for mr in result.modules:
        status[mr.name] = _module_status_text(mr)
        table.add_row(mr.name.upper(), status[mr.name], name_map.get(mr.name, mr.name))

    console.print(table)


def _render_findings(result: ScanResult) -> None:
    for mr in result.modules:
        actionable = [f for f in mr.findings if f.severity not in (Severity.PASS, Severity.INFO)]
        if not actionable:
            continue
        console.print(f"\n[bold]{mr.name.upper()}[/bold]")
        for f in actionable:
            console.print(f"  {_severity_text(f.severity)}  [bold]{f.title}[/bold]")
            if f.detail:
                for line in f.detail.splitlines():
                    console.print(f"      {line}")
            if f.recommendation:
                console.print(f"      [cyan]Recommended:[/cyan] {f.recommendation}")
            if f.rfc_ref:
                console.print(f"      [dim]Ref: {f.rfc_ref}[/dim]")


def _render_score(result: ScanResult) -> None:
    breakdown = getattr(result, "breakdown", None)
    if breakdown is None:
        return
    table = Table(show_header=True, header_style="bold", border_style="grey50")
    table.add_column("Category", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Max", justify="right")
    for cat in breakdown.categories[:-1]:
        table.add_row(cat.name, f"{cat.score:>5.1f}", f"{cat.max:>4.0f}")
    console.print(table)
    total = breakdown.total
    risk = breakdown.risk_level
    style = _RISK_STYLE.get(risk, "bold")
    console.print(
        Panel(
            f"[bold]TOTAL  {total:.0f}/100     Risk: [/bold][{style}]{risk}[/]",
            border_style="grey50",
        )
    )


def render(result: ScanResult) -> None:
    """Render full scan report to the terminal."""
    console.print()
    console.rule("[bold]MAIL SECURITY ASSESSMENT[/bold]")
    console.print(f"  [bold]Target:[/bold] {result.domain}")
    console.print(f"  [dim]Scan time: {result.timestamp}[/dim]")

    if result.mx_hosts:
        mx_list = ", ".join(f"{m.preference} {m.hostname}" for m in result.mx_hosts)
        console.print(f"  [dim]MX: {mx_list}[/dim]")

    console.print()
    _render_summary(result)
    _render_score(result)
    _render_findings(result)
    console.print()


def _summary_state(analysis: EMLAnalysis) -> str:
    if analysis.measured_dmarc == "fail":
        return "FAIL"
    if analysis.measured_dmarc == "pass":
        return "PASS"
    return "UNKNOWN"


def render_eml(analysis: EMLAnalysis, result: ModuleResult) -> None:
    """Render EML forensic analysis to the terminal."""
    console.print()
    console.rule("[bold]EMAIL FORENSIC ANALYSIS[/bold]")
    console.print(f"  [bold]From:[/bold]        {analysis.from_header}")
    console.print(f"  [bold]Return-Path:[/bold] {analysis.return_path}")
    console.print(f"  [bold]Subject:[/bold]     {analysis.subject}")
    console.print(f"  [bold]SPF:[/bold]        {analysis.measured_spf}")
    console.print(f"  [bold]DKIM:[/bold]       {analysis.measured_dkim}")
    console.print(f"  [bold]DMARC:[/bold]      {analysis.measured_dmarc} "
                  f"(disposition: {analysis.dmarc_disposition})")
    console.print(f"  [bold]Overall:[/bold]    {_summary_state(analysis)}")
    console.print()

    if analysis.received_chain:
        table = Table(title="Received chain", show_header=False, border_style="grey50")
        for i, hop in enumerate(reversed(analysis.received_chain)):
            table.add_row(f"[dim]#{i + 1}[/dim]", html.unescape(hop))
        console.print(table)

    console.print()
    for f in result.findings:
        console.print(f"  {_severity_text(f.severity)}  [bold]{f.title}[/bold]")
        if f.detail:
            for line in f.detail.splitlines():
                console.print(f"      {line}")
        if f.recommendation:
            console.print(f"      [cyan]Recommended:[/cyan] {f.recommendation}")
    console.print()