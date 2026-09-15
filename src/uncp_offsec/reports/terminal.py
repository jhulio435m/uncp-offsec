"""Terminal rendering for the combined report."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mailsec.models import Severity
from mailsec.reports.terminal_report import render as render_email

from ..models import CombinedScanResult, WebScanResult

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
    "INCONCLUSIVE": "bold white on grey50",
    "CRITICAL": "bold white on red",
    "HIGH": "bold white on magenta",
    "MEDIUM": "bold black on yellow",
    "LOW": "bold white on blue",
    "GOOD": "bold black on green",
}


def _severity_text(sev: Severity) -> str:
    return f"[{_SEV_STYLE[sev]}]{sev.value}[/]"


def _module_status_text(mr) -> str:
    if not mr.assessed or any(f.verification_status == "TOOL_INCOMPLETE" for f in mr.findings):
        return "[bold white on grey50]INCOMPLETE[/]"
    if not mr.findings:
        return _severity_text(Severity.INFO)
    worst = max((f.severity for f in mr.findings), key=lambda s: s.weight * -1)
    return _severity_text(worst)


def _render_web_summary(result: WebScanResult) -> None:
    table = Table(show_header=True, header_style="bold", border_style="grey50")
    table.add_column("Module", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Name", style="dim")
    for mr in result.modules:
        table.add_row(mr.name.upper(), _module_status_text(mr), mr.name)
    console.print(table)


def _render_web_findings(result: WebScanResult) -> None:
    for mr in result.modules:
        actionable = [f for f in mr.findings if f.severity not in (Severity.PASS, Severity.INFO)]
        if not actionable:
            continue
        actionable.sort(key=lambda finding: finding.severity.weight)
        displayed = actionable[:25]
        console.print(f"\n[bold]{mr.name.upper()}[/bold]")
        for f in displayed:
            console.print(f"  {_severity_text(f.severity)}  [bold]{f.title}[/bold]")
            if f.detail:
                for line in f.detail.splitlines():
                    console.print(f"      {line}")
            if f.recommendation:
                console.print(f"      [cyan]Recommended:[/cyan] {f.recommendation}")
        remaining = len(actionable) - len(displayed)
        if remaining:
            console.print(
                f"  [dim]... {remaining} additional actionable finding instance(s) are preserved "
                "in the JSON/HTML report.[/dim]"
            )


def _render_web_score(result: WebScanResult) -> None:
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
    risk = result.risk_level
    style = _RISK_STYLE.get(risk, "bold")
    console.print(
        Panel(
            f"[bold]TOTAL  {total:.0f}/100     Risk: [/bold][{style}]{risk}[/]",
            border_style="grey50",
        )
    )
    console.print(
        f"  [bold]Coverage:[/bold] {result.coverage_score:.1f}%"
        f"  [bold]Confidence:[/bold] {result.confidence}"
    )


def render_web(result: WebScanResult) -> None:
    """Render only the web phase section."""
    console.print()
    title = "EXACT-HOST WEB ASSESSMENT" if result.target_mode == "exact-host" else "WEB ASSET ASSESSMENT"
    console.rule(f"[bold]{title}[/bold]")
    console.print(f"  [bold]Target:[/bold] {result.domain}")
    if result.live_hosts:
        if result.target_mode == "exact-host":
            console.print(f"  [dim]Responding HTTP(S) endpoints: {len(result.live_hosts)} · subdomain discovery skipped[/dim]")
        else:
            console.print(f"  [dim]Live hosts: {len(result.live_hosts)} / discovered subdomains: {len(result.subdomains)}[/dim]")
    console.print()
    _render_web_summary(result)
    _render_web_score(result)
    _render_web_findings(result)
    if result.coverage_metrics:
        metrics = result.coverage_metrics
        console.print(
            "  [bold]Application coverage:[/bold] "
            f"URLs {metrics.get('unique_urls', 0)} · paths {metrics.get('unique_paths', 0)} · "
            f"parameters {metrics.get('unique_parameters', 0)} · APIs {metrics.get('api_endpoints', 0)} · "
            f"auth {metrics.get('auth_endpoints', 0)} · identifiers {metrics.get('identifier_endpoints', 0)} · "
            f"forms {metrics.get('forms', 'UNMEASURED')}"
        )
    if result.owasp_coverage:
        table = Table(title="OWASP Top 10:2025 coverage", show_header=True, header_style="bold")
        table.add_column("Category")
        table.add_column("Status")
        table.add_column("Evidence")
        for row in result.owasp_coverage:
            table.add_row(f"{row['id']} {row['name']}", row["status"], ", ".join(row["evidence_modules"]) or "none")
        console.print(table)
    console.print()


def render_combined(combined: CombinedScanResult) -> None:
    """Render the full combined report to the terminal."""
    console.print()
    console.rule(f"[bold]UNCP OFFSEC - {combined.domain}[/bold]")
    console.print(f"  [dim]Scan time: {combined.timestamp}[/dim]")
    console.print(f"  [dim]Assessment mode: {combined.assessment_mode}[/dim]")
    if combined.elapsed_seconds:
        console.print(f"  [dim]Execution time: {combined.elapsed_seconds:.3f}s[/dim]")

    if combined.email is not None:
        render_email(combined.email)
    else:
        console.print("\n[dim]Email phase skipped (-no-email).[/dim]")

    if combined.web is not None:
        render_web(combined.web)
    else:
        console.print("\n[dim]Web phase skipped (-no-web).[/dim]")

    total = combined.overall_score
    risk = combined.overall_risk
    style = _RISK_STYLE.get(risk, "bold")
    phase_label = "COMBINED" if combined.email is not None and combined.web is not None else "WEB ONLY" if combined.web is not None else "EMAIL ONLY"
    module_summary = (
        f"email {combined.email_modules} modules · web {combined.web_modules} modules"
        if combined.email is not None and combined.web is not None else
        f"web {combined.web_modules} modules" if combined.web is not None else
        f"email {combined.email_modules} modules"
    )
    console.print(
        Panel(
            f"[bold]{phase_label}  {total:.0f}/100     Risk: [/bold][{style}]{risk}[/]\n"
            f"[dim]{module_summary}[/dim]",
            border_style="grey50",
        )
    )
    console.print()
