"""MailSec Auditor CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import click

from . import __version__
from .models import ScanConfig, Severity
from .modules import eml_analyzer
from .reports import html_report, json_report, terminal_report
from .scanner import scan

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "magenta",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
    Severity.PASS: "green",
}


@click.group()
@click.version_option(__version__, prog_name="mailsec")
def cli():
    """MailSec Auditor - authorized email surface assessment."""


@cli.command()
@click.argument("domain")
@click.option("--active", is_flag=True, help="Enable active SMTP probes (relay test).")
@click.option("--timeout", default=10.0, type=float, show_default=True, help="DNS/socket timeout (s).")
@click.option("--tls-timeout", default=15.0, type=float, show_default=True, help="TLS handshake timeout (s).")
@click.option("--no-verify-cert", is_flag=True, help="Skip TLS certificate verification.")
@click.option("--selectors", default=None, help="Comma-separated DKIM selectors to probe.")
@click.option(
    "-o", "--output", default=None, type=click.Path(path_type=Path),
    help="Write report to a file (inferred format from extension, default JSON).",
)
@click.option("--format", "fmt", default=None, type=click.Choice(["json", "html"]),
              help="Report format when using -o/--output.")
def scan_cmd(domain, active, timeout, tls_timeout, no_verify_cert, selectors, output, fmt):
    """Assess the email security posture of DOMAIN."""
    config = ScanConfig(
        domain=domain,
        active=active,
        timeout=timeout,
        tls_timeout=tls_timeout,
        verify_cert=not no_verify_cert,
    )
    if selectors:
        config.dkim_selectors = [s.strip() for s in selectors.split(",") if s.strip()]

    if not active:
        click.echo(click.style(
            "[!] Passive scan: DNS-based checks only. Use --active for SMTP port-25 probes.",
            fg="yellow",
        ))
    else:
        click.echo(click.style(
            "[!] Active mode: connecting to MX hosts on port 25. Ensure you are authorized "
            "to test this domain.",
            fg="yellow",
        ))

    with click.progressbar(length=100, label="Scanning", show_percent=True) as bar:
        result = scan(domain, config)
        bar.update(100)

    terminal_report.render(result)

    if output:
        fmt = fmt or (output.suffix.lstrip(".") if output.suffix else "json")
        output.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "html":
            html_report.write(result, output)
        else:
            json_report.write(result, output)
        click.echo(click.style(f"Report written to {output}", fg="green"))


@cli.command()
@click.argument("eml", type=click.Path(path_type=Path, exists=True))
@click.option("--domain", default=None, help="Domain to treat as the local organization.")
def analyze(eml, domain):
    """Forensically analyze a received message (.eml)."""
    config = ScanConfig(domain=domain or "")
    analysis, result = eml_analyzer.analyze(eml, config)
    terminal_report.render_eml(analysis, result)


@cli.command("report")
@click.argument("input", type=click.Path(path_type=Path, exists=True))
@click.argument("output", type=click.Path(path_type=Path))
@click.option("--format", "fmt", default=None, type=click.Choice(["json", "html"]),
              help="Output format (inferred from output extension if not given).")
def report_cmd(input, output, fmt):
    """Convert a saved JSON scan report into another format."""
    payload = json.loads(input.read_text())
    fmt = fmt or (output.suffix.lstrip(".") if output.suffix else "html")
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "html":
        html_report.write(payload, output)
    else:
        json_report.write(payload, output)
    click.echo(click.style(f"Report written to {output}", fg="green"))


if __name__ == "__main__":
    cli()