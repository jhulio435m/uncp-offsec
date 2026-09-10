"""UnCP OffSec CLI - unified email + web asset assessment."""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from mailsec.models import ScanConfig
from mailsec.modules import eml_analyzer
from mailsec.reports import terminal_report

from . import __version__
from .compare import build as build_comparison
from .reports import html as combined_html
from .reports import json as combined_json
from .reports import terminal as combined_terminal
from .scanner import run_combined
from .scope import allows as scope_allows
from .scope import load as load_scope
from .web import sqli
from .web.auth import load_headers
from .web.tools import which


def _warn(message: str) -> None:
    click.echo(click.style(message, fg="yellow"))


def _automatic_scope(domain: str) -> Path | None:
    """Find one local active scope that authorizes the requested host."""
    for directory in (Path.cwd(), Path("/opt/uncp-tools/scopes")):
        matches: list[tuple[int, Path]] = []
        for candidate in sorted(directory.glob("scope*.json")):
            try:
                authorization = load_scope(candidate)
            except (TypeError, ValueError):
                continue
            if authorization.allow_active and scope_allows(authorization, domain):
                specificity = max(
                    (len(item) for item in authorization.domains if scope_allows(authorization, domain)),
                    default=0,
                )
                matches.append((specificity, candidate))
        if matches:
            best_specificity = max(item[0] for item in matches)
            best = [path for specificity, path in matches if specificity == best_specificity]
            return best[0] if len(best) == 1 else None
    return None


def _automatic_wordlist() -> Path | None:
    """Return the first approved bundled/system web-content wordlist available."""
    candidates = (
        Path("/opt/uncp-tools/wordlists/raft-medium-directories.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        Path.cwd() / "lab" / "wordlist.txt",
    )
    return next((path for path in candidates if path.is_file()), None)


def _automatic_report_dir() -> Path:
    """Use the container report mount when present, otherwise the local folder."""
    container_reports = Path("/reports")
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    return container_reports if in_container and container_reports.is_dir() else Path.cwd() / "reports"


@click.group()
@click.version_option(__version__, prog_name="uncp_offsec")
def cli():
    """UnCP OffSec - automated email + web surface assessment."""


@cli.command()
@click.argument("domain")
@click.option(
    "--profile",
    type=click.Choice(["passive", "standard", "active-authorized", "active-validation", "lab"]),
    default="standard",
    show_default=True,
    help="Execution profile; active-authorized requires --scope.",
)
@click.option(
    "--scope",
    "scope_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON authorization file; required for active tests.",
)
@click.option("--active", is_flag=True, help="Enable active probes; requires an authorizing --scope.")
@click.option("--no-email", is_flag=True, help="Skip the email (MailSec) phase.")
@click.option("--no-web", is_flag=True, help="Skip the web asset phase.")
@click.option("--ports", "with_ports", is_flag=True, help="Run naabu port scan (web phase).")
@click.option("--nmap", "with_nmap", is_flag=True, help="Identify Naabu-confirmed services with Nmap; requires --scope.")
@click.option("--nmap-safe-scripts", is_flag=True, help="Run a fixed set of safe discovery/TLS NSE scripts.")
@click.option("--nmap-vuln-authorized", is_flag=True, help="Correlate service versions with CVEs using detection-only NSE; requires scope permission.")
@click.option("--nuclei", "with_nuclei", is_flag=True, help="Run nuclei vulnerability matching (web phase).")
@click.option("--cves", "with_cves", is_flag=True, help="Enrich exact technology versions with NVD CVEs and CISA KEV.")
@click.option("--cve-cache", type=click.Path(file_okay=False, path_type=Path), help="Required local cache directory with --cves.")
@click.option("--dns-inventory", is_flag=True, help="Collect structured DNS records for the target and discovered assets.")
@click.option("--headers", "with_headers", is_flag=True, help="Review security response headers on discovered web hosts.")
@click.option("--crawl", "with_crawl", is_flag=True, help="Authorized bounded crawling with Katana; requires --scope.")
@click.option("--content-discovery", is_flag=True, help="Authorized bounded directory discovery with ffuf; requires --scope.")
@click.option("--wordlist", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Approved ffuf wordlist; required with --content-discovery.")
@click.option("--sqli-detection", is_flag=True, help="Bounded SQLi detection from Katana GET candidates and approved raw requests.")
@click.option("--sqlmap-request", "sqlmap_requests", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Raw authorized HTTP request for SQLMap POST/JSON detection; repeatable.")
@click.option("--dast", is_flag=True, help="Run OWASP ZAP spider and active validation; requires scope permission.")
@click.option("--zap-api-url", default="http://zap:8080", show_default=True, envvar="ZAP_API_URL", help="OWASP ZAP daemon API URL.")
@click.option("--zap-ajax", is_flag=True, help="Add the browser-based ZAP AJAX spider; requires scope permission.")
@click.option("--auth-headers", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="JSON file of authorization/session headers; values are never written to reports.")
@click.option("--api-spec-url", help="Authorized in-scope OpenAPI definition URL imported into ZAP.")
@click.option("--source", "source_path", type=click.Path(exists=True, file_okay=False, path_type=Path), help="Authorized local source tree for SAST/SCA.")
@click.option("--sast", is_flag=True, help="Run Semgrep/Bandit against --source.")
@click.option("--sca", is_flag=True, help="Run Trivy/pip-audit dependency analysis against --source.")
@click.option("--anonymous-assessment", is_flag=True, help="Inspect anonymous auth/API exposure with safe HTTP methods; requires scope permission.")
@click.option("--rate-limit-check", is_flag=True, help="Add 3-10 low-rate HEAD requests; requires anonymous assessment and scope permission.")
@click.option("--compare", "compare_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Previous combined JSON report for change detection.")
@click.option("--tls-limit", default=2, type=int, show_default=True, help="Max https hosts to TLS-test with testssl.sh (0 = all; slower).")
@click.option("--selectors", default=None, help="Comma-separated DKIM selectors to probe (email phase).")
@click.option("--no-verify-cert", is_flag=True, help="Skip TLS certificate verification (email phase).")
@click.option("--all-sources", is_flag=True, help="Enable every subfinder OSINT source (slower).")
@click.option("--exact-host", is_flag=True, help="Skip Subfinder and restrict all downstream web tools to DOMAIN only.")
@click.option(
    "-sub", "--sub", "full_subdomain", is_flag=True,
    help="Run the complete authorized web/infrastructure suite against one exact subdomain.",
)
@click.option(
    "--resolvers", default=None,
    help="Optional comma-separated DNS resolvers for web tools; defaults to the system resolver.",
)
@click.option("--timeout", default=10.0, type=float, show_default=True, help="DNS/socket timeout (s).")
@click.option("--tls-timeout", default=15.0, type=float, show_default=True, help="TLS handshake timeout (s).")
@click.option(
    "-o", "--output", default=None, type=click.Path(path_type=Path),
    help="Write report to a file (inferred format from extension, default JSON).",
)
@click.option("--format", "fmt", default=None, type=click.Choice(["json", "html"]),
              help="Report format when using -o/--output.")
def scan_cmd(
    domain, profile, scope_path, active, no_email, no_web, with_ports, with_nmap, nmap_safe_scripts, nmap_vuln_authorized, with_nuclei, with_cves, cve_cache, dns_inventory, with_headers, with_crawl, content_discovery, wordlist, sqli_detection, sqlmap_requests, dast, zap_api_url, zap_ajax, auth_headers, api_spec_url, source_path, sast, sca, anonymous_assessment, rate_limit_check, compare_path, tls_limit,
    selectors, no_verify_cert, all_sources, exact_host, full_subdomain, resolvers, timeout, tls_timeout, output, fmt,
):
    """Assess both the email and web security posture of DOMAIN."""
    if full_subdomain:
        exact_host = True
        no_email = True
        active = True
        with_nmap = True
        nmap_safe_scripts = True
        dns_inventory = True
        with_headers = True
        with_crawl = True
        with_cves = True
        if profile == "standard":
            profile = "active-validation"
        if scope_path is None:
            scope_path = _automatic_scope(domain)
        if cve_cache is None:
            cve_cache = _automatic_report_dir() / ".cve-cache"
        if wordlist is None:
            wordlist = _automatic_wordlist()
        if wordlist is not None:
            content_discovery = True
        else:
            _warn("[!] No approved content-discovery wordlist found; ffuf will be skipped.")
        if output is None:
            output = _automatic_report_dir() / f"{domain}-full.html"

    include_email = not no_email
    include_web = not no_web
    full_active_bundle = active
    if not include_email and not include_web:
        _warn("[!] Both --no-email and --no-web given; nothing to do.")
        return
    if with_cves and not include_web:
        raise click.UsageError("--cves requires the web phase.")
    if with_cves and cve_cache is None:
        raise click.UsageError("--cves requires --cve-cache DIR so responses are cached locally.")
    if content_discovery and wordlist is None:
        raise click.UsageError("--content-discovery requires an approved --wordlist FILE.")
    if (sast or sca) and source_path is None:
        raise click.UsageError("--sast/--sca require --source DIR.")
    if api_spec_url and not dast:
        raise click.UsageError("--api-spec-url requires --dast.")
    if rate_limit_check and not anonymous_assessment:
        raise click.UsageError("--rate-limit-check requires --anonymous-assessment.")
    if exact_host and all_sources:
        _warn("[i] --exact-host skips Subfinder; --all-sources will be ignored.")
    try:
        request_headers = load_headers(auth_headers)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    with_nmap = with_nmap or nmap_safe_scripts or nmap_vuln_authorized
    requested_active = active or with_ports or with_nmap or with_nuclei or with_crawl or content_discovery or sqli_detection or bool(sqlmap_requests) or dast or anonymous_assessment or profile in ("active-authorized", "active-validation", "lab")
    if profile == "passive" and requested_active:
        raise click.UsageError("--profile passive cannot be combined with active modules.")
    if requested_active:
        if scope_path is None:
            suffix = " No unique local scope*.json authorizes this host." if full_subdomain else ""
            raise click.UsageError(
                "Active tests require --scope FILE with allow_active: true." + suffix
            )
        try:
            authorization = load_scope(scope_path)
        except (TypeError, ValueError) as exc:
            raise click.UsageError(str(exc)) from exc
        if not authorization.allow_active:
            raise click.UsageError("The selected scope does not set allow_active to true.")
        if not scope_allows(authorization, domain):
            raise click.UsageError(f"{domain} is not included in the selected authorization scope.")
        if full_subdomain:
            sqli_detection = authorization.allow_sqli_detection
            nmap_vuln_authorized = authorization.allow_nmap_vuln
            dast = authorization.allow_dast
            zap_ajax = authorization.allow_dast and authorization.allow_ajax_spider
            anonymous_assessment = authorization.allow_anonymous_assessment
            rate_limit_check = (
                authorization.allow_anonymous_assessment
                and authorization.allow_rate_limit_check
            )
        if api_spec_url:
            from urllib.parse import urlparse
            spec_host = urlparse(api_spec_url).hostname
            if not spec_host or not scope_allows(authorization, spec_host):
                raise click.UsageError("--api-spec-url must be HTTP(S) and inside the authorization scope.")
        if (sqli_detection or sqlmap_requests) and not authorization.allow_sqli_detection:
            raise click.UsageError("The selected scope does not set allow_sqli_detection to true.")
        for request_file in sqlmap_requests:
            request_host, _request_path = sqli.request_metadata(request_file)
            if not request_host or not scope_allows(authorization, request_host):
                raise click.UsageError(f"SQLMap request host is outside scope: {request_host or request_file}")
        if nmap_vuln_authorized and not authorization.allow_nmap_vuln:
            raise click.UsageError("The selected scope does not set allow_nmap_vuln to true.")
        if dast and not authorization.allow_dast:
            raise click.UsageError("The selected scope does not set allow_dast to true.")
        if zap_ajax and not authorization.allow_ajax_spider:
            raise click.UsageError("The selected scope does not set allow_ajax_spider to true.")
        if anonymous_assessment and not authorization.allow_anonymous_assessment:
            raise click.UsageError("The selected scope does not set allow_anonymous_assessment to true.")
        if rate_limit_check and not authorization.allow_rate_limit_check:
            raise click.UsageError("The selected scope does not set allow_rate_limit_check to true.")
        _warn(
            f"[!] {authorization.assessment_mode} mode: active probes may validate findings, "
            "but exploitation, persistence, data extraction and WAF evasion are never performed."
        )
    else:
        authorization = None

    mail_config = ScanConfig(
        domain=domain,
        active=full_active_bundle,
        timeout=timeout,
        tls_timeout=tls_timeout,
        verify_cert=not no_verify_cert,
    )
    if selectors:
        mail_config.dkim_selectors = [s.strip() for s in selectors.split(",") if s.strip()]

    started = time.monotonic()
    progress_console = Console(stderr=True)
    stage_started = started
    current_stage = "initializing"
    stage_labels = {
        "exact_host": "exact target preparation", "subdomains": "subdomain discovery (Subfinder)",
        "live_hosts": "HTTP service probing", "technology": "technology fingerprinting",
        "headers": "security header review", "dns_inventory": "DNS inventory", "tls": "TLS analysis",
        "crawl": "application crawling (Katana)", "anonymous_access": "anonymous access assessment",
        "content_discovery": "content discovery (ffuf)", "sqli": "SQL injection detection",
        "ports": "TCP port discovery (Naabu)", "nmap": "service validation (Nmap)",
        "vulns": "template matching (Nuclei)", "cves": "CVE enrichment", "dast": "DAST validation (ZAP)",
        "sast": "static analysis (Semgrep)", "sca": "dependency analysis (Trivy)",
        "correlation": "cross-engine correlation", "mail done": "email assessment complete",
    }
    with Progress(
        SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), BarColumn(),
        TaskProgressColumn(), TimeElapsedColumn(), TimeRemainingColumn(),
        TextColumn("[dim]{task.fields[target]}[/dim]"), console=progress_console, refresh_per_second=4,
    ) as progress:
        task_id = progress.add_task("initializing", total=100, target=domain)

        def on_progress(label: str, frac: float) -> None:
            nonlocal current_stage, stage_started
            now = time.monotonic()
            if label != current_stage and current_stage != "initializing":
                progress.console.print(f"[green]✓[/green] {stage_labels.get(current_stage, current_stage)} [dim]{now - stage_started:.1f}s[/dim]")
            if label != current_stage:
                current_stage = label
                stage_started = now
            progress.update(task_id, completed=min(99, frac * 100), description=stage_labels.get(label, label))

        combined = run_combined(
            domain,
            mail_config,
            include_email=include_email,
            include_web=include_web,
            on_progress=on_progress,
            active=full_active_bundle,
            tls_limit=tls_limit,
            ports_enabled=with_ports,
            nuclei_enabled=with_nuclei,
            extra_sources=all_sources,
            resolvers=resolvers,
            cve_enabled=with_cves,
            cve_cache=cve_cache,
            dns_inventory_enabled=dns_inventory,
            headers_enabled=with_headers,
            crawl_enabled=with_crawl,
            content_enabled=content_discovery,
            wordlist=wordlist,
            sqli_enabled=sqli_detection or bool(sqlmap_requests),
            sqli_exclude_paths=authorization.exclude_paths if authorization else (),
            sqli_max_targets=authorization.sqli_max_targets if authorization else 20,
            sqli_request_files=sqlmap_requests,
            nmap_enabled=with_nmap,
            nmap_safe_scripts=nmap_safe_scripts,
            nmap_vuln_scripts=nmap_vuln_authorized,
            dast_enabled=dast,
            zap_api_url=zap_api_url,
            dast_max_minutes=authorization.dast_max_minutes if authorization else 10,
            zap_ajax=zap_ajax,
            request_headers=request_headers,
            api_spec_url=api_spec_url,
            source_path=source_path,
            sast_enabled=sast,
            sca_enabled=sca,
            anonymous_enabled=anonymous_assessment,
            anonymous_max_targets=authorization.anonymous_max_targets if authorization else 80,
            rate_limit_check=rate_limit_check,
            rate_limit_requests=authorization.rate_limit_requests if authorization else 5,
            exact_host=exact_host,
        )
        combined.scan_profile = profile
        combined.scope_name = authorization.name if authorization else ""
        combined.assessment_mode = authorization.assessment_mode if authorization else "identification-only"
        combined.elapsed_seconds = time.monotonic() - started
        combined.target_mode = "exact-host" if exact_host else "domain-discovery"
        if compare_path:
            try:
                combined.comparison = build_comparison(json.loads(compare_path.read_text(encoding="utf-8")), combined.to_dict())
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise click.UsageError(f"cannot compare report: {exc}") from exc
        progress.console.print(f"[green]✓[/green] {stage_labels.get(current_stage, current_stage)} [dim]{time.monotonic() - stage_started:.1f}s[/dim]")
        progress.update(task_id, completed=100, description="assessment complete")

    combined_terminal.render_combined(combined)

    if output:
        fmt = fmt or (output.suffix.lstrip(".") if output.suffix else "json")
        output.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "html":
            combined_html.write(combined, output)
        else:
            combined_json.write(combined, output)
        click.echo(click.style(f"Report written to {output}", fg="green"))


@cli.command()
@click.option("--full", is_flag=True, help="Require every tool and bundled asset used by the complete image.")
def doctor(full):
    """Check local or containerized scan prerequisites without scanning a target."""
    click.echo(f"Platform: {platform.system()} {platform.release()}")
    click.echo("Python: " + platform.python_version())

    required = (
        "subfinder", "httpx", "whatweb", "testssl.sh", "hexdump", "ps", "dig",
        "naabu", "nuclei", "curl",
    )
    optional = ("katana", "ffuf", "sqlmap", "nmap", "semgrep", "bandit", "trivy", "pip-audit")
    missing: list[str] = []
    for binary in required:
        path = which(binary)
        if path:
            click.echo(click.style(f"OK      {binary:<12} {path}", fg="green"))
        else:
            missing.append(binary)
            click.echo(click.style(f"MISSING {binary}", fg="yellow"))
    for binary in optional:
        path = which(binary)
        if path:
            click.echo(click.style(f"OK      {binary:<12} {path} (optional module)", fg="green"))
        else:
            click.echo(click.style(f"OPTIONAL MISSING {binary}", fg="yellow"))
            if full:
                missing.append(binary)

    if full:
        assets = (
            Path("/opt/uncp-tools/wordlists/raft-medium-directories.txt"),
            Path("/opt/uncp-tools/nuclei-safe/http/technologies/tech-detect.yaml"),
            Path("/opt/uncp-tools/nuclei-safe/http/misconfiguration/http-missing-security-headers.yaml"),
            Path("/usr/share/nmap/scripts/vulners.nse"),
            Path("/opt/uncp-tools/scopes/scope.uncp.json"),
        )
        for asset in assets:
            if asset.is_file() and asset.stat().st_size > 0:
                click.echo(click.style(f"OK      asset        {asset}", fg="green"))
            else:
                click.echo(click.style(f"MISSING asset        {asset}", fg="yellow"))
                missing.append(str(asset))

    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        click.echo(click.style("Container engine: running inside a container", fg="green"))
    else:
        engines = [engine for engine in ("docker", "podman") if which(engine)]
        if engines:
            click.echo(click.style("Container engine: " + ", ".join(engines), fg="green"))
        else:
            click.echo(click.style("Container engine: missing (Docker or Podman)", fg="yellow"))

    if missing:
        click.echo(
            "Web tools are missing. Use the provided Containerfile/compose.yaml for the full "
            "reproducible environment, or install the missing tools natively."
        )
        raise click.exceptions.Exit(1)
    message = "Complete image prerequisites are available." if full else "Native web scan prerequisites are available."
    click.echo(click.style(message, fg="green"))


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
    """Convert a saved JSON scan report into HTML (combined or single-phase)."""
    payload = json.loads(input.read_text(encoding="utf-8"))
    fmt = fmt or (output.suffix.lstrip(".") if output.suffix else "html")
    output.parent.mkdir(parents=True, exist_ok=True)

    if "overall" in payload and "email" in payload and "web" in payload:
        if fmt == "html":
            combined_html.write(payload, output)
        else:
            combined_json.write(payload, output)
    else:
        # Single-phase MailSec-style report → re-use MailSec writers.
        from mailsec.reports import html_report, json_report

        if fmt == "html":
            html_report.write(payload, output)
        else:
            json_report.write(payload, output)
    click.echo(click.style(f"Report written to {output}", fg="green"))


if __name__ == "__main__":
    cli()
