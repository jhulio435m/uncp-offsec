"""Scan orchestrators: email (reuses MailSec), web (external tools), combined."""

from __future__ import annotations

from collections.abc import Callable

from mailsec.constants import RISK_THRESHOLDS
from mailsec.models import Finding, ModuleResult, ScanConfig, Severity
from mailsec.scanner import scan as mail_scan

from .models import CombinedScanResult, HostInfo, WebScanResult
from .web import (
    anonymous,
    content,
    correlation,
    cves,
    discovery,
    dns_inventory,
    headers,
    nmap,
    ports,
    probe,
    sqli,
    static_analysis,
    tech,
    tls,
    vulns,
    zap,
)
from .web.owasp import coverage as owasp_coverage
from .web.scoring import compute_coverage, compute_web_score
from .web.tools import which

WEB_MODULE_ORDER = ["subdomains", "live_hosts", "technology", "headers", "dns_inventory", "crawl", "anonymous_access", "content_discovery", "sqli", "tls", "ports", "nmap", "vulns", "cves", "dast", "sast", "sca", "correlation"]


def _scale_progress(
    callback: Callable[[str, float], None] | None,
    start: float,
    span: float,
) -> Callable[[str, float], None] | None:
    """Return a progress callback that maps a phase-local fraction into [start, start+span]."""
    if callback is None or span <= 0.0:
        return None
    return lambda label, frac: callback(label, start + span * frac)


def _risk_level(total: float) -> str:
    for lo, hi, label in RISK_THRESHOLDS:
        if lo <= total <= hi:
            return label
    return "UNKNOWN"


def _not_assessed(name: str, title: str, detail: str, recommendation: str) -> ModuleResult:
    mr = ModuleResult(name=name, score_contribution=0.0, max_score=40.0)
    mr.assessed = False
    mr.findings.append(
        Finding(
            module=name,
            severity=Severity.INFO,
            title=title,
            detail=detail,
            recommendation=recommendation,
        )
    )
    return mr


def _exact_host_result(domain: str) -> tuple[ModuleResult, list[str]]:
    """Represent an intentionally skipped discovery phase without claiming security."""
    result = ModuleResult(name="subdomains")
    result.findings.append(Finding(
        module="subdomains", severity=Severity.INFO,
        title="Exact-host mode: subdomain discovery skipped",
        detail=f"Only {domain} was supplied to downstream web, port and DAST modules.",
        recommendation="Run without --exact-host when organization-wide asset discovery is required.",
        confidence="HIGH", verification_status="CONFIGURED",
    ))
    return result, []


def run_mail(domain: str, config: ScanConfig, on_progress: Callable[[str, float], None] | None = None):
    """Run the MailSec scan and return the ScanResult object."""
    return mail_scan(domain, config, on_progress=on_progress)


def run_tls(
    domain: str, hosts: list[HostInfo], tls_limit: int = 4,
    tool_timeout: float | None = 150.0,
) -> ModuleResult:
    """Run testssl.sh per https host; returns a tls ModuleResult."""
    https_hosts = [h for h in hosts if h.scheme == "https"]
    if not which("testssl.sh"):
        return _not_assessed(
            "tls",
            "testssl.sh not available",
            "TLS analysis skipped: testssl.sh not found on PATH.",
            "Install testssl.sh: git clone https://github.com/drwetter/testssl.sh",
        )
    if not https_hosts:
        return _not_assessed(
            "tls",
            "No HTTPS hosts",
            "No https:// endpoint discovered to run testssl.sh against.",
            "",
        )
    def priority(h: HostInfo) -> int:
        if h.host == domain:
            return 0
        if h.host in (f"www.{domain}",) or h.host.startswith(f"www.{domain}."):
            return 1
        return 2

    scanned = sorted(https_hosts, key=lambda h: (priority(h), len(h.host), h.host))[:tls_limit] if tls_limit else https_hosts
    mr = ModuleResult(name="tls", score_contribution=0.0, max_score=40.0)
    mr.assessed = True
    findings: list[Finding] = []
    protocols: list[str] = []
    for host in scanned:
        f, p = tls.analyze_host(host.host, timeout=tool_timeout)
        findings.extend(f)
        protocols.extend(p)
    if not findings:
        findings.append(
            Finding(
                module="tls",
                severity=Severity.PASS,
                title=f"TLS posture clean on {len(scanned)} host(s)",
                detail=(
                    ", ".join(sorted(set(protocols))) + " offered"
                    if protocols else "No protocol or certificate issues reported by testssl.sh."
                ),
                recommendation="",
            )
        )
    mr.findings = findings
    return mr


def run_web(
    domain: str,
    *,
    active: bool = False,
    tls_limit: int = 4,
    timeout: float = 60.0,
    ports_enabled: bool = False,
    nuclei_enabled: bool = False,
    extra_sources: bool = False,
    resolvers: str | None = None,
    cve_enabled: bool = False,
    cve_cache=None,
    dns_inventory_enabled: bool = False,
    headers_enabled: bool = False,
    crawl_enabled: bool = False,
    content_enabled: bool = False,
    wordlist=None,
    sqli_enabled: bool = False,
    sqli_exclude_paths: tuple[str, ...] = (),
    sqli_max_targets: int = 20,
    sqli_request_files: tuple = (),
    nmap_enabled: bool = False,
    nmap_safe_scripts: bool = False,
    nmap_vuln_scripts: bool = False,
    dast_enabled: bool = False,
    zap_api_url: str = "http://zap:8080",
    dast_max_minutes: int = 10,
    zap_ajax: bool = False,
    request_headers: dict[str, str] | None = None,
    api_spec_url: str | None = None,
    source_path=None,
    sast_enabled: bool = False,
    sca_enabled: bool = False,
    anonymous_enabled: bool = False,
    anonymous_max_targets: int = 80,
    rate_limit_check: bool = False,
    rate_limit_requests: int = 5,
    on_progress: Callable[[str, float], None] | None = None,
    exact_host: bool = False,
    unlimited_tool_time: bool = False,
) -> WebScanResult:
    """Run the full web recon pipeline against a domain."""
    do_ports = active or ports_enabled
    do_nuclei = active or nuclei_enabled

    steps: list[str] = ["exact_host" if exact_host else "subdomains", "live_hosts", "technology"]
    if headers_enabled:
        steps.append("headers")
    if dns_inventory_enabled:
        steps.append("dns_inventory")
    steps.append("tls")
    if crawl_enabled or sqli_enabled or anonymous_enabled:
        steps.append("crawl")
    if anonymous_enabled:
        steps.append("anonymous_access")
    if content_enabled:
        steps.append("content_discovery")
    if sqli_enabled:
        steps.append("sqli")
    if do_ports:
        steps.append("ports")
    if nmap_enabled:
        steps.append("nmap")
    if do_nuclei:
        steps.append("vulns")
    if cve_enabled:
        steps.append("cves")
    if dast_enabled:
        steps.append("dast")
    if sast_enabled:
        steps.append("sast")
    if sca_enabled:
        steps.append("sca")
    steps.append("correlation")
    total_steps = len(steps)
    pos = 0

    def tick(label: str) -> None:
        nonlocal pos
        if on_progress is not None:
            on_progress(label, pos / total_steps)
        pos += 1

    tick("exact_host" if exact_host else "subdomains")
    if exact_host:
        disc_mr, subdomains = _exact_host_result(domain)
    else:
        disc_mr, subdomains = discovery.run(
            domain, timeout=120.0 if extra_sources else 60.0, extra_sources=extra_sources, resolvers=resolvers
        )
    tick("live_hosts")
    probe_mr, hosts = probe.run(domain, subdomains, timeout=timeout, resolvers=resolvers)
    tick("technology")
    tech_mr = tech.run(hosts, timeout=90.0)
    if headers_enabled:
        tick("headers")
        headers_mr = headers.run(hosts)
    else:
        headers_mr = None
    if dns_inventory_enabled:
        tick("dns_inventory")
        dns_mr, dns_records = dns_inventory.run(domain, subdomains)
    else:
        dns_mr, dns_records = None, {}
    tick("tls")
    tool_timeout = None if unlimited_tool_time else 180.0
    tls_mr = run_tls(
        domain, hosts, tls_limit=tls_limit,
        tool_timeout=None if unlimited_tool_time else 150.0,
    )

    modules: dict[str, ModuleResult] = {
        "subdomains": disc_mr,
        "live_hosts": probe_mr,
        "technology": tech_mr,
        "tls": tls_mr,
    }
    if headers_mr:
        modules["headers"] = headers_mr
    if dns_mr:
        modules["dns_inventory"] = dns_mr
    crawled_urls: list[str] = []
    if crawl_enabled or sqli_enabled or anonymous_enabled:
        tick("crawl")
        modules["crawl"], crawled_urls = content.crawl(
            hosts, headers=request_headers or {}, timeout=tool_timeout,
        )
    coverage_metrics = anonymous.classify(crawled_urls)
    if anonymous_enabled:
        tick("anonymous_access")
        modules["anonymous_access"], coverage_metrics = anonymous.run(
            crawled_urls, allowed_hosts={host.host for host in hosts},
            excluded_paths=sqli_exclude_paths, limit=anonymous_max_targets,
            rate_limit_check=rate_limit_check, rate_limit_requests=rate_limit_requests,
        )
    if content_enabled:
        tick("content_discovery")
        modules["content_discovery"] = content.directories(
            hosts, wordlist=wordlist, headers=request_headers or {}, timeout=tool_timeout,
        )
    if sqli_enabled:
        tick("sqli")
        modules["sqli"] = sqli.run(crawled_urls, excluded_paths=sqli_exclude_paths, limit=sqli_max_targets, request_files=sqli_request_files, headers=request_headers or {})
    if do_ports:
        tick("ports")
        modules["ports"] = ports.run(
            hosts, timeout=None if unlimited_tool_time else 300.0, resolvers=resolvers,
        )
    if nmap_enabled:
        tick("nmap")
        modules["nmap"] = nmap.run(
            getattr(modules.get("ports"), "open_ports", []),
            safe_scripts=nmap_safe_scripts, vuln_scripts=nmap_vuln_scripts,
            timeout=None if unlimited_tool_time else 120.0,
        )
    if do_nuclei:
        tick("vulns")
        modules["vulns"] = vulns.run(
            hosts, timeout=None if unlimited_tool_time else 900.0,
            resolvers=resolvers, headers=request_headers or {},
        )
    if cve_enabled:
        tick("cves")
        modules["cves"] = cves.run(hosts, cache_dir=cve_cache)
    if dast_enabled:
        tick("dast")
        modules["dast"] = zap.run(
            hosts,
            api_url=zap_api_url,
            max_minutes=dast_max_minutes,
            ajax=zap_ajax,
            active=True,
            excluded_paths=sqli_exclude_paths,
            seed_urls=tuple(crawled_urls),
            request_headers=request_headers or {},
            api_spec_url=api_spec_url,
        )
    if sast_enabled:
        tick("sast")
        modules["sast"] = static_analysis.sast(source_path)
    if sca_enabled:
        tick("sca")
        modules["sca"] = static_analysis.sca(source_path)
    tick("correlation")
    modules["correlation"] = correlation.run(modules)

    breakdown = compute_web_score(modules)
    coverage = compute_coverage(modules)
    # Risk and coverage answer different questions. The score classifies the
    # observed evidence; coverage/confidence states how complete that evidence
    # is. Do not erase a useful risk rating merely because optional engines did
    # not run.
    risk_level = breakdown.risk_level
    confidence = "HIGH" if coverage >= 90 else "MEDIUM" if coverage >= 70 else "LOW"

    result = WebScanResult(
        domain=domain,
        modules=[m for n in WEB_MODULE_ORDER if (m := modules.get(n))],
        total_score=breakdown.total,
        risk_level=risk_level,
        coverage_score=coverage,
        confidence=confidence,
        subdomains=subdomains,
        live_hosts=hosts,
        dns_records=dns_records,
        owasp_coverage=owasp_coverage(modules, authenticated=bool(request_headers)),
        authenticated=bool(request_headers),
        coverage_metrics=coverage_metrics,
        target_mode="exact-host" if exact_host else "domain-discovery",
    )
    result.breakdown = breakdown  # type: ignore[attr-defined]
    return result


def run_combined(
    domain: str,
    mail_config: ScanConfig,
    *,
    include_email: bool = True,
    include_web: bool = True,
    on_progress: Callable[[str, float], None] | None = None,
    **web_kwargs,
) -> CombinedScanResult:
    """Run email + web phases and aggregate an overall score."""
    if on_progress is None:
        email_progress = None
        web_progress = None
    else:
        email_span = 0.35 if include_email and include_web else (1.0 if include_email else 0.0)
        web_span = 0.65 if include_web and include_email else (1.0 if include_web else 0.0)
        email_progress = _scale_progress(on_progress, 0.0, email_span)
        web_progress = _scale_progress(on_progress, email_span, web_span)

    email = run_mail(domain, mail_config, on_progress=email_progress) if include_email else None
    web_result = run_web(domain, on_progress=web_progress, **web_kwargs) if include_web else None

    if email is not None and web_result is not None:
        overall = round((float(email.total_score) + float(web_result.total_score)) / 2.0, 1)
    elif email is not None:
        overall = round(float(email.total_score), 1)
    elif web_result is not None:
        overall = round(float(web_result.total_score), 1)
    else:
        overall = 0.0

    combined = CombinedScanResult(domain=domain)
    combined.overall_score = overall
    combined.overall_risk = _risk_level(overall) if email is not None or web_result is not None else "INCONCLUSIVE"
    combined.email = email
    combined.web = web_result
    combined.email_modules = len(email.modules) if email is not None else 0
    combined.web_modules = len(web_result.modules) if web_result is not None else 0
    return combined
