"""OWASP ZAP spider and active validation through its local daemon API."""

from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo

MODULE_NAME = "dast"

_RISK = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

_RISK_NAME = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def alert_severity(alert: dict) -> Severity:
    """Accept both the Core API's risk name and report-style risk code."""
    code = alert.get("riskcode", alert.get("riskCode"))
    if code is not None:
        return _RISK.get(str(code), Severity.INFO)
    return _RISK_NAME.get(str(alert.get("risk") or "").lower(), Severity.INFO)


def _api(base: str, path: str, params: dict[str, str] | None = None, timeout: float = 20) -> dict:
    query = f"?{urlencode(params or {})}" if params else ""
    request = Request(f"{base.rstrip('/')}{path}{query}", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise OSError(f"ZAP API {path} returned HTTP {exc.code}: {body}") from exc


def _wait_percent(base: str, component: str, scan_id: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        payload = _api(base, f"/JSON/{component}/view/status/", {"scanId": scan_id})
        if int(payload.get("status", 0)) >= 100:
            return True
        time.sleep(2)
    return False


def _wait_ajax(base: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        status = str(_api(base, "/JSON/ajaxSpider/view/status/").get("status", "")).lower()
        if status == "stopped":
            return True
        time.sleep(2)
    return False


def _detail(alert: dict) -> str:
    fields = [
        ("URL", alert.get("url")),
        ("Method", alert.get("method")),
        ("Parameter", alert.get("param")),
        ("Attack", alert.get("attack")),
        ("Evidence", alert.get("evidence")),
        ("Confidence", alert.get("confidence")),
        ("CWE", alert.get("cweid")),
        ("WASC", alert.get("wascid")),
        ("Reference", alert.get("reference")),
    ]
    return "\n".join(f"{label}: {value}" for label, value in fields if value)


def _alerts(base: str, target: str, limit: int = 2000) -> list[dict]:
    rows: list[dict] = []
    page_size = 500
    while len(rows) < limit:
        payload = _api(
            base,
            "/JSON/core/view/alerts/",
            {"baseurl": target, "start": str(len(rows)), "count": str(page_size)},
        )
        page = payload.get("alerts") or []
        rows.extend(page)
        if len(page) < page_size:
            break
    return rows[:limit]


def parse_alerts(alerts: list[dict]) -> list[Finding]:
    """Consolidate alert instances by rule while retaining reproducible samples."""
    findings: list[Finding] = []
    groups: dict[tuple[str, str], list[dict]] = {}
    for alert in alerts:
        if str(alert.get("confidence", "")).lower() == "false positive":
            continue
        key = (str(alert.get("pluginId") or alert.get("alertRef") or ""), str(alert.get("name") or alert.get("alert") or "ZAP alert"))
        groups.setdefault(key, []).append(alert)
    for (_plugin_id, title), instances in groups.items():
        alert = max(instances, key=lambda item: alert_severity(item).weight * -1)
        confidence = str(alert.get("confidence") or "Low").upper()
        evidence = str(alert.get("evidence") or "").strip()
        verification = "POTENTIAL"
        if confidence in ("HIGH", "CONFIRMED") and evidence:
            verification = "PROBABLE"
        samples = []
        seen_instances: set[tuple[str, str, str, str]] = set()
        for instance in instances:
            identity = tuple(str(instance.get(field) or "") for field in ("url", "method", "param", "attack"))
            if identity in seen_instances:
                continue
            seen_instances.add(identity)
            if len(samples) < 20:
                samples.append(_detail(instance))
        cwe = str(alert.get("cweid") or "")
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity=alert_severity(alert),
                title=title,
                detail=f"Occurrences: {len(seen_instances)}\n\n" + "\n\n--- sample ---\n".join(samples),
                recommendation=str(alert.get("solution") or "Review and remediate the affected endpoint."),
                rfc_ref=f"CWE-{cwe}" if cwe.isdigit() else "",
                confidence=confidence,
                verification_status=verification,
                occurrence_count=len(seen_instances),
            )
        )
    return findings


def _configure_headers(base: str, target: str, headers: dict[str, str]) -> list[str]:
    """Inject caller-provided session headers only for the current target origin."""
    url_regex = re.escape(target.rstrip("/")) + ".*"
    descriptions = []
    target_id = hashlib.sha256(target.encode()).hexdigest()[:10]
    for index, (name, value) in enumerate(headers.items()):
        description = f"uncp-auth-{target_id}-{index}"
        _api(base, "/JSON/replacer/action/addRule/", {
            "description": description, "enabled": "true", "matchType": "REQ_HEADER",
            "matchRegex": "false", "matchString": name, "replacement": value,
            "initiators": "", "url": url_regex,
        })
        descriptions.append(description)
    return descriptions


def run(
    hosts: list[HostInfo],
    *,
    api_url: str,
    max_minutes: int = 10,
    ajax: bool = False,
    active: bool = True,
    excluded_paths: tuple[str, ...] = (),
    seed_urls: tuple[str, ...] = (),
    request_headers: dict[str, str] | None = None,
    api_spec_url: str | None = None,
) -> ModuleResult:
    """Spider approved hosts and optionally perform ZAP active validation."""
    result = ModuleResult(name=MODULE_NAME, max_score=20.0)
    if not hosts:
        result.assessed = False
        result.findings.append(
            Finding(MODULE_NAME, Severity.INFO, "No hosts for DAST", "No live HTTP targets.", "")
        )
        return result

    total_seconds = max(1, max_minutes) * 60
    deadline = time.monotonic() + total_seconds
    completed = True
    all_alerts: list[dict] = []
    seeded = 0
    rejected_seeds = 0
    configured_rules: list[str] = []
    stage = "initializing a clean ZAP session"
    try:
        _api(
            api_url,
            "/JSON/core/action/newSession/",
            {"name": "", "overwrite": "true"},
            timeout=60,
        )
        for host in hosts[:5]:
            target = host.url.rstrip("/") + "/"
            stage = f"preparing {target}"
            if request_headers:
                configured_rules.extend(_configure_headers(api_url, target, request_headers))
            if api_spec_url:
                _api(api_url, "/JSON/openapi/action/importUrl/", {"url": api_spec_url, "hostOverride": ""}, timeout=60)
            for path in excluded_paths:
                regex = re.escape(host.url.rstrip("/") + "/" + path.lstrip("/")) + ".*"
                _api(api_url, "/JSON/spider/action/excludeFromScan/", {"regex": regex})
                _api(api_url, "/JSON/ascan/action/excludeFromScan/", {"regex": regex})
            _api(api_url, "/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
            for seed in seed_urls[:200]:
                parsed = urlparse(seed)
                if parsed.hostname != host.host:
                    continue
                if any(parsed.path.startswith(path) for path in excluded_paths):
                    continue
                try:
                    _api(
                        api_url,
                        "/JSON/core/action/accessUrl/",
                        {"url": seed, "followRedirects": "true"},
                    )
                    seeded += 1
                except OSError:
                    rejected_seeds += 1
            stage = f"spidering {target}"
            spider = _api(
                api_url,
                "/JSON/spider/action/scan/",
                {"url": target, "maxChildren": "200", "recurse": "true", "subtreeOnly": "true"},
            )
            spider_deadline = min(deadline, time.monotonic() + max(30, total_seconds * 0.2))
            spider_done = _wait_percent(api_url, "spider", str(spider["scan"]), spider_deadline)
            if not spider_done:
                _api(api_url, "/JSON/spider/action/stop/", {"scanId": str(spider["scan"])})
            completed = spider_done and completed
            if ajax and time.monotonic() < deadline:
                stage = f"running AJAX spider on {target}"
                _api(
                    api_url,
                    "/JSON/ajaxSpider/action/scan/",
                    {"url": target, "inScope": "false", "subtreeOnly": "true"},
                )
                ajax_deadline = min(deadline, time.monotonic() + max(60, total_seconds * 0.3))
                ajax_done = _wait_ajax(api_url, ajax_deadline)
                if not ajax_done:
                    _api(api_url, "/JSON/ajaxSpider/action/stop/")
                completed = ajax_done and completed
            if active and time.monotonic() < deadline:
                stage = f"running active validation on {target}"
                scan = _api(
                    api_url,
                    "/JSON/ascan/action/scan/",
                    {"url": target, "recurse": "true", "inScopeOnly": "false"},
                )
                active_done = _wait_percent(api_url, "ascan", str(scan["scan"]), deadline)
                if not active_done:
                    _api(api_url, "/JSON/ascan/action/stop/", {"scanId": str(scan["scan"])})
                completed = active_done and completed
            stage = f"collecting alerts for {target}"
            all_alerts.extend(_alerts(api_url, target))
            if time.monotonic() >= deadline:
                completed = False
                break
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        result.assessed = False
        result.findings.append(
            Finding(
                MODULE_NAME,
                Severity.INFO,
                "OWASP ZAP coverage incomplete",
                f"Failed while {stage}: {exc}"[:500],
                "Start the ZAP daemon declared in compose.yaml and retry the authorized scan.",
            )
        )
        return result
    finally:
        for description in configured_rules:
            try:
                _api(api_url, "/JSON/replacer/action/removeRule/", {"description": description})
            except OSError:
                pass

    result.assessed = completed
    parsed = parse_alerts(all_alerts)
    result.findings.extend(parsed)
    if not parsed:
        result.findings.append(
            Finding(
                MODULE_NAME,
                Severity.PASS if completed else Severity.INFO,
                "No ZAP alerts" if completed else "ZAP coverage incomplete",
                f"DAST completed={completed}; hosts={min(len(hosts), 5)}.",
                "Increase the authorized DAST time window when coverage is incomplete.",
            )
        )
    result.findings.append(
        Finding(
            MODULE_NAME,
            Severity.INFO,
            f"ZAP seeded {seeded} discovered URL(s)",
            "Katana discoveries were imported into the ZAP site tree before active validation."
            f" Rejected malformed/unreachable seeds: {rejected_seeds}.",
            "",
        )
    )
    if not completed:
        result.findings.append(
            Finding(
                MODULE_NAME,
                Severity.LOW,
                "ZAP coverage incomplete",
                f"The authorized {max_minutes}-minute DAST deadline was reached.",
                "Increase the time window or reduce the target set.",
            )
        )
    return result
