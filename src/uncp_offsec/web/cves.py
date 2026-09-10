"""Optional NVD/CISA KEV enrichment for exact technology versions only."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from mailsec.models import Finding, ModuleResult, Severity

from ..models import HostInfo

MODULE_NAME = "cves"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CPE = {
    "nginx": "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
    "apache": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "apache_http_server": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
}


def _read(path: Path, ttl: int = 86_400) -> dict | None:
    try:
        if time.time() - path.stat().st_mtime <= ttl:
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _fetch(url: str, key: str = "") -> dict:
    headers = {"User-Agent": "uncp-offsec/0.2 CVE-enrichment"}
    if key:
        headers["apiKey"] = key
    with urlopen(Request(url, headers=headers), timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _sev(score: float) -> Severity:
    return Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM if score >= 4 else Severity.LOW


def _kev(cache: Path) -> set[str]:
    path = cache / "cisa-kev.json"
    payload = _read(path)
    if payload is None:
        payload = _fetch(KEV_URL)
        _write(path, payload)
    return {str(item["cveID"]) for item in payload.get("vulnerabilities", []) if item.get("cveID")}


def _rows(payload: dict, kev: set[str]) -> list[dict]:
    rows = []
    for item in payload.get("vulnerabilities", [])[:50]:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        metrics = cve.get("metrics") or {}
        metric = next(iter(metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []), {})
        score = float((metric.get("cvssData") or {}).get("baseScore") or 0)
        rows.append({"id": cve_id, "score": score, "severity": _sev(score).value, "kev": cve_id in kev, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
    return rows


def _group_matches(hosts: list[HostInfo]) -> list[dict]:
    """Group identical version correlations while retaining affected assets."""
    grouped: dict[tuple[str, str, str], dict] = {}
    for host in hosts:
        for cve in host.cves:
            group_key = (cve["id"], cve["product"], cve["version"])
            grouped.setdefault(group_key, {**cve, "hosts": set()})["hosts"].add(host.host)
    return list(grouped.values())


def run(hosts: list[HostInfo], *, cache_dir: Path) -> ModuleResult:
    """Look up only CPEs created from explicit versions; unknown versions are skipped."""
    result = ModuleResult(name=MODULE_NAME, max_score=0.0)
    candidates = []
    for host in hosts:
        for product, version in host.tech_versions.items():
            template = _CPE.get(product.lower().replace(" ", "_"))
            if template and version:
                candidates.append((host, product, version, template.format(version=version)))
    if not candidates:
        result.assessed = False
        result.findings.append(Finding(module=MODULE_NAME, severity=Severity.INFO, title="No exact version fingerprints for CVE lookup", detail="Skipped to avoid CVE matches from a product name alone.", recommendation="Expose exact authorized versions or use asset inventory data."))
        return result
    try:
        kev = _kev(cache_dir)
        key = os.environ.get("NVD_API_KEY", "")
        by_cpe: dict[str, list[tuple[HostInfo, str, str]]] = {}
        for host, product, version, cpe in candidates:
            by_cpe.setdefault(cpe, []).append((host, product, version))
        for cpe, assets in list(by_cpe.items())[:20]:
            path = cache_dir / f"nvd-{hashlib.sha256(cpe.encode()).hexdigest()}.json"
            payload = _read(path)
            if payload is None:
                payload = _fetch(f"{NVD_URL}?{urlencode({'cpeName': cpe})}", key)
                _write(path, payload)
            rows = _rows(payload, kev)
            for host, product, version in assets:
                host.cves.extend([{**row, "product": product, "version": version} for row in rows])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result.assessed = False
        result.findings.append(Finding(module=MODULE_NAME, severity=Severity.INFO, title="CVE enrichment unavailable", detail=str(exc)[:300], recommendation="Retry later or set NVD_API_KEY in the environment."))
        return result
    matches = _group_matches(hosts)
    result.assessed = True
    if not matches:
        result.findings.append(Finding(module=MODULE_NAME, severity=Severity.PASS, title="No NVD CVEs matched exact fingerprints", detail=f"Queried {len(candidates)} exact product/version fingerprint(s).", recommendation=""))
        return result
    for cve in sorted(matches, key=lambda item: (not item["kev"], -item["score"], item["id"]))[:100]:
        severity = Severity.CRITICAL if cve["kev"] else Severity(cve["severity"])
        affected_hosts = sorted(cve["hosts"])
        detail = (
            f"CVSS: {cve['score']:.1f}\nNVD: {cve['url']}\nMatch: exact CPE\n"
            f"Assets ({len(affected_hosts)}): {', '.join(affected_hosts[:25])}\n"
            "Status: version-correlated only. Required modules, operating system, configuration "
            "and reachability were not confirmed."
        )
        if cve["kev"]:
            detail += "\nCISA KEV: known exploited vulnerability"
        result.findings.append(Finding(module=MODULE_NAME, severity=severity, title=f"Potential exposure: {cve['id']} on {cve['product']} {cve['version']}", detail=detail, recommendation="Confirm the server-side package and affected configuration, then patch or mitigate using the vendor advisory.", confidence="MEDIUM", verification_status="VERSION_CORRELATED", occurrence_count=len(affected_hosts), cve_ids=[cve["id"]], owasp_categories=["A03:2025"]))
    return result
