"""Small, deterministic comparison of two combined scanner reports."""

from __future__ import annotations


def _web_values(payload: dict, key: str) -> set[str]:
    return {str(value) for value in (payload.get("web") or {}).get(key, [])}


def _hosts(payload: dict) -> set[str]:
    return {str(item.get("url")) for item in (payload.get("web") or {}).get("live_hosts", []) if item.get("url")}


def _cves(payload: dict) -> set[str]:
    return {str(cve.get("id")) for host in (payload.get("web") or {}).get("live_hosts", []) for cve in host.get("cves", []) if cve.get("id")}


def build(previous: dict, current: dict) -> dict[str, list[str]]:
    """Return added/removed assets and CVEs; input is saved combined JSON."""
    groups = {
        "subdomains": (_web_values(previous, "subdomains"), _web_values(current, "subdomains")),
        "live_hosts": (_hosts(previous), _hosts(current)),
        "cves": (_cves(previous), _cves(current)),
    }
    return {f"new_{name}": sorted(now - old) for name, (old, now) in groups.items()} | {f"removed_{name}": sorted(old - now) for name, (old, now) in groups.items()}
