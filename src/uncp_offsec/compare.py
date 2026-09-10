"""Deterministic comparison of combined scanner reports."""

from __future__ import annotations


def _subdomains(report: dict) -> set[str]:
    return {str(value) for value in (report.get("web") or {}).get("subdomains", [])}


def _hosts(report: dict) -> set[str]:
    return {str(item.get("url")) for item in (report.get("web") or {}).get("live_hosts", []) if item.get("url")}


def _cves(report: dict) -> set[str]:
    return {str(cve.get("id")) for host in (report.get("web") or {}).get("live_hosts", []) for cve in host.get("cves", []) if cve.get("id")}


def build(previous: dict, current: dict) -> dict[str, list[str]]:
    groups = {"subdomains": (_subdomains(previous), _subdomains(current)), "live_hosts": (_hosts(previous), _hosts(current)), "cves": (_cves(previous), _cves(current))}
    return {f"new_{name}": sorted(now - old) for name, (old, now) in groups.items()} | {f"removed_{name}": sorted(old - now) for name, (old, now) in groups.items()}
