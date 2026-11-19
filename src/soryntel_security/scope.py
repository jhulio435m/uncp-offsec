"""Explicit authorization scope for active assessment modules."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuthorizationScope:
    """Domain boundaries and active-test authorization read from JSON."""

    name: str
    domains: tuple[str, ...]
    assessment_mode: str = "identification-only"
    allow_active: bool = False
    allow_sqli_detection: bool = False
    allow_nmap_vuln: bool = False
    allow_dast: bool = False
    allow_ajax_spider: bool = False
    allow_anonymous_assessment: bool = False
    allow_rate_limit_check: bool = False
    dast_max_minutes: int = 10
    sqli_max_targets: int = 20
    anonymous_max_targets: int = 80
    rate_limit_requests: int = 5
    exclude_paths: tuple[str, ...] = ()
    # Private ranges the internal-network mode may assess, and the most
    # addresses one run may cover.
    networks: tuple[str, ...] = ()
    network_max_hosts: int = 256


def _normal_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


# A scope may not authorize a whole private class in one line.
MIN_PREFIX = {4: 16, 6: 64}


def _networks(raw: object) -> tuple[str, ...]:
    """Validate the 'networks' list: private CIDR ranges of a bounded size."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError("'networks' must be a list of CIDR strings")
    networks = []
    for item in raw:
        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid network '{item}' in scope: {exc}") from exc
        if not network.is_private:
            raise ValueError(f"network {network} is public; 'networks' only accepts private ranges")
        if network.prefixlen < MIN_PREFIX[network.version]:
            raise ValueError(f"network {network} is too broad; use /{MIN_PREFIX[network.version]} or narrower")
        networks.append(str(network))
    return tuple(sorted(set(networks)))


def load(path: Path) -> AuthorizationScope:
    """Load a small, dependency-free JSON authorization file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read scope file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise TypeError("scope file must contain a JSON object")
    networks = _networks(raw.get("networks"))
    domains = raw.get("domains", [] if networks else None)
    if not isinstance(domains, list) or not all(isinstance(x, str) for x in domains) or not (domains or networks):
        raise ValueError("scope file needs a non-empty 'domains' string list")
    normalized = tuple(sorted({_normal_domain(value) for value in domains if _normal_domain(value)}))
    if not normalized and not networks:
        raise ValueError("scope file needs at least one non-empty domain")
    assessment_mode = str(raw.get("assessment_mode", "identification-only"))
    supported_modes = ("identification-only", "active-validation")
    if assessment_mode not in supported_modes:
        raise ValueError(
            "assessment_mode must be 'identification-only' or 'active-validation'; "
            "exploitation is not supported"
        )
    forbidden = ("allow_exploitation", "allow_persistence", "allow_data_extraction", "allow_evasion")
    enabled_forbidden = [key for key in forbidden if raw.get(key) is True]
    if enabled_forbidden:
        raise ValueError(f"unsupported unsafe scope permission(s): {', '.join(enabled_forbidden)}")
    return AuthorizationScope(
        name=str(raw.get("name") or path.stem),
        domains=normalized,
        assessment_mode=assessment_mode,
        allow_active=raw.get("allow_active") is True,
        allow_sqli_detection=raw.get("allow_sqli_detection") is True,
        allow_nmap_vuln=raw.get("allow_nmap_vuln") is True,
        allow_dast=raw.get("allow_dast") is True,
        allow_ajax_spider=raw.get("allow_ajax_spider") is True,
        allow_anonymous_assessment=raw.get("allow_anonymous_assessment") is True,
        allow_rate_limit_check=raw.get("allow_rate_limit_check") is True,
        dast_max_minutes=max(1, min(int(raw.get("dast_max_minutes", 10)), 60)),
        sqli_max_targets=max(1, min(int(raw.get("sqli_max_targets", 20)), 50)),
        anonymous_max_targets=max(1, min(int(raw.get("anonymous_max_targets", 80)), 200)),
        rate_limit_requests=max(3, min(int(raw.get("rate_limit_requests", 5)), 10)),
        exclude_paths=tuple(str(item) for item in raw.get("exclude_paths", []) if isinstance(item, str)),
        networks=networks,
        network_max_hosts=max(1, min(int(raw.get("network_max_hosts", 256)), 4096)),
    )


def allows(scope: AuthorizationScope, target: str) -> bool:
    """Return whether target is an explicitly allowed domain or its subdomain."""
    target = _normal_domain(target)
    return any(target == domain or target.endswith(f".{domain}") for domain in scope.domains)


def allows_ip(scope: AuthorizationScope, address: str) -> bool:
    """Return whether address falls inside one of the scope's authorized networks."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip.version == network.version and ip in network for network in map(ipaddress.ip_network, scope.networks))
