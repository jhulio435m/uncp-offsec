"""What is already public about a domain, read from free third-party sources.

Passive by design: nothing here touches the organisation's own systems. It asks
public DNS which look-alike domains are registered and reads what Certificate
Transparency logs, Shodan's InternetDB, Have I Been Pwned and (with an API key)
Google Safe Browsing already publish. Every finding says which source said so;
none of it is validated against the target.
"""

from __future__ import annotations

import json
import os
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from urllib.request import Request, urlopen

import dns.exception
import dns.resolver

from mailsec.models import Finding, ModuleResult, Severity

MODULE_NAME = "exposure"
USER_AGENT = "soryntel-security/0.4 exposure-check"
MAX_LOOKALIKES = 400
THIRD_PARTY = "THIRD_PARTY_REPORTED"

# Keys next to each other on a QWERTY keyboard: the usual slip of a finger.
_ADJACENT = {
    "a": "qs", "b": "vn", "c": "xv", "d": "sf", "e": "wr", "f": "dg", "g": "fh", "h": "gj", "i": "uo",
    "j": "hk", "k": "jl", "l": "k", "m": "n", "n": "bm", "o": "ip", "p": "o", "q": "wa", "r": "et",
    "s": "ad", "t": "ry", "u": "yi", "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "x",
}
# Characters that read alike at a glance.
_LOOKALIKE = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv", "g": "q"}
_TLDS = ("com", "net", "org", "pe", "com.pe", "co", "info", "online", "app", "io")
_SENSITIVE = ("vpn", "admin", "intranet", "internal", "dev", "test", "staging", "stage", "qa", "backup",
              "db", "sql", "git", "jenkins", "jira", "erp", "crm", "remote", "portal", "old")


def lookalikes(domain: str) -> list[str]:
    """Return plausible typo and imitation domains for domain, without the original."""
    domain = domain.strip().lower().rstrip(".")
    label, _, suffix = domain.partition(".")
    if not label or not suffix:
        return []
    names: set[str] = set()
    for i in range(len(label)):
        names.add(label[:i] + label[i + 1:])                       # omitted letter
        names.add(label[:i] + label[i] + label[i:])                # doubled letter
        if i + 1 < len(label):
            names.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])  # swapped letters
        for other in _ADJACENT.get(label[i], ""):
            names.add(label[:i] + other + label[i + 1:])           # neighbouring key
        if label[i] in _LOOKALIKE:
            names.add(label[:i] + _LOOKALIKE[label[i]] + label[i + 1:])     # look-alike character
        if 0 < i < len(label) and label[i - 1] != "-" and label[i] != "-":
            names.add(label[:i] + "-" + label[i:])                 # inserted hyphen
    names.discard(label)
    candidates = {f"{name}.{suffix}" for name in names if len(name) >= 2 and not name.startswith("-") and not name.endswith("-")}
    candidates.update(f"{label}.{tld}" for tld in _TLDS)
    for extra in ("secure", "login", "soporte", "pagos"):
        candidates.add(f"{label}-{extra}.{suffix}")
    candidates.discard(domain)
    return sorted(candidates)[:MAX_LOOKALIKES]


def _resolve(name: str) -> dict | None:
    """Return {domain, a, mx} when name is registered and resolves, else None."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    record: dict = {"domain": name, "a": [], "mx": False}
    for rtype in ("A", "MX"):
        try:
            answer = resolver.resolve(name, rtype)
        except (dns.exception.DNSException, OSError):
            continue
        if rtype == "A":
            record["a"] = sorted(str(item) for item in answer)[:3]
        else:
            record["mx"] = True
    return record if record["a"] or record["mx"] else None


def registered_lookalikes(domain: str, resolve: Callable[[str], dict | None] = _resolve) -> tuple[list[dict], int]:
    """Resolve every look-alike candidate; return (those that exist, how many were checked)."""
    candidates = lookalikes(domain)
    with ThreadPoolExecutor(max_workers=20) as pool:
        found = [item for item in pool.map(resolve, candidates) if item]
    return sorted(found, key=lambda item: (not item["mx"], item["domain"])), len(candidates)


RETRY_WAIT = (2.0, 6.0)


def _get_json(url: str, *, timeout: float = 45.0, data: bytes | None = None, sleep: Callable[[float], None] = time.sleep):
    """GET (or POST when data is given) and decode JSON; raises OSError/ValueError on failure.

    Free services fail often and briefly: a timeout or a 5xx answer is retried
    twice. A 4xx answer is a real answer and is raised at once.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    for attempt in range(len(RETRY_WAIT) + 1):
        try:
            with urlopen(Request(url, headers=headers, data=data), timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except OSError as exc:
            status = getattr(exc, "code", None)
            if (status is not None and status < 500) or attempt == len(RETRY_WAIT):
                raise
            sleep(RETRY_WAIT[attempt])
    return None  # pragma: no cover - the loop always returns or raises


def certificate_names(domain: str, fetch=_get_json) -> list[str]:
    """Hostnames under domain that appear in public Certificate Transparency logs."""
    rows = fetch(f"https://crt.sh/?q={quote('%.' + domain)}&output=json", timeout=60.0)
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


def domain_addresses(domain: str) -> list[str]:
    """IPv4 addresses of the domain and its www host."""
    addresses: set[str] = set()
    for host in (domain, f"www.{domain}"):
        try:
            addresses.update(info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET))
        except OSError:
            continue
    return sorted(addresses)[:6]


def run(domain: str, *, fetch=_get_json, resolve: Callable[[str], dict | None] = _resolve,
        addresses: Callable[[str], list[str]] = domain_addresses) -> ModuleResult:
    """Collect what public sources already say about domain."""
    domain = domain.strip().lower().rstrip(".")
    result = ModuleResult(name=MODULE_NAME)
    completed = 0
    failed: list[str] = []

    # 1. Look-alike domains, asked from public DNS.
    try:
        found, checked = registered_lookalikes(domain, resolve)
        completed += 1
        if found:
            with_mail = [item for item in found if item["mx"]]
            result.findings.append(Finding(
                MODULE_NAME, Severity.MEDIUM if with_mail else Severity.LOW,
                f"{len(found)} look-alike domain(s) are registered",
                "\n".join(
                    f"{item['domain']}  {', '.join(item['a']) or 'no address'}{'  accepts mail' if item['mx'] else ''}"
                    for item in found[:60]
                ) + f"\nChecked {checked} variations. Registered does not mean malicious: some may be yours or legitimate.",
                "Identify which belong to you; watch the rest, and report the ones impersonating you to the registrar. "
                "Domains that accept mail can be used to phish your staff and customers.",
                confidence="MEDIUM", verification_status="POTENTIAL", occurrence_count=len(found),
            ))
        else:
            result.findings.append(Finding(MODULE_NAME, Severity.PASS, "No look-alike domains registered", f"Checked {checked} variations in public DNS.", ""))
    except Exception as exc:
        failed.append(f"look-alike domains ({exc})")

    # 2. Certificate Transparency.
    try:
        names = certificate_names(domain, fetch)
        completed += 1
        sensitive = [name for name in names if any(part in _SENSITIVE for part in name.removesuffix(domain).strip(".").replace("-", ".").split("."))]
        result.findings.append(Finding(
            MODULE_NAME, Severity.INFO, f"{len(names)} hostname(s) appear in public certificate logs",
            "\n".join(names[:80]) or "None.", "", confidence="HIGH", verification_status=THIRD_PARTY,
        ))
        if sensitive:
            result.findings.append(Finding(
                MODULE_NAME, Severity.LOW, "Internal-looking hostnames are public",
                "\n".join(sensitive[:40]) + "\nSource: Certificate Transparency (crt.sh). Anyone can list these names.",
                "Assume these hosts are known to attackers: keep them patched and behind authentication, or use a wildcard or private certificate.",
                confidence="MEDIUM", verification_status=THIRD_PARTY, occurrence_count=len(sensitive),
            ))
    except Exception as exc:
        failed.append(f"certificate logs ({str(exc)[:80]})")

    # 3. Shodan InternetDB: what an Internet-wide scanner already recorded for the domain's addresses.
    try:
        reported = []
        for address in addresses(domain):
            try:
                row = fetch(f"https://internetdb.shodan.io/{address}", timeout=20.0)
            except OSError as exc:
                if getattr(exc, "code", None) == 404:  # No record for this address.
                    continue
                raise
            if isinstance(row, dict) and (row.get("ports") or row.get("vulns")):
                hostnames = [str(name).lower() for name in row.get("hostnames") or []]
                foreign = [name for name in hostnames if name != domain and not name.endswith("." + domain)]
                reported.append({
                    "ip": address, "ports": row.get("ports") or [], "vulns": row.get("vulns") or [], "hostnames": hostnames,
                    # A CDN or shared host: what Shodan saw there belongs to other sites too.
                    "shared": bool(foreign) or "cdn" in [str(tag).lower() for tag in row.get("tags") or []],
                    "foreign": foreign,
                })
        completed += 1
        for row in [item for item in reported if item["shared"]]:
            result.findings.append(Finding(
                MODULE_NAME, Severity.INFO, f"{row['ip']} is a shared address (CDN or shared hosting)",
                "Shodan's ports and CVEs for this address were ignored: it also serves "
                + (", ".join(row["foreign"][:5]) or "other sites")
                + ", so they cannot be attributed to this domain.\nSource: Shodan InternetDB.",
                "", confidence="HIGH", verification_status=THIRD_PARTY,
            ))
        for row in [item for item in reported if not item["shared"]]:
            result.findings.append(Finding(
                MODULE_NAME, Severity.MEDIUM if row["vulns"] else Severity.INFO,
                f"Shodan lists {len(row['ports'])} open port(s) on {row['ip']}"
                + (f" and {len(row['vulns'])} CVE(s)" if row["vulns"] else ""),
                f"Ports: {', '.join(map(str, row['ports'][:40]))}"
                + (f"\nCVEs by version match: {', '.join(row['vulns'][:20])}" if row["vulns"] else "")
                + (f"\nHostnames: {', '.join(row['hostnames'][:10])}" if row["hostnames"] else "")
                + "\nSource: Shodan InternetDB. Reported by a third party, not verified here; the address may be shared hosting.",
                "Confirm each port is meant to be public and check the listed CVEs against the installed versions." if row["vulns"] else "",
                confidence="LOW", verification_status=THIRD_PARTY, cve_ids=[cve for cve in row["vulns"][:20] if str(cve).startswith("CVE-")],
            ))
        if not reported:
            result.findings.append(Finding(MODULE_NAME, Severity.INFO, "Shodan has no record for the domain's addresses", "Source: Shodan InternetDB.", "", verification_status=THIRD_PARTY))
    except Exception as exc:
        failed.append(f"Shodan InternetDB ({str(exc)[:80]})")

    # 4. Have I Been Pwned: breaches where this domain is the breached service.
    try:
        breaches = fetch(f"https://haveibeenpwned.com/api/v3/breaches?Domain={quote(domain)}", timeout=20.0)
        completed += 1
        for breach in breaches if isinstance(breaches, list) else []:
            result.findings.append(Finding(
                MODULE_NAME, Severity.HIGH, f"Public data breach recorded: {breach.get('Title', breach.get('Name', ''))}",
                f"Date: {breach.get('BreachDate', '')}\nAccounts: {breach.get('PwnCount', '')}\n"
                f"Data: {', '.join(breach.get('DataClasses') or [])}\nSource: Have I Been Pwned.",
                "Treat the exposed data as known to attackers: force password resets where they applied and watch for reuse.",
                confidence="HIGH", verification_status=THIRD_PARTY,
            ))
        if not breaches:
            result.findings.append(Finding(
                MODULE_NAME, Severity.INFO, "No public breach of this domain's own service is recorded",
                "Source: Have I Been Pwned. This does not cover staff passwords leaked in other companies' breaches; "
                "that lookup needs a verified, paid account and was not done.", "", verification_status=THIRD_PARTY,
            ))
    except Exception as exc:
        failed.append(f"Have I Been Pwned ({str(exc)[:80]})")

    # 5. Google Safe Browsing, only with the operator's own API key.
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if key:
        try:
            body = json.dumps({
                "client": {"clientId": "soryntel-security", "clientVersion": "0.4"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{domain}/"}, {"url": f"https://{domain}/"}, {"url": f"https://www.{domain}/"}],
                },
            }).encode()
            answer = fetch(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={quote(key)}", timeout=20.0, data=body)
            completed += 1
            matches = (answer or {}).get("matches") or []
            if matches:
                result.findings.append(Finding(
                    MODULE_NAME, Severity.HIGH, "Google Safe Browsing flags this domain",
                    "\n".join(sorted({f"{m.get('threatType', '')}: {(m.get('threat') or {}).get('url', '')}" for m in matches}))
                    + "\nSource: Google Safe Browsing. Browsers are warning visitors.",
                    "Find and remove the malicious content, then request a review from Google.",
                    confidence="HIGH", verification_status=THIRD_PARTY,
                ))
            else:
                result.findings.append(Finding(MODULE_NAME, Severity.PASS, "Google Safe Browsing does not flag this domain", "Source: Google Safe Browsing.", "", verification_status=THIRD_PARTY))
        except Exception as exc:
            failed.append("Google Safe Browsing (request failed)")
            del exc
    else:
        result.findings.append(Finding(
            MODULE_NAME, Severity.INFO, "Google Safe Browsing was not checked",
            "Set GOOGLE_SAFE_BROWSING_KEY (a free Google Cloud API key) to include it.", "",
        ))

    if failed:
        result.findings.append(Finding(
            MODULE_NAME, Severity.INFO, "Some public sources did not answer",
            "\n".join(failed), "Rerun later; these sources are free services without guaranteed availability.",
            confidence="HIGH", verification_status="TOOL_INCOMPLETE",
        ))
    result.assessed = completed > 0
    return result
