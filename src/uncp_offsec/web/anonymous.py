"""Bounded anonymous HTTP surface assessment using safe methods only."""

from __future__ import annotations

import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from mailsec.models import Finding, ModuleResult, Severity

MODULE_NAME = "anonymous_access"
AUTH_RE = re.compile(r"(?:^|[/_.-])(?:login|signin|register|signup|password|forgot|reset|oauth2?|sso|token|session)(?:$|[/_.-])", re.IGNORECASE)
SENSITIVE_RE = re.compile(r"(?:^|[/_.-])(?:admin|account|profile|users?|orders?|invoices?|documents?|files?|backup|config|private)(?:$|[/_.-])", re.IGNORECASE)
API_RE = re.compile(r"(?:^|/)(?:api|rest|graphql)(?:/|$)", re.IGNORECASE)
ID_RE = re.compile(r"(?:^|/)(?:\d{1,12}|[0-9a-f]{8}(?:-[0-9a-f-]{27})?)(?:/|$)", re.IGNORECASE)
ID_PARAM_RE = re.compile(r"(?:^|_)(?:id|uid|user|account|order|document)(?:$|_)", re.IGNORECASE)
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
STATIC_SUFFIXES = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify(urls: list[str]) -> dict[str, list[str] | int]:
    """Return deterministic anonymous surface metrics from discovered URLs."""
    unique = sorted(set(urls))
    paths = {urlparse(url).path or "/" for url in unique}
    params = {(urlparse(url).path, name) for url in unique for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
    auth = [url for url in unique if not _is_static(url) and AUTH_RE.search(urlparse(url).path)]
    sensitive = [url for url in unique if not _is_static(url) and SENSITIVE_RE.search(urlparse(url).path)]
    apis = [url for url in unique if not _is_static(url) and API_RE.search(urlparse(url).path)]
    identified = [url for url in unique if not _is_static(url) and _has_identifier(url)]
    return {
        "unique_urls": len(unique), "unique_paths": len(paths), "unique_parameters": len(params),
        "api_endpoints": len(apis), "auth_endpoints": len(auth), "sensitive_endpoints": len(sensitive),
        "identifier_endpoints": len(identified), "forms": "UNMEASURED",
        "auth_urls": auth, "sensitive_urls": sensitive, "api_urls": apis, "identifier_urls": identified,
    }


def _has_identifier(url: str) -> bool:
    parsed = urlparse(url)
    if ID_RE.search(parsed.path):
        return True
    return any(ID_PARAM_RE.search(name) and bool(value) for name, value in parse_qsl(parsed.query))


def _is_static(url: str) -> bool:
    return urlparse(url).path.lower().endswith(STATIC_SUFFIXES)


def _request(url: str, method: str, *, timeout: float = 10.0, origin: bool = False) -> dict:
    headers = {"User-Agent": "uncp-offsec/0.2 anonymous-assessment", "Accept": "*/*"}
    if method == "GET":
        headers["Range"] = "bytes=0-4095"
    if origin:
        headers["Origin"] = "https://uncp-offsec.invalid"
        headers["Access-Control-Request-Method"] = "GET"
    handlers = [_NoRedirect]
    parsed = urlparse(url)
    if parsed.scheme == "https":
        ssl_ctx = ssl.create_default_context()
        hostname = (parsed.hostname or "").lower()
        if hostname.endswith(".local") or hostname in ("localhost", "127.0.0.1", "::1"):
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=ssl_ctx))
    opener = build_opener(*handlers)
    try:
        with opener.open(Request(url, method=method, headers=headers), timeout=timeout) as response:
            body = response.read(4096) if method == "GET" else b""
            cookies = response.headers.get_all("Set-Cookie", []) or []
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "cookies": cookies,
                "body": body,
            }
    except HTTPError as exc:
        body = exc.read(4096) if method == "GET" else b""
        cookies = exc.headers.get_all("Set-Cookie", []) if hasattr(exc, "headers") else []
        return {
            "status": exc.code,
            "headers": dict(exc.headers.items()) if hasattr(exc, "headers") else {},
            "cookies": cookies,
            "body": body,
        }
    except (URLError, OSError, ValueError):
        return {"status": 0, "headers": {}, "cookies": [], "body": b""}


def _cookie_issues(headers: dict[str, str], cookies: list[str] | None = None) -> list[str]:
    raw_cookies = list(cookies or [])
    if not raw_cookies:
        raw = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        if raw:
            raw_cookies = [raw]
    if not raw_cookies:
        return []
    issues: list[str] = []
    for cookie in raw_cookies:
        lower = cookie.lower()
        cookie_missing = []
        if "secure" not in lower:
            cookie_missing.append("Secure")
        if "httponly" not in lower:
            cookie_missing.append("HttpOnly")
        if "samesite" not in lower:
            cookie_missing.append("SameSite")
        if cookie_missing:
            name = cookie.split("=")[0].strip() if "=" in cookie else "cookie"
            issues.append(f"cookie '{name}' missing {', '.join(cookie_missing)}")
    return issues


def _select_rate_limit_target(candidates: list[str], metrics: dict) -> str:
    """Prioritize authentication, sensitive, or API endpoints over arbitrary candidates."""
    auth_set = set(metrics.get("auth_urls") or [])
    for url in candidates:
        if url in auth_set:
            return url
    sensitive_set = set(metrics.get("sensitive_urls") or [])
    for url in candidates:
        if url in sensitive_set:
            return url
    api_set = set(metrics.get("api_urls") or [])
    for url in candidates:
        if url in api_set:
            return url
    return candidates[0]


def run(
    urls: list[str], *, allowed_hosts: set[str], excluded_paths: tuple[str, ...] = (),
    limit: int = 80, rate_limit_check: bool = False, rate_limit_requests: int = 5,
) -> tuple[ModuleResult, dict]:
    """Inspect discovered endpoints anonymously without sending state-changing methods."""
    result = ModuleResult(name=MODULE_NAME)
    metrics = classify(urls)
    candidates = []
    for url in sorted(set(urls)):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed_hosts:
            continue
        if any(parsed.path.startswith(path) for path in excluded_paths):
            continue
        if _is_static(url):
            continue
        if AUTH_RE.search(parsed.path) or SENSITIVE_RE.search(parsed.path) or API_RE.search(parsed.path) or _has_identifier(url):
            candidates.append(url)
    candidates = candidates[:limit]
    if not candidates:
        result.assessed = True
        result.findings.append(Finding(MODULE_NAME, Severity.INFO, "No anonymous-sensitive candidates", "No discovered URL matched authentication, API, sensitive-resource, or identifier patterns.", ""))
        return result, metrics

    public_sensitive: list[str] = []
    unsafe_advertised: list[str] = []
    cors_issues: list[str] = []
    cache_issues: list[str] = []
    cookie_issues: list[str] = []
    jwt_signals: list[str] = []
    statuses: list[str] = []
    for url in candidates:
        get = _request(url, "GET")
        options = _request(url, "OPTIONS", origin=True)
        status = int(get["status"])
        statuses.append(f"{status} GET {url}")
        path = urlparse(url).path
        if status in (200, 206) and (SENSITIVE_RE.search(path) or _has_identifier(url)):
            public_sensitive.append(url)
        allow = str(options["headers"].get("Allow", options["headers"].get("allow", "")))
        announced = {value.strip().upper() for value in allow.split(",")}
        if announced & UNSAFE_METHODS:
            unsafe_advertised.append(f"{url}: {', '.join(sorted(announced & UNSAFE_METHODS))}")
        acao = str(options["headers"].get("Access-Control-Allow-Origin", options["headers"].get("access-control-allow-origin", "")))
        acac = str(options["headers"].get("Access-Control-Allow-Credentials", options["headers"].get("access-control-allow-credentials", ""))).lower()
        if acao == "https://uncp-offsec.invalid" or (acao == "*" and acac == "true"):
            cors_issues.append(url)
        cache_control = str(get["headers"].get("Cache-Control", get["headers"].get("cache-control", ""))).lower()
        if status in (200, 206) and SENSITIVE_RE.search(path) and not any(token in cache_control for token in ("no-store", "private")):
            cache_issues.append(url)
        missing_cookie_flags = _cookie_issues(get.get("headers", {}), get.get("cookies"))
        for issue_text in missing_cookie_flags:
            cookie_issues.append(f"{url}: {issue_text}")
        if JWT_RE.search(get["body"]):
            jwt_signals.append(url)

    result.assessed = True
    result.findings.append(Finding(MODULE_NAME, Severity.INFO, f"Anonymous access checked on {len(candidates)} endpoint(s)", "\n".join(statuses), "", confidence="HIGH", verification_status="OBSERVED"))
    if public_sensitive:
        result.findings.append(Finding(MODULE_NAME, Severity.MEDIUM, "Sensitive-looking resources reachable anonymously", "\n".join(public_sensitive), "Verify whether the response contains non-public information and require authorization where appropriate.", confidence="MEDIUM", verification_status="POTENTIAL", occurrence_count=len(public_sensitive), owasp_categories=["A01:2025", "A07:2025"]))
    if unsafe_advertised:
        result.findings.append(Finding(MODULE_NAME, Severity.LOW, "State-changing methods advertised anonymously", "Only OPTIONS was sent; advertised methods were not executed.\n" + "\n".join(unsafe_advertised), "Confirm server-side authorization for every state-changing method.", confidence="LOW", verification_status="POTENTIAL", occurrence_count=len(unsafe_advertised), owasp_categories=["A01:2025"]))
    for title, rows, recommendation, categories in (
        ("Potentially unsafe anonymous CORS policy", cors_issues, "Use an explicit trusted-origin allowlist and avoid credentialed wildcard/reflected origins.", ["A02:2025"]),
        ("Sensitive-looking response may be cacheable", cache_issues, "Return Cache-Control: no-store or private for authenticated or sensitive responses.", ["A02:2025", "A04:2025"]),
        ("Session cookie attributes incomplete", cookie_issues, "Set Secure, HttpOnly and an appropriate SameSite attribute.", ["A07:2025"]),
        ("JWT-shaped value exposed in anonymous response", jwt_signals, "Confirm the token is not a credential or sensitive bearer token; rotate it if exposed.", ["A07:2025"]),
    ):
        if rows:
            result.findings.append(Finding(MODULE_NAME, Severity.MEDIUM, title, "\n".join(rows), recommendation, confidence="MEDIUM", verification_status="POTENTIAL", occurrence_count=len(rows), owasp_categories=categories))

    if rate_limit_check:
        target = _select_rate_limit_target(candidates, metrics)
        rate_statuses = []
        for _ in range(max(3, min(rate_limit_requests, 10))):
            rate_statuses.append(int(_request(target, "HEAD", timeout=5)["status"]))
            time.sleep(0.2)
        limited = any(code == 429 for code in rate_statuses)
        result.findings.append(Finding(MODULE_NAME, Severity.INFO, "Bounded rate-limit observation", f"Target: {target}\nRequests: {len(rate_statuses)}\nHTTP 429 observed: {limited}", "A short low-rate sample cannot prove that rate limiting is absent.", confidence="LOW", verification_status="OBSERVED", owasp_categories=["A07:2025"]))
    return result, metrics
