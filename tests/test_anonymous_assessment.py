from mailsec.models import Finding, ModuleResult, Severity
from uncp_offsec.web import anonymous
from uncp_offsec.web.correlation import run as correlate


def test_classify_counts_auth_api_parameters_and_identifiers():
    metrics = anonymous.classify([
        "https://app.example/api/login",
        "https://app.example/api/orders?id=42",
        "https://app.example/profile/123",
    ])
    assert metrics["unique_urls"] == 3
    assert metrics["api_endpoints"] == 2
    assert metrics["auth_endpoints"] == 1
    assert metrics["identifier_endpoints"] == 2
    assert metrics["unique_parameters"] == 1
    assert metrics["forms"] == "UNMEASURED"


def test_classify_ignores_sensitive_words_inside_static_assets_and_mime_names():
    metrics = anonymous.classify([
        "https://app.example/build/routes/orderHistory.js",
        "https://app.example/application/vnd.openxmlformats-officedocument.wordprocessingml.do",
        "https://app.example/rest/admin/application-configuration",
    ])
    assert metrics["sensitive_endpoints"] == 1


def test_anonymous_module_only_uses_get_options_and_redacts_jwt(monkeypatch):
    methods = []

    def fake_request(url, method, **_kwargs):
        methods.append(method)
        if method == "GET":
            return {
                "status": 200,
                "headers": {"Set-Cookie": "sid=x", "Cache-Control": "public"},
                "body": b"eyJabcdefgh.abcdefgh.abcdefgh",
            }
        return {"status": 204, "headers": {"Allow": "GET, POST"}, "body": b""}

    monkeypatch.setattr(anonymous, "_request", fake_request)
    result, _metrics = anonymous.run(
        ["https://app.example/api/orders?id=42"], allowed_hosts={"app.example"}
    )
    assert set(methods) == {"GET", "OPTIONS"}
    assert not any("eyJabcdefgh" in finding.detail for finding in result.findings)
    assert any("State-changing methods" in finding.title for finding in result.findings)
    assert any(finding.verification_status == "POTENTIAL" for finding in result.findings)


def test_anonymous_module_drops_out_of_scope_and_excluded_urls(monkeypatch):
    monkeypatch.setattr(anonymous, "_request", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network called")))
    result, _metrics = anonymous.run(
        ["https://outside.example/api/users/1", "https://app.example/delete/users/1"],
        allowed_hosts={"app.example"}, excluded_paths=("/delete",),
    )
    assert result.assessed
    assert result.findings[0].title == "No anonymous-sensitive candidates"


def test_correlation_requires_independent_modules():
    modules = {
        "dast": ModuleResult("dast", [Finding("dast", Severity.HIGH, "Injection", rfc_ref="CWE-89")]),
        "sqli": ModuleResult("sqli", [Finding("sqli", Severity.HIGH, "SQL injection", rfc_ref="CWE-89")]),
    }
    result = correlate(modules)
    assert result.findings[0].verification_status == "CORRELATED"
    assert "dast, sqli" in result.findings[0].detail


def test_select_rate_limit_target_prioritizes_auth_and_sensitive():
    candidates = [
        "https://app.example/api/%5C%22/",
        "https://app.example/api/products",
        "https://app.example/rest/user/login",
    ]
    metrics = {
        "auth_urls": ["https://app.example/rest/user/login"],
        "sensitive_urls": [],
        "api_urls": ["https://app.example/api/%5C%22/", "https://app.example/api/products"],
    }
    target = anonymous._select_rate_limit_target(candidates, metrics)
    assert target == "https://app.example/rest/user/login"


def test_cookie_issues_handles_multiple_cookies():
    headers = {}
    cookies = [
        "session_id=abc; Path=/; HttpOnly; SameSite=Strict",  # missing Secure
        "tracking_id=123; Path=/",  # missing Secure, HttpOnly, SameSite
        "csrf_token=xyz; Path=/; Secure; HttpOnly; SameSite=Lax",  # complete
    ]
    issues = anonymous._cookie_issues(headers, cookies)
    assert len(issues) == 2
    assert any("session_id" in issue and "Secure" in issue for issue in issues)
    assert any("tracking_id" in issue and "HttpOnly" in issue for issue in issues)


def test_anonymous_run_rate_limit_targets_auth_endpoint(monkeypatch):
    requested_urls = []

    def fake_request(url, method, **_kwargs):
        requested_urls.append((url, method))
        if method == "HEAD":
            return {"status": 200, "headers": {}, "cookies": [], "body": b""}
        return {"status": 200, "headers": {}, "cookies": [], "body": b""}

    monkeypatch.setattr(anonymous, "_request", fake_request)
    urls = [
        "https://app.example/api/%5C%22/",
        "https://app.example/rest/user/login",
    ]
    result, _metrics = anonymous.run(
        urls, allowed_hosts={"app.example"}, rate_limit_check=True, rate_limit_requests=3
    )
    assert result.assessed
    head_requests = [url for url, method in requested_urls if method == "HEAD"]
    assert len(head_requests) == 3
    assert all(url == "https://app.example/rest/user/login" for url in head_requests)
    rate_finding = [f for f in result.findings if f.title == "Bounded rate-limit observation"][0]
    assert "https://app.example/rest/user/login" in rate_finding.detail
