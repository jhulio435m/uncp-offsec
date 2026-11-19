from mailsec.models import Finding, Severity
from soryntel_security import scanner
from soryntel_security.models import HostInfo
from soryntel_security.web import tls
from soryntel_security.web.tools import ToolResult


def test_testssl_timeout_is_a_coverage_gap_not_a_risk(monkeypatch):
    monkeypatch.setattr(tls, "run", lambda cmd, timeout=None: ToolResult("testssl.sh", -1, "", "", timed_out=True))
    monkeypatch.setattr(tls, "_openssl_probe", lambda host: [])

    findings, _protocols = tls.analyze_host("empresa.com", timeout=150.0)

    assert findings[0].severity is Severity.INFO
    assert findings[0].verification_status == "TOOL_INCOMPLETE"


def test_tls_module_is_unassessed_when_no_host_finished(monkeypatch):
    gap = Finding(module="tls", severity=Severity.INFO, title="testssl.sh timed out", verification_status="TOOL_INCOMPLETE")
    monkeypatch.setattr(scanner.tls, "analyze_host", lambda host, timeout=None: ([gap], []))
    hosts = [HostInfo(url="https://empresa.com", host="empresa.com", scheme="https")]

    assert scanner.run_tls("empresa.com", hosts).assessed is False

    monkeypatch.setattr(scanner.tls, "analyze_host", lambda host, timeout=None: ([], ["TLS1_3"]))
    assert scanner.run_tls("empresa.com", hosts).assessed is True


def test_failed_prober_is_incomplete_not_a_missing_site(monkeypatch):
    from soryntel_security.web import probe

    monkeypatch.setattr(probe, "which", lambda name: "/bin/httpx")
    monkeypatch.setattr(probe, "run_tool", lambda cmd, timeout=None: ToolResult("httpx", -1, "", "", timed_out=True))
    monkeypatch.setattr(probe, "_curl_fallback", lambda targets, timeout=0: [])

    result, hosts = probe.run("empresa.com", [], timeout=10)

    assert hosts == [] and result.assessed is False
    assert all(f.severity is Severity.INFO and f.verification_status == "TOOL_INCOMPLETE" for f in result.findings)
