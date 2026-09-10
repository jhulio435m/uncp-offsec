"""Tests for authorization scope and WAF response reporting."""

from pathlib import Path

from click.testing import CliRunner

from uncp_offsec.cli import cli
from uncp_offsec.models import HostInfo
from uncp_offsec.scope import allows, load
from uncp_offsec.web import ports, probe
from uncp_offsec.web.sqli import is_positive_detection, request_metadata


def test_scope_allows_domain_and_subdomain(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"name":"test","domains":["example.com"],"allow_active":true}')
    scope = load(path)
    assert scope.allow_active
    assert allows(scope, "example.com")
    assert allows(scope, "api.example.com")
    assert not allows(scope, "example.org")


def test_probe_reports_waf_like_status(monkeypatch):
    output = '{"host":"app.example.com","url":"https://app.example.com","status_code":429,"scheme":"https"}'
    monkeypatch.setattr(probe, "which", lambda _name: "httpx")
    monkeypatch.setattr(
        probe,
        "run_tool",
        lambda *_args, **_kwargs: type("Result", (), {"ok": True, "json_lines": lambda self: [output]})(),
    )
    result, _hosts = probe.run("example.com", [])
    assert any("limiting or blocking" in finding.title for finding in result.findings)


def test_port_scan_deduplicates_shared_ips(monkeypatch):
    observed: list[str] = []
    command: list[str] = []

    def fake_run(cmd, **kwargs):
        command.extend(cmd)
        list_path = cmd[cmd.index("-l") + 1]
        observed.extend(Path(list_path).read_text().splitlines())
        return type("Result", (), {"ok": True, "json_lines": lambda self: []})()

    monkeypatch.setattr(ports, "which", lambda _name: "naabu")
    monkeypatch.setattr(ports, "run_tool", fake_run)
    hosts = [
        HostInfo(url="https://a.example", host="a.example", ip="192.0.2.1"),
        HostInfo(url="https://b.example", host="b.example", ip="192.0.2.1"),
    ]

    ports.run(hosts)

    assert observed == ["192.0.2.1"]
    assert "-ec" in command
    assert command[command.index("-s") + 1] == "c"
    assert "-Pn" in command


def test_active_scan_requires_authorization_before_network_access():
    result = CliRunner().invoke(cli, ["scan", "example.com", "--active"])
    assert result.exit_code == 2
    assert "Active tests require --scope" in result.output


def test_nmap_vuln_requires_extra_scope_permission(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"domains":["example.com"],"allow_active":true}')
    result = CliRunner().invoke(
        cli,
        ["scan", "example.com", "--nmap-vuln-authorized", "--scope", str(path)],
    )
    assert result.exit_code == 2
    assert "allow_nmap_vuln" in result.output


def test_dast_requires_extra_scope_permission(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"domains":["example.com"],"allow_active":true}')
    result = CliRunner().invoke(
        cli,
        ["scan", "example.com", "--dast", "--scope", str(path)],
    )
    assert result.exit_code == 2
    assert "allow_dast" in result.output


def test_anonymous_assessment_requires_extra_scope_permission(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"domains":["example.com"],"allow_active":true}')
    result = CliRunner().invoke(
        cli, ["scan", "example.com", "--anonymous-assessment", "--scope", str(path)]
    )
    assert result.exit_code == 2
    assert "allow_anonymous_assessment" in result.output


def test_rate_limit_check_requires_anonymous_assessment():
    result = CliRunner().invoke(cli, ["scan", "example.com", "--rate-limit-check"])
    assert result.exit_code == 2
    assert "requires --anonymous-assessment" in result.output


def test_scope_rejects_exploitation_mode(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"domains":["example.com"],"assessment_mode":"exploitation"}')
    try:
        load(path)
    except ValueError as exc:
        assert "identification-only" in str(exc)
    else:
        raise AssertionError("unsafe assessment mode was accepted")


def test_scope_rejects_unsafe_permissions(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text('{"domains":["example.com"],"allow_exploitation":true}')
    try:
        load(path)
    except ValueError as exc:
        assert "allow_exploitation" in str(exc)
    else:
        raise AssertionError("unsafe scope permission was accepted")


def test_sqlmap_negative_output_is_not_a_finding():
    assert not is_positive_detection("parameter 'to' does not seem to be injectable")


def test_sqlmap_explicit_confirmation_is_a_finding():
    assert is_positive_detection("parameter 'id' appears to be injectable")


def test_raw_sqlmap_request_metadata(tmp_path: Path):
    request = tmp_path / "request.txt"
    request.write_text(
        "POST /api/search HTTP/1.1\nHost: api.example.com:443\nContent-Type: application/json\n\n{}"
    )
    assert request_metadata(request) == ("api.example.com", "/api/search")


def test_raw_sqlmap_request_must_be_in_scope(tmp_path: Path):
    scope = tmp_path / "scope.json"
    scope.write_text(
        '{"domains":["example.com"],"allow_active":true,"allow_sqli_detection":true}'
    )
    request = tmp_path / "request.txt"
    request.write_text("POST /api HTTP/1.1\nHost: outside.example.org\n\n{}")
    result = CliRunner().invoke(
        cli,
        ["scan", "example.com", "--sqlmap-request", str(request), "--scope", str(scope)],
    )
    assert result.exit_code == 2
    assert "outside scope" in result.output
