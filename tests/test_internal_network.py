import json

import pytest
from click.testing import CliRunner

from mailsec.models import Finding, ModuleResult, Severity
from soryntel_security import network
from soryntel_security.cli import cli
from soryntel_security.scope import allows_ip, load


def _scope(tmp_path, **fields):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"name": "lab", "allow_active": True, "networks": ["10.20.0.0/24"], **fields}), encoding="utf-8")
    return path


def test_scope_accepts_private_networks_without_domains(tmp_path):
    scope = load(_scope(tmp_path, networks=["10.20.0.5/24", "192.168.1.0/28"]))

    assert scope.networks == ("10.20.0.0/24", "192.168.1.0/28")
    assert scope.domains == ()
    assert allows_ip(scope, "10.20.0.77") and not allows_ip(scope, "10.21.0.1") and not allows_ip(scope, "no-ip")


@pytest.mark.parametrize(("networks", "message"), [
    (["8.8.8.0/24"], "public"),
    (["10.0.0.0/8"], "too broad"),
    (["not-a-network"], "invalid network"),
    ("10.0.0.0/24", "list of CIDR"),
])
def test_scope_rejects_unsafe_networks(tmp_path, networks, message):
    with pytest.raises(ValueError, match=message):
        load(_scope(tmp_path, networks=networks))


def test_scope_still_requires_domains_or_networks(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"name": "empty"}), encoding="utf-8")
    with pytest.raises(ValueError, match="domains"):
        load(path)


def test_expand_targets_stays_inside_the_scope(tmp_path):
    scope = load(_scope(tmp_path))

    assert network.expand_targets(["10.20.0.8/30", "10.20.0.200"], scope) == ["10.20.0.9", "10.20.0.10", "10.20.0.200"]
    for target, message in (("10.20.1.0/30", "outside"), ("8.8.8.8", "not a private"), ("router", "not an IP")):
        with pytest.raises(ValueError, match=message):
            network.expand_targets([target], scope)


def test_expand_targets_enforces_the_host_limit(tmp_path):
    scope = load(_scope(tmp_path, network_max_hosts=4))

    with pytest.raises(ValueError, match="limit of 4"):
        network.expand_targets(["10.20.0.0/24"], scope)


def test_expand_targets_needs_authorized_networks(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"domains": ["example.com"], "allow_active": True}), encoding="utf-8")

    with pytest.raises(ValueError, match="authorizes no internal networks"):
        network.expand_targets(["10.20.0.1"], load(path))


def test_parse_ping_scan_keeps_only_hosts_that_are_up():
    xml = (
        "<nmaprun><host><status state=\"up\"/><address addr=\"10.20.0.9\" addrtype=\"ipv4\"/></host>"
        "<host><status state=\"down\"/><address addr=\"10.20.0.10\" addrtype=\"ipv4\"/></host></nmaprun>"
    )

    assert network.parse_ping_scan(xml) == ["10.20.0.9"]
    assert network.parse_ping_scan("not xml") == []


def test_run_network_scans_only_live_hosts(tmp_path, monkeypatch):
    scope = load(_scope(tmp_path))
    seen = {}
    monkeypatch.setattr(network, "discover", lambda addresses: (ModuleResult(name=network.MODULE_NAME), ["10.20.0.9"]))

    def fake_ports(hosts, **kwargs):
        seen["ports"] = [host.ip for host in hosts]
        result = ModuleResult(name="ports")
        result.open_ports = [{"host": "10.20.0.9", "hostname": "10.20.0.9", "port": 3306, "protocol": "tcp"}]
        result.findings.append(Finding(module="ports", severity=Severity.MEDIUM, title="Potential MySQL exposure (3306/tcp)", detail="", recommendation=""))
        return result

    def fake_nmap(entries, **kwargs):
        seen["nmap"] = (entries, kwargs)
        return ModuleResult(name="nmap")

    monkeypatch.setattr(network.ports_mod, "run", fake_ports)
    monkeypatch.setattr(network.nmap_mod, "run", fake_nmap)

    result = network.run_network(["10.20.0.8/30"], scope)

    assert seen["ports"] == ["10.20.0.9"]
    assert seen["nmap"][1]["vuln_scripts"] is False and seen["nmap"][1]["safe_scripts"] is True
    assert result.target_mode == "internal-network"
    assert [module.name for module in result.modules] == [network.MODULE_NAME, "ports", "nmap"]


def test_run_network_refuses_a_passive_scope(tmp_path):
    scope = load(_scope(tmp_path, allow_active=False))

    with pytest.raises(ValueError, match="allow_active"):
        network.run_network(["10.20.0.9"], scope)


def test_network_command_refuses_targets_outside_the_scope(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(network, "run_network", lambda *args, **kwargs: called.append(args))

    result = CliRunner().invoke(cli, ["network", "192.168.99.1", "--scope", str(_scope(tmp_path))])

    assert result.exit_code != 0 and "outside the networks authorized" in result.output
    assert called == []


def test_network_command_requires_a_scope_file():
    result = CliRunner().invoke(cli, ["network", "10.20.0.9"])

    assert result.exit_code != 0 and "--scope" in result.output


def test_naabu_duplicates_are_reported_once():
    from soryntel_security.web.ports import parse_naabu_json

    line = '{"ip":"10.20.0.9","port":22,"protocol":"tcp"}'

    assert len(parse_naabu_json([line, line, '{"ip":"10.20.0.9","port":80,"protocol":"tcp"}'])) == 2


def test_external_tools_never_inherit_stdin(monkeypatch):
    import subprocess

    from soryntel_security.web import tools

    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    tools.run(["naabu", "-version"])

    assert seen["stdin"] is subprocess.DEVNULL
