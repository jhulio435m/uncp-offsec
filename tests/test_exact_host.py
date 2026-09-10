from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from mailsec.models import ModuleResult
from uncp_offsec import scanner
from uncp_offsec.cli import cli


def test_exact_host_skips_discovery_and_limits_probe(monkeypatch):
    observed: dict[str, object] = {}

    def fail_discovery(*args, **kwargs):
        raise AssertionError("Subfinder discovery must not run in exact-host mode")

    def fake_probe(domain, subdomains, **kwargs):
        observed["domain"] = domain
        observed["subdomains"] = subdomains
        return ModuleResult(name="live_hosts"), []

    monkeypatch.setattr(scanner.discovery, "run", fail_discovery)
    monkeypatch.setattr(scanner.probe, "run", fake_probe)
    monkeypatch.setattr(scanner.tech, "run", lambda *a, **k: ModuleResult(name="technology"))
    monkeypatch.setattr(scanner, "run_tls", lambda *a, **k: ModuleResult(name="tls"))
    monkeypatch.setattr(scanner.correlation, "run", lambda *a, **k: ModuleResult(name="correlation"))

    result = scanner.run_web("api.example.com", exact_host=True)

    assert observed == {"domain": "api.example.com", "subdomains": []}
    assert result.target_mode == "exact-host"
    assert result.to_dict()["target_mode"] == "exact-host"
    discovery_result = next(module for module in result.modules if module.name == "subdomains")
    assert "discovery skipped" in discovery_result.findings[0].title.lower()


def test_sub_preset_selects_scope_and_complete_authorized_bundle(monkeypatch, tmp_path):
    observed: dict[str, object] = {}

    def fake_run(domain, mail_config, **kwargs):
        observed.update(domain=domain, mail_active=mail_config.active, **kwargs)
        return SimpleNamespace(
            scan_profile="", scope_name="", assessment_mode="", elapsed_seconds=0.0,
            target_mode="", comparison=None,
        )

    monkeypatch.setattr("uncp_offsec.cli.run_combined", fake_run)
    monkeypatch.setattr("uncp_offsec.cli.combined_terminal.render_combined", lambda _result: None)
    monkeypatch.setattr("uncp_offsec.cli.combined_html.write", lambda _result, _path: None)

    monkeypatch.chdir(tmp_path)
    Path("scope.uncp.json").write_text(
        '{"domains":["uncp.edu.pe"],"allow_active":true,'
        '"allow_sqli_detection":true}',
        encoding="utf-8",
    )
    Path("lab").mkdir()
    Path("lab/wordlist.txt").write_text("admin\n", encoding="utf-8")
    result = CliRunner().invoke(cli, ["scan", "-sub", "www.uncp.edu.pe"])

    assert result.exit_code == 0, result.output
    assert observed["domain"] == "www.uncp.edu.pe"
    assert observed["exact_host"] is True
    assert observed["mail_active"] is True
    assert observed["include_email"] is False
    assert observed["include_web"] is True
    assert observed["nmap_enabled"] is True
    assert observed["nmap_safe_scripts"] is True
    assert observed["headers_enabled"] is True
    assert observed["dns_inventory_enabled"] is True
    assert observed["crawl_enabled"] is True
    assert observed["content_enabled"] is True
    assert observed["sqli_enabled"] is True
    assert observed["cve_enabled"] is True


def test_sub_preset_requires_a_matching_local_scope():
    result = CliRunner().invoke(cli, ["scan", "-sub", "api.example.com"])
    assert result.exit_code == 2
    assert "No unique local scope*.json authorizes this host" in result.output
