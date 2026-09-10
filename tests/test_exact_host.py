from mailsec.models import ModuleResult
from uncp_offsec import scanner


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
