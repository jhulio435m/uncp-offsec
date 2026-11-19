import json
from pathlib import Path

from click.testing import CliRunner

from mailsec.models import Severity
from soryntel_security.cli import cli
from soryntel_security.web import exposure, secrets
from soryntel_security.web.tools import ToolResult

FAKE_KEY = "AKIA" + "Q3EGR5XJ7WLMN2PD"
FAKE_TOKEN = "ghp_" + "a8Kd93LmQx7Zp2Rt5Vw1Yb4Nc6Hf0Jg3EuSo"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_builtin_scan_reports_location_but_never_the_value(tmp_path, monkeypatch):
    source = _tree(tmp_path, {"app/settings.py": f"x = 1\nKEY = \"{FAKE_KEY}\"\nTOKEN = \"{FAKE_TOKEN}\"\n", ".env": "A=1\n", ".env.example": "A=\n"})
    monkeypatch.setattr(secrets, "which", lambda name: None)

    result = secrets.run(source)

    report = json.dumps([finding.to_dict() for finding in result.findings])
    assert FAKE_KEY not in report and FAKE_TOKEN not in report
    aws = next(f for f in result.findings if f.title == "AWS Access Key ID committed to the source tree")
    assert "File: app/settings.py:2" in aws.detail and aws.severity is Severity.CRITICAL
    files = next(f for f in result.findings if f.title == "Credential-style files in the source tree")
    assert files.detail.splitlines() == [".env"]
    assert any(f.title == "Built-in secret patterns used" for f in result.findings)


def test_trivy_secrets_are_grouped_without_copying_the_match(tmp_path, monkeypatch):
    payload = {"Results": [{"Target": "app/settings.py", "Secrets": [
        {"RuleID": "aws-access-key-id", "Title": "AWS Access Key ID", "Severity": "CRITICAL", "StartLine": 2, "Match": "KEY = \"****\""},
        {"RuleID": "aws-access-key-id", "Title": "AWS Access Key ID", "Severity": "CRITICAL", "StartLine": 9, "Match": "OTHER = \"****\""},
    ]}]}
    monkeypatch.setattr(secrets, "which", lambda name: "/bin/trivy")
    monkeypatch.setattr(secrets, "run_tool", lambda cmd, timeout=None: ToolResult("trivy", 0, json.dumps(payload), ""))

    result = secrets.run(tmp_path)

    finding = next(f for f in result.findings if f.title.startswith("AWS Access Key ID"))
    assert finding.occurrence_count == 2 and "app/settings.py:9" in finding.detail
    assert "KEY =" not in finding.detail and finding.verification_status == "STATIC_SIGNAL"


def test_clean_tree_passes_and_says_history_was_not_scanned(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "which", lambda name: "/bin/trivy")
    monkeypatch.setattr(secrets, "run_tool", lambda cmd, timeout=None: ToolResult("trivy", 0, json.dumps({"Results": []}), ""))

    result = secrets.run(_tree(tmp_path, {"main.py": "print(1)\n"}))

    assert result.findings[0].severity is Severity.PASS and "Git history was not scanned" in result.findings[0].detail


def test_failed_secret_scan_is_incomplete_not_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "which", lambda name: "/bin/trivy")
    monkeypatch.setattr(secrets, "run_tool", lambda cmd, timeout=None: ToolResult("trivy", 1, "", "boom"))

    result = secrets.run(tmp_path)

    assert result.assessed is False and result.findings[0].verification_status == "TOOL_INCOMPLETE"


def test_lookalikes_cover_typos_and_other_endings():
    names = exposure.lookalikes("empresa.com.pe")

    assert "empresa.com.pe" not in names
    for expected in ("empesa.com.pe", "empresa.com", "empres4.com.pe", "empresa-login.com.pe", "emrpesa.com.pe"):
        assert expected in names
    assert len(names) <= exposure.MAX_LOOKALIKES and exposure.lookalikes("localhost") == []


def _fetch(responses):
    def fetch(url, timeout=0.0, data=None):
        for key, value in responses.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value
        raise OSError("unexpected url " + url)
    return fetch


def test_exposure_attributes_every_finding_to_its_source(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    fetch = _fetch({
        "crt.sh": [{"name_value": "www.empresa.com\nvpn.empresa.com\n*.empresa.com"}, {"name_value": "otra.org"}],
        "internetdb": {"ports": [22, 443], "vulns": ["CVE-2021-41773"], "hostnames": ["www.empresa.com"]},
        "haveibeenpwned": [{"Title": "Empresa", "BreachDate": "2024-01-01", "PwnCount": 10, "DataClasses": ["Email addresses"]}],
    })
    resolve = lambda name: {"domain": name, "a": ["203.0.113.5"], "mx": True} if name == "empresa.net" else None

    result = exposure.run("empresa.com", fetch=fetch, resolve=resolve, addresses=lambda domain: ["198.51.100.7"])

    titles = [finding.title for finding in result.findings]
    assert "1 look-alike domain(s) are registered" in titles
    lookalike = result.findings[titles.index("1 look-alike domain(s) are registered")]
    assert lookalike.severity is Severity.MEDIUM and "accepts mail" in lookalike.detail and lookalike.verification_status == "POTENTIAL"
    assert "3 hostname(s) appear in public certificate logs" in titles
    assert "vpn.empresa.com" in result.findings[titles.index("Internal-looking hostnames are public")].detail
    shodan = next(f for f in result.findings if f.title.startswith("Shodan lists 2 open port(s)"))
    assert shodan.cve_ids == ["CVE-2021-41773"] and shodan.verification_status == "THIRD_PARTY_REPORTED" and shodan.confidence == "LOW"
    assert any(f.title == "Public data breach recorded: Empresa" and f.severity is Severity.HIGH for f in result.findings)
    assert "Google Safe Browsing was not checked" in titles
    assert result.assessed is True


def test_exposure_survives_sources_that_fail(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    fetch = _fetch({"crt.sh": OSError("timeout"), "internetdb": OSError("down"), "haveibeenpwned": []})

    result = exposure.run("empresa.com", fetch=fetch, resolve=lambda name: None, addresses=lambda domain: ["198.51.100.7"])

    gap = next(f for f in result.findings if f.title == "Some public sources did not answer")
    assert "certificate logs" in gap.detail and "Shodan" in gap.detail and gap.verification_status == "TOOL_INCOMPLETE"
    assert any(f.title == "No look-alike domains registered" for f in result.findings)
    assert result.assessed is True


def test_safe_browsing_is_used_only_with_a_key_and_never_leaks_it(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "clave-secreta")
    fetch = _fetch({"crt.sh": [], "haveibeenpwned": [], "safebrowsing": {"matches": [{"threatType": "MALWARE", "threat": {"url": "http://empresa.com/"}}]}})

    result = exposure.run("empresa.com", fetch=fetch, resolve=lambda name: None, addresses=lambda domain: [])

    flagged = next(f for f in result.findings if f.title == "Google Safe Browsing flags this domain")
    assert flagged.severity is Severity.HIGH
    assert "clave-secreta" not in json.dumps([finding.to_dict() for finding in result.findings])


def test_code_command_runs_the_three_checks(tmp_path, monkeypatch):
    from mailsec.models import ModuleResult
    from soryntel_security.web import static_analysis

    ran = []
    monkeypatch.setattr(secrets, "run", lambda source: ran.append("secrets") or ModuleResult(name="secrets"))
    monkeypatch.setattr(static_analysis, "sca", lambda source: ran.append("sca") or ModuleResult(name="sca"))
    monkeypatch.setattr(static_analysis, "sast", lambda source: ran.append("sast") or ModuleResult(name="sast"))
    out = tmp_path / "codigo.html"

    result = CliRunner().invoke(cli, ["code", str(tmp_path), "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert ran == ["secrets", "sca", "sast"]
    html = out.read_text(encoding="utf-8")
    assert "Revisión de código" in html and "Secretos en el código" in html


def test_exposure_command_rejects_urls():
    result = CliRunner().invoke(cli, ["exposure", "https://empresa.com/login"])

    assert result.exit_code != 0 and "dominio válido" in result.output


def test_real_trivy_secret_output_is_parsed(tmp_path, monkeypatch):
    # Output of Trivy 0.74.0 on a tree with fake credentials, with the masked "Match" field dropped.
    fixture = (Path(__file__).parent / "fixtures" / "trivy-secrets.json").read_text(encoding="utf-8")
    monkeypatch.setattr(secrets, "which", lambda name: "/bin/trivy")
    monkeypatch.setattr(secrets, "run_tool", lambda cmd, timeout=None: ToolResult("trivy", 0, fixture, ""))

    result = secrets.run(tmp_path)

    titles = {finding.title for finding in result.findings}
    assert {"AWS Access Key ID committed to the source tree", "Asymmetric Private Key committed to the source tree",
            "GitHub Personal Access Token committed to the source tree"} <= titles
