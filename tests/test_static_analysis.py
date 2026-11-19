import json
from pathlib import Path

from soryntel_security.web import static_analysis
from soryntel_security.web.tools import ToolResult


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_detect_manifests_groups_lockfiles_and_flags_unlocked(tmp_path):
    source = _tree(tmp_path, {
        "requirements.txt": "requests==2.19.0\n",
        "web/package.json": "{}", "web/package-lock.json": "{}",
        "api/go.mod": "module x\n",
        "tools/composer.json": "{}",
        "node_modules/x/package-lock.json": "{}",
    })

    locked, unlocked = static_analysis.detect_manifests(source)

    assert locked == {"Python": ["requirements.txt"], "Node.js": ["web/package-lock.json"], "Go": ["api/go.mod"]}
    assert unlocked == {"PHP": ["tools/composer.json"]}


def test_detect_languages_counts_by_extension(tmp_path):
    source = _tree(tmp_path, {"a.py": "", "b.py": "", "src/c.ts": "", "src/d.php": "", "tests/e.py": "", "README.md": ""})

    assert static_analysis.detect_languages(source) == {"Python": 2, "PHP": 1, "TypeScript": 1}


def test_sca_reports_ecosystem_from_trivy(tmp_path, monkeypatch):
    source = _tree(tmp_path, {"package-lock.json": "{}", "go.mod": "module x\n"})
    payload = {"Results": [
        {"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2020-8203", "PkgName": "lodash", "InstalledVersion": "4.17.15", "FixedVersion": "4.17.19", "Severity": "HIGH"}]},
        {"Target": "go.mod", "Type": "gomod"},
    ]}
    monkeypatch.setattr(static_analysis, "which", lambda name: "/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(static_analysis, "run_tool", lambda cmd, timeout=None: ToolResult(cmd, 0, json.dumps(payload), ""))

    result = static_analysis.sca(source)

    assert result.assessed is True
    vuln = next(f for f in result.findings if f.title == "CVE-2020-8203 in lodash")
    assert "Ecosystem: npm" in vuln.detail and vuln.verification_status == "VERSION_CORRELATED"
    manifests = next(f for f in result.findings if f.title == "Dependency manifests found")
    assert "Node.js: package-lock.json" in manifests.detail and "Go: go.mod" in manifests.detail


def test_sca_with_only_pip_audit_declares_other_ecosystems_unanalysed(tmp_path, monkeypatch):
    source = _tree(tmp_path, {"requirements.txt": "requests==2.31.0\n", "package-lock.json": "{}"})
    monkeypatch.setattr(static_analysis, "which", lambda name: "/bin/pip-audit" if name == "pip-audit" else None)
    monkeypatch.setattr(static_analysis, "run_tool", lambda cmd, timeout=None: ToolResult(cmd, 0, json.dumps({"dependencies": []}), ""))

    result = static_analysis.sca(source)

    assert result.assessed is False
    gap = next(f for f in result.findings if f.title == "Non-Python dependencies were not analysed")
    assert "Node.js" in gap.detail and gap.verification_status == "TOOL_INCOMPLETE"


def test_sca_flags_manifest_without_lockfile(tmp_path, monkeypatch):
    source = _tree(tmp_path, {"package.json": "{}"})
    monkeypatch.setattr(static_analysis, "which", lambda name: "/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(static_analysis, "run_tool", lambda cmd, timeout=None: ToolResult(cmd, 0, json.dumps({"Results": []}), ""))

    result = static_analysis.sca(source)

    unlocked = next(f for f in result.findings if f.title == "Manifests without a lockfile")
    assert "Node.js: package.json" in unlocked.detail


def test_sast_with_only_bandit_declares_other_languages_unanalysed(tmp_path, monkeypatch):
    source = _tree(tmp_path, {"app.py": "x = 1\n", "web/index.ts": "export {}\n"})
    monkeypatch.setattr(static_analysis, "which", lambda name: "/bin/bandit" if name == "bandit" else None)
    monkeypatch.setattr(static_analysis, "run_tool", lambda cmd, timeout=None: ToolResult(cmd, 0, json.dumps({"results": []}), ""))

    result = static_analysis.sast(source)

    assert result.assessed is False
    gap = next(f for f in result.findings if f.title == "Non-Python source was not analysed")
    assert "TypeScript" in gap.detail


def test_sca_parses_real_trivy_output_for_eight_ecosystems(tmp_path, monkeypatch):
    # Trimmed output of Trivy 0.58.1 against one lockfile per ecosystem.
    fixture = (Path(__file__).parent / "fixtures" / "trivy-multi.json").read_text(encoding="utf-8")
    monkeypatch.setattr(static_analysis, "which", lambda name: "/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(static_analysis, "run_tool", lambda cmd, timeout=None: ToolResult(cmd, 0, fixture, ""))

    result = static_analysis.sca(tmp_path)

    ecosystems = {
        line.removeprefix("Ecosystem: ")
        for finding in result.findings for line in finding.detail.splitlines() if line.startswith("Ecosystem: ")
    }
    assert ecosystems == {"pip", "npm", "gomod", "bundler", "cargo", "composer", "pom", "nuget"}
    assert all(f.verification_status == "VERSION_CORRELATED" for f in result.findings if "Ecosystem: " in f.detail)
