from types import SimpleNamespace

from click.testing import CliRunner

from mailsec.models import ModuleResult, ScanResult
from uncp_offsec.cli import _target_value, cli


def test_mail_command_runs_only_mailsec(monkeypatch):
    observed = {}

    def fake_run(domain, config, on_progress=None):
        observed.update(domain=domain, active=config.active, on_progress=on_progress)
        return ScanResult(domain=domain, modules=[ModuleResult(name="spf")])

    monkeypatch.setattr("uncp_offsec.scanner.run_mail", fake_run)
    monkeypatch.setattr("uncp_offsec.cli.terminal_report.render", lambda result: observed.update(rendered=result.domain))

    result = CliRunner().invoke(cli, ["mail", "example.com"])

    assert result.exit_code == 0, result.output
    assert observed == {
        "domain": "example.com",
        "active": False,
        "on_progress": None,
        "rendered": "example.com",
    }


def test_mail_command_writes_html_only_when_requested(monkeypatch, tmp_path):
    written = []
    monkeypatch.setattr(
        "uncp_offsec.scanner.run_mail",
        lambda domain, config, on_progress=None: ScanResult(domain=domain),
    )
    monkeypatch.setattr("uncp_offsec.cli.terminal_report.render", lambda _result: None)
    monkeypatch.setattr(
        "mailsec.reports.html_report.write",
        lambda _result, path: written.append(path),
    )

    output = tmp_path / "mail.html"
    result = CliRunner().invoke(cli, ["mail", "example.com", "-o", str(output)])

    assert result.exit_code == 0, result.output
    assert written == [output]


def test_wizard_can_choose_passive_mail(monkeypatch):
    observed = {}
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "uncp_offsec.scanner.run_mail",
        lambda domain, config, on_progress=None: (
            observed.update(domain=domain, active=config.active) or ScanResult(domain=domain)
        ),
    )
    monkeypatch.setattr("uncp_offsec.cli.terminal_report.render", lambda _result: None)

    result = CliRunner().invoke(cli, ["wizard"], input="3\nexample.com\n1\nn\n")

    assert result.exit_code == 0, result.output
    assert observed == {"domain": "example.com", "active": False}
    assert "uncp_offsec mail example.com" in result.output


def test_wizard_mail_uses_specific_prompt_and_complete_preset(monkeypatch):
    observed = {}
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "uncp_offsec.scanner.run_mail",
        lambda domain, config, on_progress=None: (
            observed.update(domain=domain, active=config.active) or ScanResult(domain=domain)
        ),
    )
    monkeypatch.setattr("uncp_offsec.cli.terminal_report.render", lambda _result: None)

    result = CliRunner().invoke(cli, ["wizard"], input="3\nsoryntel.com\n2\nn\n")

    assert result.exit_code == 0, result.output
    assert "Ingresa el dominio de correo" in result.output
    assert "MX, SPF, DKIM, DMARC" in result.output
    assert observed == {"domain": "soryntel.com", "active": True}


def test_wizard_rejects_url_and_reprompts_for_mail_domain(monkeypatch):
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr(
        "uncp_offsec.scanner.run_mail",
        lambda domain, config, on_progress=None: ScanResult(domain=domain),
    )
    monkeypatch.setattr("uncp_offsec.cli.terminal_report.render", lambda _result: None)

    result = CliRunner().invoke(
        cli, ["wizard"], input="3\nhttps://soryntel.com/mail\nsoryntel.com\n1\nn\n"
    )

    assert result.exit_code == 0, result.output
    assert "Entrada inválida" in result.output


def test_target_normalizes_invisible_paste_characters():
    assert _target_value("\u200bcepre.uncp.edu.pe\u200b") == "cepre.uncp.edu.pe"


def test_wizard_custom_web_selection_resolves_resources(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config/scopes").mkdir(parents=True)
    (tmp_path / "config/scopes/scope.local.json").write_text(
        '{"domains":["example.com"],"allow_active":true}', encoding="utf-8"
    )
    (tmp_path / "wordlists").mkdir()
    (tmp_path / "wordlists/raft-standard-directories.txt").write_text("admin\n", encoding="utf-8")

    def fake_run(domain, _mail_config, **kwargs):
        observed.update(domain=domain, **kwargs)
        return SimpleNamespace(
            scan_profile="", scope_name="", assessment_mode="", elapsed_seconds=0,
            target_mode="", comparison=None,
        )

    monkeypatch.setattr("uncp_offsec.cli.run_combined", fake_run)
    monkeypatch.setattr("uncp_offsec.cli.combined_terminal.render_combined", lambda _result: None)

    result = CliRunner().invoke(
        cli, ["wizard"], input="1\nexample.com\n3\nheaders,content\n2\nn\n"
    )

    assert result.exit_code == 0, result.output
    assert observed["headers_enabled"] is True
    assert observed["content_enabled"] is True
    assert observed["wordlist"] == tmp_path / "wordlists/raft-standard-directories.txt"
    assert observed["unlimited_tool_time"] is True


def test_wizard_quick_subdomain_uses_exact_host_without_full_sub_preset(monkeypatch):
    observed = {}
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)

    def fake_run(domain, _mail_config, **kwargs):
        observed.update(domain=domain, **kwargs)
        return SimpleNamespace(
            scan_profile="", scope_name="", assessment_mode="", elapsed_seconds=0,
            target_mode="", comparison=None,
        )

    monkeypatch.setattr("uncp_offsec.cli.run_combined", fake_run)
    monkeypatch.setattr("uncp_offsec.cli.combined_terminal.render_combined", lambda _result: None)

    result = CliRunner().invoke(
        cli, ["wizard"], input="2\napi.example.com\n1\nn\n"
    )

    assert result.exit_code == 0, result.output
    assert observed["exact_host"] is True
    assert observed["include_email"] is False
    assert observed["headers_enabled"] is True
    assert observed["dns_inventory_enabled"] is True


def test_wizard_complete_subdomain_allows_ffuf_list_selection(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr("uncp_offsec.cli._interactive_terminal", lambda: True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config/scopes").mkdir(parents=True)
    (tmp_path / "config/scopes/scope.local.json").write_text(
        '{"domains":["example.com"],"allow_active":true}', encoding="utf-8"
    )
    (tmp_path / "wordlists").mkdir()
    quick = tmp_path / "wordlists/raft-quick-directories.txt"
    quick.write_text("admin\n", encoding="utf-8")

    def fake_run(domain, _mail_config, **kwargs):
        observed.update(domain=domain, **kwargs)
        return SimpleNamespace(
            scan_profile="", scope_name="", assessment_mode="", elapsed_seconds=0,
            target_mode="", comparison=None,
        )

    monkeypatch.setattr("uncp_offsec.cli.run_combined", fake_run)
    monkeypatch.setattr("uncp_offsec.cli.combined_terminal.render_combined", lambda _result: None)

    result = CliRunner().invoke(
        cli, ["wizard"], input="2\napi.example.com\n2\n1\nn\n"
    )

    assert result.exit_code == 0, result.output
    assert observed["wordlist"] == quick
    assert observed["content_enabled"] is True
    assert observed["unlimited_tool_time"] is True
    assert observed["ports_enabled"] is False
