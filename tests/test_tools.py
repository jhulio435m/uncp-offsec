import subprocess

from uncp_offsec.web import tools


def test_timeout_retains_partial_tool_output(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["katana"], timeout=1, output=b"https://a.example/path\n", stderr=b"deadline\n"
        )

    monkeypatch.setattr(subprocess, "run", timeout)

    result = tools.run(["katana"], timeout=1)

    assert result.timed_out
    assert result.lines() == ["https://a.example/path"]
    assert result.stderr.strip() == "deadline"
