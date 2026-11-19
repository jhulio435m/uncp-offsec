from pathlib import Path

from soryntel_security.web.vulns import reviewed_templates

LIST = Path(__file__).resolve().parents[1] / "config" / "nuclei-reviewed.txt"


def test_reviewed_list_is_well_formed():
    templates = reviewed_templates(LIST.read_text(encoding="utf-8"))

    assert len(templates) == len(set(templates)), "duplicated template"
    assert len(templates) >= 30
    for path in templates:
        assert path.endswith(".yaml")
        assert path.split("/")[0] in {"http", "ssl"}
        assert ".." not in path and not path.startswith("/")


def test_reviewed_list_excludes_templates_that_break_the_scope():
    templates = "\n".join(reviewed_templates(LIST.read_text(encoding="utf-8")))

    for forbidden in ("default-login", "put-method", "git-config", "phpinfo", "http-trace", "/cves/", "fuzzing", "takeover"):
        assert forbidden not in templates


def test_comments_and_blank_lines_are_ignored():
    assert reviewed_templates("# nota\n\n  ssl/tls-version.yaml  \n") == ["ssl/tls-version.yaml"]
