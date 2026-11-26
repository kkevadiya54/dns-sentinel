from __future__ import annotations

import json

import pytest

from dns_sentinel import cli
from dns_sentinel.auditor import Finding, Report


def test_cli_json_output_and_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = Report("example.com", (Finding("spf", "pass", "info", "ok"),))
    monkeypatch.setattr(cli.sys, "argv", ["dns-sentinel", "example.com", "--json"])
    monkeypatch.setattr(
        cli, "Auditor", lambda **kwargs: type("Fake", (), {"audit": lambda self, name: report})()
    )
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["domain"] == "example.com"


def test_cli_nonzero_for_error_findings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = Report("example.com", (Finding("spf", "fail", "error", "bad"),))
    monkeypatch.setattr(cli.sys, "argv", ["dns-sentinel", "example.com"])
    monkeypatch.setattr(
        cli, "Auditor", lambda **kwargs: type("Fake", (), {"audit": lambda self, name: report})()
    )
    assert cli.main() == 1
    assert "spf" in capsys.readouterr().out


def test_cli_version_matches_package_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["dns-sentinel", "--version"])
    with pytest.raises(SystemExit, match="0"):
        cli.main()
    assert capsys.readouterr().out.strip() == f"dns-sentinel {cli.__version__}"
