import importlib.metadata
import sys

import pytest


def test_cli_parser_exposes_help_without_import_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["zebbern-kali-mcp", "--help"])

    import mcp_server

    with pytest.raises(SystemExit) as exit_info:
        mcp_server.parse_args()

    assert exit_info.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_cli_parser_uses_published_program_name():
    import mcp_server

    assert mcp_server.build_parser().prog == "zebbern-kali-mcp"


def test_installed_distribution_exposes_console_entry_point():
    distribution = importlib.metadata.distribution("zebbern-kali-mcp")

    assert distribution.version == "1.0.3"
    entry_points = {
        entry_point.name: entry_point.value
        for entry_point in distribution.entry_points
        if entry_point.group == "console_scripts"
    }
    assert entry_points["zebbern-kali-mcp"] == "mcp_server:main"
