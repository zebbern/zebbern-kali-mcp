"""Behavioral checks for Active Directory tool discovery."""

import sys
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
sys.path.insert(0, str(SERVER_ROOT))

from core.ad_tools import ADTools


def test_certipy_ad_launcher_is_reported_as_certipy(monkeypatch):
    tools = object.__new__(ADTools)
    tools.impacket_path = "/missing"
    tools.bloodhound_path = "/missing/bloodhound-python"
    tools.netexec_path = "/missing/netexec"
    tools.ldapsearch_path = "/missing/ldapsearch"
    tools._check_command = lambda _name: False

    monkeypatch.setattr(
        "core.ad_tools.shutil.which",
        lambda name: "/usr/bin/certipy-ad" if name == "certipy-ad" else None,
    )
    monkeypatch.setattr("core.ad_tools.os.path.exists", lambda _path: False)

    assert tools._check_tools()["certipy"] is True
