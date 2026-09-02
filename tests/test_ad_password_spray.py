import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.ad_tools import ADTools


def test_netexec_password_spray_reports_tool_output_verbatim(tmp_path, monkeypatch):
    password = "SpraySecret!42"
    userlist = tmp_path / "users.txt"
    userlist.write_text("alice\n", encoding="utf-8")
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            returncode=0,
            stdout=f"SMB 10.0.0.10 alice:{password} [+] authenticated\n",
            stderr="",
        )

    tools = object.__new__(ADTools)
    tools.available_tools = {"crackmapexec": True}
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/netexec" if name == "netexec" else None)
    monkeypatch.setattr(subprocess, "run", run)

    result = tools.password_spray(
        target="10.0.0.10",
        userlist=str(userlist),
        password=password,
        domain="EXAMPLE",
        delay=0,
    )

    command = captured["command"]
    assert command[command.index("-p") + 1] == password
    assert result["success"] is True
    assert result["users_tested"] == 1
    assert result["valid_credentials"] == [
        {
            "line": f"SMB 10.0.0.10 alice:{password} [+] authenticated",
            "success": True,
        }
    ]
    # The tool's own output comes back untouched. Rewriting it would hide the
    # operator's credential from the operator, and a blind string replace over
    # stdout can corrupt unrelated output that happens to contain the same text.
    assert password in json.dumps(result)


def test_smb_fallback_password_spray_returns_identity_without_password(tmp_path, monkeypatch):
    password = "FallbackSecret!42"
    userlist = tmp_path / "users.txt"
    userlist.write_text("alice\n", encoding="utf-8")
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="Sharename", stderr="")

    tools = object.__new__(ADTools)
    tools.available_tools = {"crackmapexec": False, "netexec": False}
    monkeypatch.setattr(subprocess, "run", run)

    result = tools.password_spray(
        target="10.0.0.10",
        userlist=str(userlist),
        password=password,
        domain="EXAMPLE",
        delay=0,
    )

    assert captured["command"] == [
        "smbclient",
        "-L",
        "10.0.0.10",
        "-U",
        f"EXAMPLE\\alice%{password}",
        "-c",
        "exit",
    ]
    assert result["success"] is True
    assert result["users_tested"] == 1
    assert result["valid_credentials"] == [
        {"username": "alice", "domain": "EXAMPLE"}
    ]
    assert "password" not in result
    assert password not in json.dumps(result)
