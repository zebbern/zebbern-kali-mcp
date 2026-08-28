import logging
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# The SSH implementation targets Kali's POSIX PTY. Provide only the import-time
# boundary on Windows so these tests can exercise send_command's real behavior.
if os.name == "nt":
    pty_module = ModuleType("pty")
    pty_module.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", pty_module)

import core.api_security as api_security_module
import core.ssh_manager as ssh_manager_module
from core.api_security import APISecurityTester
from core.ssh_manager import SSHSessionManager


def test_ssh_command_redacts_logs_and_metadata_without_changing_execution(
    caplog,
    monkeypatch,
):
    command = (
        "audit-tool --password ssh-password --token ssh-token "
        "--target 10.0.0.5"
    )
    writes = []
    manager = SSHSessionManager("10.0.0.8", "operator", session_id="session-1")
    manager.is_connected = True
    manager.master_fd = 123

    monkeypatch.setattr(
        ssh_manager_module.os,
        "write",
        lambda _fd, payload: writes.append(payload) or len(payload),
    )
    monkeypatch.setattr(ssh_manager_module.os, "read", lambda _fd, _size: b"SSH_END_feedface\n")
    monkeypatch.setattr(
        ssh_manager_module.select,
        "select",
        lambda *_args, **_kwargs: ([manager.master_fd], [], []),
    )
    monkeypatch.setattr(ssh_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(ssh_manager_module.uuid, "uuid4", lambda: "feedface-rest")
    caplog.set_level(logging.INFO)

    result = manager.send_command(command, timeout=1)

    assert writes[0] == f"{command}\n".encode()
    assert result["success"] is True
    assert "ssh-password" not in result["command"]
    assert "ssh-token" not in result["command"]
    assert "--password [REDACTED]" in result["command"]
    assert "--token [REDACTED]" in result["command"]
    assert "--target 10.0.0.5" in result["command"]
    assert "ssh-password" not in caplog.text
    assert "ssh-token" not in caplog.text
    assert "Executing SSH command: audit-tool" in caplog.text


def test_ffuf_authorization_header_is_redacted_only_in_command_metadata(
    tmp_path,
    monkeypatch,
):
    captured_commands = []
    tester = APISecurityTester(str(tmp_path))

    def fake_run(command, **_kwargs):
        captured_commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(api_security_module.subprocess, "run", fake_run)

    result = tester.ffuf_fuzz(
        "https://api.example.test/FUZZ",
        headers={
            "Authorization": "Bearer ffuf-secret",
            "X-API-Key": "ffuf-api-secret",
            "X-Trace-ID": "trace-value",
        },
    )

    assert "Authorization: Bearer ffuf-secret" in captured_commands[0]
    assert "X-API-Key: ffuf-api-secret" in captured_commands[0]
    assert "X-Trace-ID: trace-value" in captured_commands[0]
    assert result["success"] is True
    assert "ffuf-secret" not in result["command"]
    assert "ffuf-api-secret" not in result["command"]
    assert "Authorization: [REDACTED]" in result["command"]
    assert "X-API-Key: [REDACTED]" in result["command"]
    assert "X-Trace-ID: trace-value" in result["command"]
    assert "https://api.example.test/FUZZ" in result["command"]
    assert "/usr/share/wordlists/dirb/common.txt" in result["command"]
