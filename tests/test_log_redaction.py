import logging
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.ad_tools import ADTools
from core.command_executor import CommandExecutor
from core.logging_utils import redact_command


def test_redact_command_removes_flag_and_embedded_credentials():
    command = (
        "tool --password secret --api-token token-value "
        "DOMAIN/user:embedded-pass@10.0.0.5 -hashes aad3:deadbeef"
    )

    redacted = redact_command(command)

    assert "secret" not in redacted
    assert "token-value" not in redacted
    assert "embedded-pass" not in redacted
    assert "aad3:deadbeef" not in redacted
    assert "10.0.0.5" in redacted
    assert "[REDACTED]" in redacted


def test_redact_command_handles_attached_flags_tokens_and_at_in_passwords():
    command = (
        "tool -pattached -wsecond --auth-token auth-secret "
        "--access-token=access-secret KALI_API_TOKEN=env-secret "
        "DOMAIN/user:p@ss@10.0.0.5 https://web:uri-secret@example.test/path"
    )

    redacted = redact_command(command)

    for secret in (
        "attached",
        "second",
        "auth-secret",
        "access-secret",
        "env-secret",
        "p@ss",
        "uri-secret",
    ):
        assert secret not in redacted
    assert "DOMAIN/user:[REDACTED]@10.0.0.5" in redacted
    assert "https://web:[REDACTED]@example.test/path" in redacted


def test_command_executor_does_not_log_password_value(caplog):
    caplog.set_level(logging.INFO)

    CommandExecutor("echo --password log-secret", timeout=5).execute()

    assert "log-secret" not in caplog.text
    assert "--password [REDACTED]" in caplog.text


def test_impacket_response_redacts_password_and_hash(tmp_path, monkeypatch):
    (tmp_path / "secretsdump.py").write_text("# test fixture", encoding="utf-8")
    tools = object.__new__(ADTools)
    tools.impacket_path = str(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="ok",
            stderr="",
        ),
    )

    result = tools._run_impacket(
        "secretsdump",
        ["DOMAIN/user:response-secret@10.0.0.5", "-hashes", "aad3:deadbeef"],
    )

    assert result["success"] is True
    assert "response-secret" not in result["command"]
    assert "aad3:deadbeef" not in result["command"]
    assert "10.0.0.5" in result["command"]
