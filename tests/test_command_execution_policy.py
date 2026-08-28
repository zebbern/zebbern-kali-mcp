import pytest
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import command_executor


@pytest.mark.parametrize("name", ["ssh", "scp", "rsync", "nc", "netcat", "telnet"])
def test_command_names_reach_executor(monkeypatch, name):
    calls = []

    class FakeExecutor:
        def __init__(self, command, timeout):
            calls.append((command, timeout))

        def execute(self):
            return {"success": True, "return_code": 0}

    monkeypatch.setattr(command_executor, "CommandExecutor", FakeExecutor)

    result = command_executor.execute_command(f"{name} --help", timeout=17)

    assert result["success"] is True
    assert calls == [(f"{name} --help", 17)]


def test_empty_command_is_rejected_without_constructing_executor(monkeypatch):
    def fail_if_constructed(*args, **kwargs):
        raise AssertionError("empty commands must not construct an executor")

    monkeypatch.setattr(command_executor, "CommandExecutor", fail_if_constructed)

    result = command_executor.execute_command("   ", timeout=17)

    assert result["success"] is False
    assert result["error"] == "Empty command provided"


def test_argv_command_reaches_executor(monkeypatch):
    calls = []

    class FakeExecutor:
        def __init__(self, command, timeout):
            calls.append((command, timeout))

        def execute(self):
            return {"success": True, "return_code": 0}

    monkeypatch.setattr(command_executor, "CommandExecutor", FakeExecutor)

    result = command_executor.execute_command_argv(["ssh", "-V"], timeout=17)

    assert result["success"] is True
    assert calls == [("ssh -V", 17)]
