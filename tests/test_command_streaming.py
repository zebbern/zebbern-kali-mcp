"""Streaming command contract tests."""

import importlib.util
import json
import sys
from pathlib import Path

from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import command_executor


def _payloads(events):
    return [json.loads(event.removeprefix("data: ").strip()) for event in events]


def _load_command_blueprint():
    path = BACKEND_ROOT / "api" / "blueprints" / "command.py"
    spec = importlib.util.spec_from_file_location("streaming_command_blueprint", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_streaming_passes_timeout_and_encodes_sse_as_json(monkeypatch):
    calls = []
    line = 'quote " backslash \\ tab\t control\x01'

    def fake_execute(command, on_output=None, timeout=None):
        calls.append({"command": command, "timeout": timeout})
        on_output("stdout", line)
        return {
            "success": True,
            "return_code": 0,
            "timed_out": False,
        }

    monkeypatch.setattr(command_executor, "execute_command", fake_execute)

    payloads = _payloads(
        command_executor.stream_command_execution(
            "example --flag",
            streaming=True,
            timeout=17,
        )
    )

    assert calls == [{"command": "example --flag", "timeout": 17}]
    assert payloads[0] == {"type": "output", "source": "stdout", "line": line}
    assert payloads[-2]["type"] == "result"
    assert payloads[-1] == {"type": "complete"}


def test_streaming_error_message_is_valid_json(monkeypatch):
    def fail_execute(*_args, **_kwargs):
        raise RuntimeError('bad "message"\nnext line')

    monkeypatch.setattr(command_executor, "execute_command", fail_execute)

    payloads = _payloads(
        command_executor.stream_command_execution("example", streaming=True, timeout=2)
    )

    assert payloads == [
        {"type": "error", "message": 'Server error: bad "message"\nnext line'},
        {"type": "complete"},
    ]


def test_command_route_passes_requested_timeout_to_stream(monkeypatch):
    module = _load_command_blueprint()
    received = {}

    def fake_stream(command, streaming=False, timeout=None):
        received.update(
            {"command": command, "streaming": streaming, "timeout": timeout}
        )
        yield 'data: {"type": "complete"}\n\n'

    monkeypatch.setattr(module, "stream_command_execution", fake_stream)
    app = Flask(__name__)
    app.register_blueprint(module.bp)

    response = app.test_client().post(
        "/api/command",
        json={"command": "example", "streaming": True, "timeout": 23},
        buffered=True,
    )

    assert response.status_code == 200
    assert received == {"command": "example", "streaming": True, "timeout": 23}
