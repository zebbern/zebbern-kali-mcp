"""Streaming command contract tests."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import command_executor


def _helper_frames_for(*, output_line, error):
    """Collect the raw SSE frames streaming_tool_response emits.

    Drives one output frame and forces the error branch, which is the frame that
    interpolates a caller-supplied string.
    """
    # Loaded by path, not by package: `api.blueprints` imports metasploit, which
    # imports pty, which is POSIX-only and cannot load on Windows.
    spec = importlib.util.spec_from_file_location(
        "_zkm_helpers", BACKEND_ROOT / "api" / "blueprints" / "_helpers.py"
    )
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    streaming_tool_response = helpers.streaming_tool_response

    def run_func(params, on_output=None):
        on_output("stdout", output_line)
        raise RuntimeError(error)

    app = Flask(__name__)
    with app.test_request_context():
        response = streaming_tool_response(run_func, {})
        return [
            chunk if isinstance(chunk, str) else chunk.decode("utf-8")
            for chunk in response.response
        ]


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


def test_command_executor_never_uses_indented_json():
    """Indented JSON would put newlines inside a frame and break the client's
    one-object-per-`data:`-line parser (mcp_tools/command_exec.py).

    Scoped to command_executor.py, which serializes whole payloads with
    json.dumps. _helpers.py now does too, but a source grep is the weaker check
    there: its frames are exercised end-to-end against hostile input by
    test_helper_frames_stay_on_one_line_for_hostile_input below.
    """
    source = (BACKEND_ROOT / "core" / "command_executor.py").read_text(encoding="utf-8")

    assert "indent=" not in source, "indented JSON in an SSE frame breaks the client parser"


@pytest.mark.parametrize(
    "hostile",
    [
        "line-one\nline-two",
        'has "quotes"',
        "tab\there",
        "back\\slash",
    ],
    ids=("newline", "quote", "tab", "backslash"),
)
def test_helper_frames_stay_on_one_line_for_hostile_input(hostile):
    """Every _helpers.py frame must be one physical line of parseable JSON.

    The invariant is the frame, not the encoder: no caller-supplied field may
    inject a raw newline or otherwise break the JSON, however the frame is
    built. An unescaped newline or quote splits a frame in two and the client
    silently drops it.
    """
    frames = _helper_frames_for(output_line=hostile, error=hostile)

    terminator = "\n\n"

    assert frames, "no frames produced"
    for frame in frames:
        assert frame.endswith(terminator), f"malformed terminator: {frame!r}"
        body = frame[len("data: ") : -len(terminator)]
        assert "\n" not in body, f"raw newline inside a frame: {frame!r}"
        json.loads(body)  # must parse; raises if a field broke the JSON


def test_client_parser_survives_output_with_embedded_newlines(monkeypatch):
    """A tool line containing a literal newline must still arrive as one frame
    and round-trip through the emitter (default json.dumps escapes the newline)."""
    line = "line-one\nline-two"

    def fake_execute(command, on_output=None, timeout=None):
        on_output("stdout", line)
        return {"success": True, "return_code": 0, "timed_out": False}

    monkeypatch.setattr(command_executor, "execute_command", fake_execute)
    events = list(
        command_executor.stream_command_execution("x", streaming=True, timeout=1)
    )
    for event in events:
        assert event.count("\n") == 2 and event.endswith("\n\n")
    payloads = _payloads(events)
    assert payloads[0] == {"type": "output", "source": "stdout", "line": line}
