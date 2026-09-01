"""Contracts for the exec_stream SSE parser.

This is the most involved client-side logic in the tool surface -- a line
oriented state machine over text/event-stream -- and it had no coverage at any
level. The backend frames every event as ``data: {json}`` with the kind carried
inside the JSON, never as an SSE ``event:`` line.

Faked at the kali_client seam: exec_stream consumes only raise_for_status,
headers, iter_lines, json and close from the response, so yielding an exact
list of decoded lines makes truncation, interleaving and malformed frames
deterministic in a way a socket-level mock cannot.
"""

import io
import json

import pytest
import requests

import mcp_tools.command_exec as command_exec


class FakeStreamResponse:
    def __init__(self, lines, *, content_type="text/event-stream", ok=True, json_body=None):
        self._lines = lines
        self.headers = {"Content-Type": content_type}
        self._ok = ok
        self._json_body = json_body
        self.encoding = "ISO-8859-1"
        self.closed = False

    def raise_for_status(self):
        if not self._ok:
            raise requests.exceptions.HTTPError("boom", response=self)

    def iter_lines(self, decode_unicode=False):
        for item in self._lines:
            if isinstance(item, Exception):
                raise item
            yield item

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise = raise_exc
        self.call = None

    def request(self, method, endpoint, **kwargs):
        self.call = (method, endpoint, kwargs)
        if self._raise:
            raise self._raise
        return self._response


def _exec_stream_for(client):
    captured = {}

    class Recorder:
        def tool(self, *args, **kwargs):
            def decorator(function):
                captured[function.__name__] = function
                return function

            return decorator

    command_exec.register(Recorder(), client)
    return captured["exec_stream"]


def run(response=None, *, raise_exc=None, command="nmap host", timeout=10):
    client = FakeClient(response, raise_exc)
    return _exec_stream_for(client)(command, timeout), client


def sse(**payload):
    return "data: " + json.dumps(payload)


# --- happy path -------------------------------------------------------------


def test_output_result_and_complete_produce_the_documented_shape():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="output", source="stdout", line="hello"),
                sse(type="result", success=True, return_code=0, timed_out=False),
                sse(type="complete"),
            ]
        )
    )

    assert result == {
        "success": True,
        "output": "[stdout] hello",
        "return_code": 0,
        "timed_out": False,
        "streamed": True,
    }


def test_output_events_accumulate_in_order_with_their_source():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="output", source="stdout", line="one"),
                sse(type="output", source="stderr", line="two"),
                sse(type="result", success=True, return_code=0, timed_out=False),
            ]
        )
    )

    assert result["output"] == "[stdout] one\n[stderr] two"


def test_failure_result_propagates_every_field():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="result", success=False, return_code=1, timed_out=True),
                sse(type="complete"),
            ]
        )
    )

    assert (result["success"], result["return_code"], result["timed_out"]) == (
        False,
        1,
        True,
    )


# --- frames that must be ignored -------------------------------------------


@pytest.mark.parametrize(
    "noise",
    [
        "",
        ": keep-alive comment",
        sse(type="heartbeat"),
        sse(type="progress", pct=10),
        sse(no_type=True),
        "data: {not valid json",
    ],
)
def test_noise_frames_do_not_disturb_the_result(noise):
    result, _ = run(
        FakeStreamResponse(
            [
                noise,
                sse(type="output", source="stdout", line="kept"),
                sse(type="result", success=True, return_code=0, timed_out=False),
            ]
        )
    )

    assert result["output"] == "[stdout] kept"
    assert result["success"] is True


def test_data_prefix_parses_without_a_space():
    result, _ = run(
        FakeStreamResponse(
            [
                "data:" + json.dumps({"type": "output", "source": "stdout", "line": "tight"}),
                sse(type="result", success=True, return_code=0, timed_out=False),
            ]
        )
    )

    assert result["output"] == "[stdout] tight"


# --- error frames -----------------------------------------------------------


def test_error_frame_returns_immediately():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="error", message="exploded"),
                sse(type="output", source="stdout", line="never read"),
            ]
        )
    )

    assert result["success"] is False
    assert result["error"] == "exploded"


def test_error_frame_without_a_message_is_still_reported():
    result, _ = run(FakeStreamResponse([sse(type="error")]))

    assert result["error"] == "Unknown error"


# --- truncation must not be reported as success -----------------------------


def test_stream_ending_without_a_result_is_not_reported_as_success():
    """A killed or truncated command previously returned success with rc 0."""
    result, _ = run(
        FakeStreamResponse([sse(type="output", source="stdout", line="partial")])
    )

    assert result["success"] is False
    assert result["incomplete"] is True
    assert result["return_code"] is None
    assert "partial" in result["output"]


def test_complete_without_a_result_is_not_reported_as_success():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="output", source="stdout", line="partial"),
                sse(type="complete"),
            ]
        )
    )

    assert result["success"] is False
    assert result["incomplete"] is True


def test_a_completed_stream_is_not_marked_incomplete():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="result", success=True, return_code=0, timed_out=False),
                sse(type="complete"),
            ]
        )
    )

    assert "incomplete" not in result


# --- non-object JSON must not escape as an exception ------------------------


@pytest.mark.parametrize(
    "frame", ["data: null", "data: 5", 'data: "text"', "data: [1, 2]"]
)
def test_non_object_json_frames_are_skipped_not_raised(frame):
    result, _ = run(
        FakeStreamResponse(
            [frame, sse(type="result", success=True, return_code=0, timed_out=False)]
        )
    )

    assert result["success"] is True


# --- encoding ---------------------------------------------------------------


def test_stream_is_decoded_as_utf8_not_latin1():
    """requests defaults a text/* type without a charset to ISO-8859-1."""
    response = FakeStreamResponse(
        [sse(type="result", success=True, return_code=0, timed_out=False)]
    )

    run(response)

    assert response.encoding == "utf-8"


def test_multibyte_output_survives_a_real_response():
    frame = json.dumps({"type": "output", "source": "stdout", "line": "café"})
    response = requests.models.Response()
    response.status_code = 200
    response.headers["Content-Type"] = "text/event-stream"
    response.raw = io.BytesIO(("data: " + frame + "\n\n").encode("utf-8"))

    result, _ = run(response)

    assert "café" in result["output"]


# --- transport --------------------------------------------------------------


def test_non_event_stream_content_type_returns_the_json_body():
    result, _ = run(
        FakeStreamResponse(
            [],
            content_type="application/json",
            json_body={"success": True, "stdout": "plain"},
        )
    )

    assert result == {"success": True, "stdout": "plain"}


def test_mid_stream_transport_failure_becomes_a_structured_error():
    result, _ = run(
        FakeStreamResponse(
            [
                sse(type="output", source="stdout", line="before"),
                requests.exceptions.ChunkedEncodingError("cut"),
            ]
        )
    )

    assert result["success"] is False
    assert "Streaming request failed" in result["error"]


def test_request_failure_before_a_response_does_not_crash_the_finally():
    result, _ = run(raise_exc=requests.exceptions.ConnectionError("refused"))

    assert result["success"] is False


@pytest.mark.parametrize(
    "lines",
    [
        [sse(type="result", success=True, return_code=0, timed_out=False)],
        [sse(type="error", message="x")],
        [requests.exceptions.ChunkedEncodingError("cut")],
    ],
    ids=("result", "error-frame", "mid-stream-failure"),
)
def test_the_response_is_always_closed(lines):
    response = FakeStreamResponse(lines)

    run(response)

    assert response.closed is True


def test_the_streaming_request_shape_is_locked():
    _, client = run(
        FakeStreamResponse(
            [sse(type="result", success=True, return_code=0, timed_out=False)]
        ),
        command="nmap x",
        timeout=42,
    )

    method, endpoint, kwargs = client.call
    assert (method, endpoint) == ("POST", "api/command")
    assert kwargs["json"] == {"command": "nmap x", "streaming": True, "timeout": 42}
    assert kwargs["headers"] == {"Accept": "text/event-stream"}
    assert kwargs["stream"] is True
    assert kwargs["timeout"] == (10, 42)
