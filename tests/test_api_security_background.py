"""The api-security scanners that could still orphan: nuclei and ffuf.

Both runners were shaped unlike the ``tools_*`` ones -- each built its own
``output_file``, called ``subprocess.run`` directly and parsed the file
afterwards -- so the ``background`` passthrough the tool routes got could not
simply be repeated here. Backgrounded, the parse never runs, which is why the
background branch drops ``-o`` and lets the scanner's own structured output
(``-jsonl`` for nuclei, ``-json`` for ffuf) land on stdout, where the job
plumbing tees 100% of it to the durable log.

Driven against the real runners with ``execute_command_argv`` recorded.
``core.api_security`` imports on Windows because it pulls in only
``core.logging_utils`` and ``core.tool_config``; the route blueprint is loaded
by path for the same reason its dotted import cannot be (the package
``__init__`` reaches ``termios``).
"""

import importlib.util
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


def _record_argv(monkeypatch):
    """Drive a runner with execute_command_argv recorded."""
    from core import api_security

    captured = {}

    def fake_execute_command_argv(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["background"] = kwargs.get("background")
        captured["timeout"] = kwargs.get("timeout")
        return {"success": True, "job_id": "job-recorded", "background": True}

    monkeypatch.setattr(api_security, "execute_command_argv", fake_execute_command_argv)
    return api_security, captured


@pytest.mark.parametrize(
    "runner, kwargs, binary, structured_flag",
    [
        (
            "nuclei_api_scan",
            {"target": "https://api.example.test"},
            "nuclei",
            "-jsonl",
        ),
        (
            "ffuf_fuzz",
            {"url": "https://api.example.test/FUZZ"},
            "ffuf",
            "-json",
        ),
    ],
)
def test_a_backgrounded_api_scan_streams_to_stdout(
    monkeypatch, runner, kwargs, binary, structured_flag
):
    """The load-bearing assertion is the absence of ``-o``.

    With ``-o`` the findings go to a file inside the container that only the
    synchronous parse ever reads, and a background job would hand back an empty
    stdout while the real results sat on disk under a name nobody was told. The
    scanner's own newline-delimited JSON on stdout is what the job log tees.
    """
    api_security, captured = _record_argv(monkeypatch)

    result = getattr(api_security.api_tester, runner)(background=True, **kwargs)

    argv = captured["argv"]
    assert captured["background"] is True, "the flag never reached the executor"
    assert captured["timeout"] == api_security.get_tool_timeout(binary)
    assert argv[0] == binary
    assert structured_flag in argv, f"{binary} must emit structured findings"
    assert "-o" not in argv, (
        "a background scan must stream to stdout, not a private file"
    )
    assert "-of" not in argv, "an output format flag is meaningless without -o"
    assert result["job_id"] == "job-recorded"


def test_the_default_stays_synchronous_for_direct_http_callers(monkeypatch):
    """``background`` defaults to False, and that path must not reach the job
    executor at all -- it is still the parsing path a plain HTTP caller gets,
    and it keeps its ``-o`` file because it is the thing that reads it."""
    api_security, captured = _record_argv(monkeypatch)
    ran = {}

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        ran["cmd"] = list(cmd)
        return _Completed()

    monkeypatch.setattr(api_security.subprocess, "run", fake_run)

    result = api_security.api_tester.nuclei_api_scan(target="https://api.example.test")

    assert captured == {}, "the default call backgrounded itself"
    assert "-o" in ran["cmd"], "the synchronous path still parses its own file"
    assert result["output_file"] == ran["cmd"][ran["cmd"].index("-o") + 1]


BLUEPRINT_PATH = BACKEND_ROOT / "api" / "blueprints" / "api_security.py"


def _blueprint_module():
    """Load the route module by path.

    ``import api.blueprints.api_security`` pulls ``termios`` through the
    package ``__init__`` and cannot run on Windows. The file itself imports
    only ``flask``, ``core.config`` and ``core.api_security``, all of which do.
    """
    spec = importlib.util.spec_from_file_location(
        "tested_api_security_blueprint", BLUEPRINT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RecordingTester:
    def __init__(self):
        self.calls = []

    def _record(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            return {"success": True, "job_id": "job-recorded", "background": True}

        return call

    def __getattr__(self, name):
        return self._record(name)


@pytest.mark.parametrize(
    "route, payload, runner",
    [
        ("/api/api-security/nuclei", {"target": "https://api.example.test"},
         "nuclei_api_scan"),
        ("/api/api-security/ffuf", {"url": "https://api.example.test/FUZZ"},
         "ffuf_fuzz"),
    ],
)
def test_the_route_threads_background_into_the_runner(route, payload, runner):
    """A runner that honours the flag is useless if the route drops it.

    The client posts ``background`` in the body like every other promoted
    tool; the route has to forward it or the backend runs synchronously, the
    bounded start POST raises ReadTimeout at ~50s, and the scan is orphaned
    again with no job_id to show for it.
    """
    from flask import Flask

    module = _blueprint_module()
    tester = _RecordingTester()
    module.api_tester = tester

    app = Flask(__name__)
    app.register_blueprint(module.bp)
    client = app.test_client()

    response = client.post(route, json={**payload, "background": True})

    assert response.status_code == 200, response.get_data(as_text=True)
    name, kwargs = tester.calls[0]
    assert name == runner
    assert kwargs["background"] is True, (
        f"{route} dropped background on the way to {runner}"
    )


def test_ffuf_accepts_the_header_string_its_wrapper_actually_sends(monkeypatch):
    """The wrapper types headers as str and documents "key:value pairs,
    comma-separated"; the runner only ever called .items() on it.

    So every documented use raised AttributeError into the broad except and came
    back as a generic failure -- the parameter was unusable exactly as written
    in its own docstring, and the swallow meant it never looked like a bug.
    """
    api_security, captured = _record_argv(monkeypatch)

    api_security.api_tester.ffuf_fuzz(
        url="https://api.example.test/FUZZ",
        headers="X-Api-Key: abc123, X-Trace : 1",
        background=True,
    )

    argv = captured["argv"]
    assert "X-Api-Key: abc123" in argv, f"header string was not parsed: {argv!r}"
    assert "X-Trace: 1" in argv, f"whitespace around the key was not trimmed: {argv!r}"
    assert argv.count("-H") == 2


def test_ffuf_still_accepts_a_header_dict(monkeypatch):
    """Direct HTTP callers pass the dict the signature annotates. Fixing the
    string case must not break them."""
    api_security, captured = _record_argv(monkeypatch)

    api_security.api_tester.ffuf_fuzz(
        url="https://api.example.test/FUZZ",
        headers={"Authorization": "Bearer t"},
        background=True,
    )

    assert "Authorization: Bearer t" in captured["argv"]
