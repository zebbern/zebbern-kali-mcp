"""The one tool runner with a completion-assuming side effect.

Backgrounding is a plain passthrough for every ``run_*`` in
``tools/kali_tools.py`` except ``run_subzy``, which does work *after*
``execute_command`` returns. Driven against the real runner with
``execute_command`` recorded; the module imports on Windows because it only
pulls in ``core.command_executor``, ``core.config`` and ``core.tool_config``.
"""

import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


def _run_subzy(monkeypatch, params):
    """Drive run_subzy with execute_command recorded, and return the command."""
    from tools import kali_tools as backend_tools

    captured = {}

    def fake_execute_command(command, **kwargs):
        captured["command"] = command
        captured["background"] = kwargs.get("background")
        return {"success": True, "job_id": "job-recorded", "background": True}

    monkeypatch.setattr(backend_tools, "execute_command", fake_execute_command)
    result = backend_tools.run_subzy(params)
    return captured, result


def _targets_path(command):
    marker = "--targets "
    assert marker in command, command
    return command.split(marker, 1)[1].split()[0]


def test_backgrounding_subzy_keeps_the_temp_targets_file_it_still_needs(monkeypatch):
    """subzy is the only runner that does anything after execute_command returns.

    With an inline ``target`` it writes the name to a NamedTemporaryFile and
    unlinks it once the scan is done. Backgrounded, "done" arrives immediately,
    so the unconditional unlink deletes the targets file out from under a job
    that has not read it yet and the scan finds nothing. Leaving a few bytes in
    the system temp dir is the honest trade; the OS temp reaper collects them.
    """
    captured, result = _run_subzy(monkeypatch, {"target": "example.com", "background": True})

    assert captured["background"] is True
    assert result["job_id"] == "job-recorded"

    path = _targets_path(captured["command"])
    try:
        assert os.path.exists(path), (
            "temp targets file deleted while the background job still needs it"
        )
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_a_foreground_subzy_still_cleans_up_its_temp_targets_file(monkeypatch):
    """The leak is scoped to the background path; nothing else changes."""
    captured, _result = _run_subzy(monkeypatch, {"target": "example.com"})

    assert captured["background"] is False
    assert not os.path.exists(_targets_path(captured["command"]))


def test_a_caller_supplied_targets_file_is_never_unlinked(monkeypatch, tmp_path):
    """The unlink has always been guarded on ``target`` because the other branch
    uses the operator's own file. Backgrounding must not reach it either."""
    targets = tmp_path / "subs.txt"
    targets.write_text("example.com\n", encoding="utf-8")

    captured, _result = _run_subzy(
        monkeypatch, {"targets_file": str(targets), "background": True}
    )

    assert _targets_path(captured["command"]) == str(targets)
    assert targets.exists()
