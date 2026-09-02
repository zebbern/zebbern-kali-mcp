"""Background execution: what ``execute_command`` does with the flag.

The MCP harness abandons a tool call at roughly 60 seconds, well under the
client's 90000s read timeout and far under every long entry in
``TOOL_TIMEOUTS``. When it does, the backend never notices: the subprocess keeps
running with nobody listening, so the scan is orphaned rather than cancelled and
its output is unreachable forever. ``background=True`` is the only escape --
``execute_command`` hands the command to ``job_manager`` and returns a
``job_id`` immediately, which ``job_status`` / ``job_output`` / ``job_cancel``
can then drive.

These run the real ``execute_command`` with ``job_manager.start`` recorded, so
no subprocess is spawned and the module loads on the Windows host as well as in
the container.
"""

import inspect
import os
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.command_executor import (  # noqa: E402
    CommandExecutor,
    execute_command,
    execute_command_argv,
)
from core.job_manager import JobManager, job_manager  # noqa: E402
from core.tool_config import TOOL_TIMEOUTS  # noqa: E402


RECORDED_JOB = {
    "success": True,
    "job_id": "job-recorded",
    "session_id": "job-recorded",
    "status": "running",
    "pid": 4242,
}


@pytest.fixture
def started_jobs(monkeypatch):
    """Record ``job_manager.start`` and make any synchronous run a failure.

    Both executor entry points raise, not just ``execute()``: gobuster and nikto
    are streaming-classified *and* always pass an ``on_output`` callback, so a
    background flag that loses to either arm of that branch would otherwise
    still look like it worked.
    """
    calls = []
    signature = inspect.signature(JobManager.start)

    def record(*args, **kwargs):
        # Bound against the real signature and defaulted, so an argument the
        # caller omits is recorded as the value job_manager would actually have
        # used. Recording the raw kwargs instead turns "hydra was capped at the
        # 3600s default" into a bare KeyError that says nothing about the budget.
        bound = signature.bind(job_manager, *args, **kwargs)
        bound.apply_defaults()
        captured = dict(bound.arguments)
        captured.pop("self", None)
        calls.append(captured)
        return dict(RECORDED_JOB)

    monkeypatch.setattr(job_manager, "start", record)

    def ran_synchronously(self, *_args, **_kwargs):
        raise AssertionError("ran synchronously")

    monkeypatch.setattr(CommandExecutor, "execute", ran_synchronously)
    monkeypatch.setattr(CommandExecutor, "execute_with_streaming", ran_synchronously)
    return calls


def test_background_returns_a_job_handle_instead_of_running_the_command(started_jobs):
    result = execute_command("nmap -sV 10.0.0.1", background=True)

    assert result["job_id"] == "job-recorded"
    assert result["background"] is True
    assert [call["command"] for call in started_jobs] == ["nmap -sV 10.0.0.1"]


def test_a_streaming_classified_tool_backgrounds_rather_than_streams(started_jobs):
    """Branch ordering is the whole test.

    ``gobuster``, ``nikto`` and ``bash`` are in ``STREAMING_TOOLS``, so checking
    ``background`` *after* ``if on_output or requires_streaming:`` leaves exactly
    those tools -- the ones most likely to outrun the harness -- silently
    running in the foreground while the flag reads as supported.
    """
    result = execute_command(
        "gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/dirb/common.txt",
        background=True,
    )

    assert result["background"] is True
    assert started_jobs[0]["command"].startswith("gobuster dir ")


def test_an_output_callback_does_not_defeat_backgrounding(started_jobs):
    """``run_gobuster``/``run_nikto`` always supply an ``on_output`` callback, so
    the other arm of the same branch has to lose to ``background`` too."""
    result = execute_command(
        "nikto -h http://10.0.0.1",
        on_output=lambda _source, _line: None,
        background=True,
    )

    assert result["background"] is True


def test_the_argv_form_forwards_background(started_jobs):
    """Eight runners call ``execute_command_argv``; a flag it drops on the floor
    is a flag those eight tools do not have."""
    result = execute_command_argv(["nmap", "-sV", "10.0.0.1"], background=True)

    assert result["background"] is True
    assert started_jobs[0]["command"] == "nmap -sV 10.0.0.1"


def test_a_foreground_call_still_runs_synchronously(monkeypatch):
    """The default must not change: only an explicit flag backgrounds."""
    monkeypatch.setattr(
        job_manager,
        "start",
        lambda *_args, **_kwargs: pytest.fail("backgrounded without being asked"),
    )

    result = execute_command("cmd /c echo sync" if os.name == "nt" else "echo sync")

    assert "job_id" not in result
    assert result["success"] is True


def test_a_backgrounded_tool_keeps_its_table_budget(started_jobs):
    """The silent bug this guards: ``job_manager.start`` defaults to
    ``timeout=3600``, so calling it without passing the resolved timeout caps
    hydra at one hour instead of the table's 24 -- and nothing else in the
    system would say so, because the job reports a clean ``timed_out`` at the
    wrong deadline.
    """
    execute_command("hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1",
                    background=True)

    assert started_jobs[0]["timeout"] == TOOL_TIMEOUTS["hydra"]
    assert TOOL_TIMEOUTS["hydra"] > TOOL_TIMEOUTS["default"]


def test_an_explicit_timeout_still_wins_over_the_table(started_jobs):
    execute_command("nmap -sV 10.0.0.1", timeout=120, background=True)

    assert started_jobs[0]["timeout"] == 120
