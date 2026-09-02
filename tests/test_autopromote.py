"""The auto-promotion helper: what an agent actually gets back.

Three shapes come out of ``run_promotable`` and an agent has to be able to tell
them apart without reading a note:

  fast path   finished=True,  stdout/stderr strings, synchronous-compatible
  handoff     finished=False, status="running", partial_output, a job_id
  passthrough the backend's own reply, verbatim

The budget is driven through ``ZKM_INLINE_WAIT_SECONDS`` here rather than
waited out -- a test that really sat for 50s would be a test nobody runs.
"""

import time

import pytest

from mcp_tools._autopromote import run_promotable


class FakeClient:
    """Stand in for KaliToolsClient, recording what the helper asked it for."""

    def __init__(self, *, start_reply, statuses=None, output=None):
        self.start_reply = start_reply
        self.statuses = list(statuses or [])
        self.output = output or {}
        self.post_read_timeouts = []
        self.get_calls = []

    def heavy_tool_post(self, endpoint, json_data, semaphore_timeout=120, read_timeout=None):
        self.post_read_timeouts.append(read_timeout)
        return self.start_reply

    def safe_post(self, endpoint, json_data, read_timeout=None):
        self.post_read_timeouts.append(read_timeout)
        return self.start_reply

    def safe_get(self, endpoint, params=None, read_timeout=None):
        self.get_calls.append((endpoint, params))
        if endpoint.endswith("/output"):
            return self.output
        return self.statuses.pop(0) if self.statuses else {"status": "running"}


@pytest.fixture
def quick_budget(monkeypatch):
    """A budget short enough that the handoff path is reachable in a test."""
    monkeypatch.setenv("ZKM_INLINE_WAIT_SECONDS", "0.3")
    monkeypatch.setenv("ZKM_INLINE_POLL_SECONDS", "0.05")


def test_fast_path_keeps_the_order_between_the_two_streams():
    """Splitting the ring into stdout and stderr is exactly what destroys the
    ordering between them, so the ordered records have to come through too.

    job_manager records every line as {"source", "line"} under one lock, which
    is the same design Docker's framed log stream and journald's tagged records
    landed on. Dropping it here would mean the layer above threw away an
    interleaving the layer below already had -- and this is now the default path
    for fourteen heavy tools, so a warning would silently detach from the line
    it belongs beside.
    """
    events = [
        {"source": "stdout", "line": "Starting Nmap 7.99"},
        {"source": "stderr", "line": "Warning: Hostname resolves to 2 IPs"},
        {"source": "stdout", "line": "80/tcp open  http"},
    ]
    client = FakeClient(
        start_reply={"job_id": "j9", "status": "running", "background": True},
        statuses=[{"status": "succeeded", "return_code": 0, "timed_out": False}],
        output={
            "stdout": ["Starting Nmap 7.99", "80/tcp open  http"],
            "stderr": ["Warning: Hostname resolves to 2 IPs"],
            "events": events,
        },
    )

    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    assert result["events"] == events, "the ordered records were dropped"
    # The split strings stay for synchronous parity; events is additive.
    assert "Starting Nmap 7.99" in result["stdout"]
    assert "Warning" in result["stderr"]
    # The warning sits between the two stdout lines, which neither string shows.
    assert [event["source"] for event in result["events"]] == [
        "stdout", "stderr", "stdout"
    ]


def test_fast_path_returns_a_synchronous_shape():
    """A job that finishes inside the budget must be indistinguishable from the
    synchronous call it replaced: stdout is a string, not the ring's list."""
    client = FakeClient(
        start_reply={"job_id": "j1", "status": "running", "background": True},
        statuses=[{"status": "succeeded", "return_code": 0, "timed_out": False}],
        output={"stdout": ["80/tcp open  http"], "stderr": [], "output": "80/tcp open  http"},
    )

    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    assert result["finished"] is True
    assert result["success"] is True
    assert result["auto_promoted"] is True
    assert result["job_id"] == "j1"
    assert isinstance(result["stdout"], str), f"stdout is {type(result['stdout'])}"
    assert "80/tcp open" in result["stdout"]
    assert "partial_output" not in result


def test_fast_path_flags_truncation_and_gives_the_log_path():
    """The in-memory ring clips; the on-disk tee does not. A clipped window must
    say so and say where the whole thing is -- a silent tail is a dropped byte."""
    client = FakeClient(
        start_reply={"job_id": "j2"},
        statuses=[{"status": "succeeded", "return_code": 0}],
        output={
            "stdout": ["...tail..."],
            "stderr": [],
            "output_truncated": True,
            "output_path": "/app/tmp/jobs/j2.log",
            "output_logged": True,
        },
    )

    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    assert result["output_truncated"] is True
    assert result["output_path"] == "/app/tmp/jobs/j2.log"
    assert "/app/tmp/jobs/j2.log" in result["note"]


def test_timed_out_with_output_is_success_true():
    """CommandExecutor parity. success stays True with timed_out True and output
    present -- callers check timed_out, never success, to know a command finished.
    Flipping success here would make an auto-promoted result a different
    category from the synchronous one."""
    client = FakeClient(
        start_reply={"job_id": "j3"},
        statuses=[{"status": "timed_out", "return_code": -1, "timed_out": True}],
        output={"stdout": ["partial line"], "stderr": []},
    )

    result = run_promotable(client, "api/tools/hydra", {"target": "x"}, heavy=True, background=False)

    assert result["success"] is True
    assert result["timed_out"] is True
    assert result["partial_results"] is True
    assert "partial line" in result["stdout"]


def test_handoff_when_the_job_outlasts_the_budget(quick_budget):
    """The whole point. Past the budget the agent gets a handle, not an orphan --
    and the budget is the env var, so this finishes in well under a second."""
    client = FakeClient(
        start_reply={"job_id": "j4"},
        statuses=[],  # always running
        output={"output": "Starting Nmap 7.94", "output_path": "/app/tmp/jobs/j4.log"},
    )

    start = time.monotonic()
    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)
    elapsed = time.monotonic() - start

    assert elapsed < 3, f"waited {elapsed:.1f}s, so the env budget was ignored"
    assert result["finished"] is False
    assert result["status"] == "running"
    assert result["success"] is True
    assert result["job_id"] == "j4"
    assert "partial_output" in result
    assert "Starting Nmap" in result["partial_output"]
    assert "stdout" not in result, "a still-running job must not look finished"
    assert result["return_code"] is None
    assert "job_status" in result["note"] and "job_cancel" in result["note"]


def test_fire_and_forget_returns_the_handle_verbatim():
    """background=True keeps its old meaning: post, return the handle, no wait."""
    handle = {"job_id": "j5", "status": "queued", "background": True, "pid": 42}
    client = FakeClient(start_reply=handle, statuses=[{"status": "succeeded"}])

    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=True)

    assert result == handle
    assert client.get_calls == [], "background=True must not poll"


def test_a_synchronous_reply_passes_through():
    """An older backend ignores the flag and answers with the finished result.
    There is no job to poll, so the reply is handed back untouched."""
    sync = {"success": True, "stdout": "80/tcp open", "return_code": 0, "timed_out": False}
    client = FakeClient(start_reply=sync)

    result = run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    assert result == sync
    assert client.get_calls == [], "there is no job_id to poll"


def test_the_job_start_post_is_bounded():
    """heavy_tool_post holds one of five semaphore slots for the whole read
    timeout. An unbounded job-start against a backend that runs the tool
    synchronously would hold that slot for 90000s."""
    client = FakeClient(
        start_reply={"job_id": "j6"},
        statuses=[{"status": "succeeded", "return_code": 0}],
        output={"stdout": [], "stderr": []},
    )

    run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    bound = client.post_read_timeouts[-1]
    assert bound is not None, "the job-start POST is unbounded"
    assert bound <= 50


def test_the_job_start_always_asks_for_a_background_job():
    """The safety keystone: the job exists before the wait begins, so a harness
    abort mid-poll leaves something job_list can still find."""
    posted = {}

    class _Recording(FakeClient):
        def heavy_tool_post(self, endpoint, json_data, semaphore_timeout=120, read_timeout=None):
            posted.update(json_data)
            return super().heavy_tool_post(endpoint, json_data, semaphore_timeout, read_timeout)

    client = _Recording(
        start_reply={"job_id": "j7"},
        statuses=[{"status": "succeeded", "return_code": 0}],
        output={"stdout": [], "stderr": []},
    )

    run_promotable(client, "api/tools/nmap", {"target": "x"}, heavy=True, background=False)

    assert posted["background"] is True
    assert posted["target"] == "x", "the caller's own arguments must survive"
