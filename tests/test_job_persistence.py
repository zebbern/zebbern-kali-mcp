"""A backend restart must not make a running job look like it never started.

Jobs were in-memory only, so a restart -- a routine ``docker compose up -d
--force-recreate`` here -- dropped the registry and left ``job_list`` answering
``{"jobs": [], "count": 0}`` and ``job_status`` answering empty, which reads
exactly like "nothing ever ran". ``JobManager`` now persists each job's METADATA
to ``jobs.json`` beside the per-job logs (via ``core.state_store.StateStore``,
under the lock the watcher and ``start`` already hold) and rehydrates stand-in
jobs at construction. These tests pin the contract that matters:

* a job the previous process left running reloads as ``orphaned`` -- a new
  terminal state whose success is *unknowable*, so it reports ``None`` (not the
  ``False`` that bare ``TERMINAL_STATES`` membership would derive), with
  ``return_code`` / ``timed_out`` left ``None`` and an error that names the
  restart and points at the preserved log;
* a job that was already terminal reloads as itself -- its on-disk log is the
  whole of its output, so ``succeeded`` stays ``succeeded`` with its real
  return code;
* a reloaded job's bytes come back from the on-disk log, never the empty
  in-memory ring;
* a reloaded job carries no process and is NEVER poll()'d, killpg'd or
  taskkill'd -- the old pid may now belong to a stranger (CLAUDE.md rule 3), so
  ``cancel`` returns ``already_terminal`` and nothing signals it;
* ``job_list`` after a restart shows the reloaded jobs, not an empty registry;
* an unwritable state dir degrades to ``persisted=False`` and never fails a job
  operation -- the same honest degradation ``output_logged=False`` already is.

``job_manager`` is pure-stdlib plus ``core.state_store`` (no ``pty`` /
``termios``), so it imports by path like the other backend-core tests here and
runs on the Windows dev host.
"""

import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import job_manager as job_manager_module  # noqa: E402
from core.job_manager import JobManager  # noqa: E402
from core.state_store import StateStore  # noqa: E402

LIVE_TERMINAL = {"succeeded", "failed", "canceled", "timed_out"}


def _write_log(path, text):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def _seed_state(jobs_dir, records):
    """Write a prior process's jobs.json into an existing ``jobs_dir``."""
    StateStore(os.path.join(jobs_dir, "jobs.json")).save({"jobs": records})


def _wait_terminal(manager, job_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if manager.get(job_id)["status"] in LIVE_TERMINAL:
            return manager.get(job_id)
        time.sleep(0.02)
    pytest.fail(f"job {job_id} did not reach a terminal state")


def _python(source):
    return [sys.executable, "-u", "-c", source]


# ---------------------------------------------------------------------------
# A job left running by a dead process reloads as 'orphaned'.
# ---------------------------------------------------------------------------


def test_running_job_reloads_as_orphaned_after_restart(tmp_path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    log = jobs_dir / "run1.log"
    _write_log(log, "scan line 1\nscan line 2\n")
    _seed_state(
        str(jobs_dir),
        {
            "run1": {
                "job_id": "run1",
                "command": "nmap -p- target",
                "status": "running",
                "return_code": None,
                "timed_out": False,
                "created_at": 100.0,
                "started_at": 101.0,
                "finished_at": None,
                "output_path": str(log),
            }
        },
    )

    manager = JobManager(output_dir=str(jobs_dir))

    meta = manager.get("run1")
    assert meta["status"] == "orphaned"
    assert meta["restored"] is True
    # The outcome is unknowable, so none of these may claim one.
    assert meta["success"] is None
    assert meta["return_code"] is None
    assert meta["timed_out"] is None
    assert "restart" in meta["error"].lower()
    assert str(log) in meta["error"]

    out = manager.read_output("run1", lines=10)
    assert out["status"] == "orphaned"
    # Both the advisory flag and the tri-state must say "nothing could tell me".
    assert out["success"] is None
    assert out["job_success"] is None
    # Bytes come from the on-disk log, not the empty in-memory ring.
    assert out["stdout"] == ["scan line 1", "scan line 2"]
    assert out["output"] == "scan line 1\nscan line 2"


def test_orphaned_is_terminal_so_cancel_is_a_no_op(tmp_path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    _write_log(jobs_dir / "run1.log", "partial\n")
    _seed_state(
        str(jobs_dir),
        {
            "run1": {
                "job_id": "run1",
                "command": "sleep 9999",
                "status": "running",
                "return_code": None,
                "timed_out": False,
                "created_at": 100.0,
                "started_at": 101.0,
                "finished_at": None,
                "output_path": str(jobs_dir / "run1.log"),
            }
        },
    )
    manager = JobManager(output_dir=str(jobs_dir))

    result = manager.cancel("run1")
    assert result["already_terminal"] is True
    assert result["canceled"] is False


# ---------------------------------------------------------------------------
# A job that was already terminal reloads as itself.
# ---------------------------------------------------------------------------


def test_terminal_job_reloads_as_itself(tmp_path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    log = jobs_dir / "done1.log"
    _write_log(log, "result A\nresult B\n")
    _seed_state(
        str(jobs_dir),
        {
            "done1": {
                "job_id": "done1",
                "command": "echo hi",
                "status": "succeeded",
                "return_code": 0,
                "timed_out": False,
                "created_at": 90.0,
                "started_at": 91.0,
                "finished_at": 92.0,
                "output_path": str(log),
            }
        },
    )

    manager = JobManager(output_dir=str(jobs_dir))

    meta = manager.get("done1")
    assert meta["status"] == "succeeded"
    assert meta["restored"] is True
    assert meta["success"] is True
    assert meta["return_code"] == 0
    assert "error" not in meta

    out = manager.read_output("done1", lines=10)
    assert out["success"] is True
    assert out["job_success"] is True
    assert out["stdout"] == ["result A", "result B"]


# ---------------------------------------------------------------------------
# job_list after a restart shows the reloaded jobs, not an empty registry --
# the headline failure this whole feature exists to fix.
# ---------------------------------------------------------------------------


def test_job_list_is_not_empty_after_restart(tmp_path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    _write_log(jobs_dir / "a.log", "a\n")
    _write_log(jobs_dir / "b.log", "b\n")
    _seed_state(
        str(jobs_dir),
        {
            "a": {
                "job_id": "a",
                "command": "cmd-a",
                "status": "running",
                "return_code": None,
                "timed_out": False,
                "created_at": 10.0,
                "started_at": 11.0,
                "finished_at": None,
                "output_path": str(jobs_dir / "a.log"),
            },
            "b": {
                "job_id": "b",
                "command": "cmd-b",
                "status": "succeeded",
                "return_code": 0,
                "timed_out": False,
                "created_at": 20.0,
                "started_at": 21.0,
                "finished_at": 22.0,
                "output_path": str(jobs_dir / "b.log"),
            },
        },
    )

    manager = JobManager(output_dir=str(jobs_dir))

    listed = manager.list()
    by_id = {entry["job_id"]: entry for entry in listed}
    assert set(by_id) == {"a", "b"}
    assert by_id["a"]["status"] == "orphaned"
    assert by_id["b"]["status"] == "succeeded"
    # newest first, by created_at, as the live list() orders.
    assert [entry["job_id"] for entry in listed] == ["b", "a"]


# ---------------------------------------------------------------------------
# A reloaded job is never signalled: no poll(), killpg() or taskkill().
# ---------------------------------------------------------------------------


def test_reloaded_job_is_never_signalled(tmp_path, monkeypatch):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    _write_log(jobs_dir / "run1.log", "line\n")
    _seed_state(
        str(jobs_dir),
        {
            "run1": {
                "job_id": "run1",
                "command": "sleep 9999",
                "status": "running",
                "return_code": None,
                "timed_out": False,
                "created_at": 100.0,
                "started_at": 101.0,
                "finished_at": None,
                "output_path": str(jobs_dir / "run1.log"),
            }
        },
    )
    manager = JobManager(output_dir=str(jobs_dir))

    # A reloaded stand-in holds no process and no group id; the persisted record
    # never even carried a pid, so there is nothing to signal -- and a pid from
    # the dead process could now belong to a stranger.
    job = manager._jobs["run1"]
    assert job.process is None
    assert job.process_group_id is None
    assert job.pid is None

    # Tripwires on every path that could reach the OS with a signal. If the code
    # ever tries to terminate a reloaded job, the test fails here.
    def tripwire(*args, **kwargs):
        pytest.fail("a reloaded job must never be signalled")

    monkeypatch.setattr(manager, "_terminate_process_tree", tripwire)
    monkeypatch.setattr(manager, "_terminate_remaining_group", tripwire)
    if hasattr(job_manager_module.os, "killpg"):
        monkeypatch.setattr(job_manager_module.os, "killpg", tripwire)
    monkeypatch.setattr(job_manager_module.subprocess, "run", tripwire)

    # Exercise every reloaded-job entry point an operator can reach.
    assert manager.cancel("run1")["already_terminal"] is True
    manager.read_output("run1", lines=10)
    manager.get("run1")
    manager.list()
    manager.shutdown()


# ---------------------------------------------------------------------------
# A live job round-trips through disk: start -> persist -> fresh manager reloads.
# ---------------------------------------------------------------------------


def test_live_job_persists_and_reloads_from_its_real_log(tmp_path):
    jobs_dir = str(tmp_path / "jobs")
    manager = JobManager(output_dir=jobs_dir)
    try:
        job = manager.start(_python("print('hello-persist')"), shell=False, timeout=30)
        job_id = job["job_id"]
        completed = _wait_terminal(manager, job_id)
        assert completed["status"] == "succeeded"
        assert completed["persisted"] is True

        on_disk = json.loads(
            (tmp_path / "jobs" / "jobs.json").read_text(encoding="utf-8")
        )
        assert job_id in on_disk["jobs"]
        assert on_disk["jobs"][job_id]["status"] == "succeeded"
        # The process handle is never serialised.
        assert "process" not in on_disk["jobs"][job_id]
        assert "pid" not in on_disk["jobs"][job_id]
    finally:
        manager.shutdown()

    # A fresh manager on the same dir == a backend restart.
    restarted = JobManager(output_dir=jobs_dir)
    reloaded = restarted.get(job_id)
    assert reloaded["status"] == "succeeded"
    assert reloaded["restored"] is True
    assert reloaded["return_code"] == 0
    assert restarted.read_output(job_id, lines=10)["stdout"] == ["hello-persist"]


# ---------------------------------------------------------------------------
# An unwritable state dir degrades to persisted=False and never fails a job.
# ---------------------------------------------------------------------------


def test_unwritable_state_dir_degrades_to_persisted_false(tmp_path):
    # A file where the jobs directory's parent should be: neither the log nor
    # jobs.json can be opened there.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    manager = JobManager(output_dir=str(blocker / "jobs"))
    try:
        # Construction (which loads state) must not raise on the unreadable dir.
        assert manager.list() == []

        job = manager.start(_python("print('still-runs')"), shell=False, timeout=30)
        completed = _wait_terminal(manager, job["job_id"])

        # The job ran to completion regardless of the persistence fault.
        assert completed["status"] == "succeeded"
        assert completed["persisted"] is False
        assert completed["output_logged"] is False
        # Output still comes back -- from the in-memory ring, the only source
        # when the log could not be opened.
        assert manager.read_output(job["job_id"], lines=10)["stdout"] == ["still-runs"]
    finally:
        manager.shutdown()
