import math
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.job_manager import JobManager


TERMINAL_STATES = {"succeeded", "failed", "canceled", "timed_out"}


def python_command(source: str) -> list[str]:
    return [sys.executable, "-u", "-c", source]


def wait_for_terminal(manager: JobManager, job_id: str, timeout: float = 5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = manager.get(job_id)
        if job["status"] in TERMINAL_STATES:
            return job
        time.sleep(0.02)
    pytest.fail(f"job {job_id} did not reach a terminal state")


@pytest.fixture
def manager():
    instance = JobManager(max_jobs=16, max_output_lines=3)
    yield instance
    instance.shutdown()


def test_job_captures_output_and_success_state(manager):
    job = manager.start(python_command("print('ready')"), shell=False, timeout=5)

    completed = wait_for_terminal(manager, job["job_id"])
    output = manager.read_output(job["job_id"], lines=10)

    assert completed["status"] == "succeeded"
    assert completed["return_code"] == 0
    assert output["stdout"] == ["ready"]
    assert output["output"] == "ready"


def test_job_marks_nonzero_exit_as_failed(manager):
    job = manager.start(python_command("raise SystemExit(3)"), shell=False, timeout=5)

    completed = wait_for_terminal(manager, job["job_id"])

    assert completed["status"] == "failed"
    assert completed["return_code"] == 3


def test_job_timeout_terminates_process(manager):
    job = manager.start(
        python_command("import time; time.sleep(30)"),
        shell=False,
        timeout=0.1,
    )

    completed = wait_for_terminal(manager, job["job_id"])

    assert completed["status"] == "timed_out"
    assert completed["timed_out"] is True


def test_job_can_receive_stdin(manager):
    job = manager.start(
        python_command("print(input())"),
        shell=False,
        timeout=5,
    )

    result = manager.send_input(job["job_id"], "hello\n")
    completed = wait_for_terminal(manager, job["job_id"])

    assert result["success"] is True
    assert completed["status"] == "succeeded"
    assert manager.read_output(job["job_id"], lines=10)["stdout"] == ["hello"]


def test_cancel_transitions_running_job_and_stops_process(manager):
    job = manager.start(
        python_command("import time; time.sleep(30)"),
        shell=False,
        timeout=60,
    )

    result = manager.cancel(job["job_id"])
    completed = wait_for_terminal(manager, job["job_id"])

    assert result["success"] is True
    assert completed["status"] == "canceled"


def test_output_buffers_drop_oldest_lines(manager):
    job = manager.start(
        python_command("[print(i) for i in range(5)]"),
        shell=False,
        timeout=5,
    )

    wait_for_terminal(manager, job["job_id"])

    assert manager.read_output(job["job_id"], lines=10)["stdout"] == ["2", "3", "4"]


def test_unknown_job_is_reported_consistently(manager):
    with pytest.raises(KeyError, match="Unknown job"):
        manager.get("missing")


def test_output_wait_rejects_non_finite_or_excessive_values():
    manager = JobManager(max_output_wait=2)
    try:
        job = manager.start(
            python_command("import time; time.sleep(30)"),
            shell=False,
            timeout=60,
        )

        with pytest.raises(ValueError, match="finite"):
            manager.read_output(job["job_id"], timeout=math.inf)
        with pytest.raises(ValueError, match="cannot exceed 2"):
            manager.read_output(job["job_id"], timeout=3)
    finally:
        manager.shutdown()


def test_stdin_is_bounded_and_queued_without_blocking_request_thread():
    manager = JobManager(max_input_bytes=4, max_pending_inputs=1)
    try:
        job = manager.start(
            python_command("import time; time.sleep(30)"),
            shell=False,
            timeout=60,
        )

        result = manager.send_input(job["job_id"], "12345")

        assert result["success"] is False
        assert "maximum size" in result["error"]
    finally:
        manager.shutdown()


def test_single_giant_line_is_truncated_with_bounded_storage():
    manager = JobManager(
        max_output_lines=20,
        max_output_chars=512,
        max_line_chars=128,
    )
    try:
        job = manager.start(
            python_command("import sys; sys.stdout.write('x' * 10000)"),
            shell=False,
            timeout=5,
        )
        wait_for_terminal(manager, job["job_id"])

        output = manager.read_output(job["job_id"], lines=20)

        assert output["output_truncated"] is True
        assert sum(len(event["line"]) for event in output["events"]) <= 512
        assert all(len(event["line"]) <= 128 for event in output["events"])
    finally:
        manager.shutdown()


def test_shutdown_cancels_active_jobs():
    manager = JobManager()
    job = manager.start(
        python_command("import time; time.sleep(30)"),
        shell=False,
        timeout=60,
    )

    manager.shutdown()
    completed = wait_for_terminal(manager, job["job_id"])

    assert completed["status"] == "canceled"
    assert completed["success"] is False


def test_shutdown_catches_a_job_between_registration_and_process_start(monkeypatch):
    manager = JobManager()
    popen_entered = threading.Event()
    release_popen = threading.Event()
    real_popen = __import__("subprocess").Popen
    started = {}

    def delayed_popen(*args, **kwargs):
        popen_entered.set()
        assert release_popen.wait(timeout=3)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr("core.job_manager.subprocess.Popen", delayed_popen)

    thread = threading.Thread(
        target=lambda: started.update(
            manager.start(
                python_command("import time; time.sleep(30)"),
                shell=False,
                timeout=60,
            )
        )
    )
    thread.start()
    assert popen_entered.wait(timeout=3)

    manager.shutdown()
    release_popen.set()
    thread.join(timeout=5)

    try:
        assert not thread.is_alive()
        completed = wait_for_terminal(manager, started["job_id"])
        assert completed["status"] == "canceled"
        with pytest.raises(RuntimeError, match="shutting down"):
            manager.start(python_command("print('late')"), shell=False, timeout=5)
    finally:
        manager.shutdown()


@pytest.mark.skipif(os.name != "nt", reason="Windows taskkill fallback")
def test_windows_taskkill_failure_falls_back_to_process_kill(monkeypatch):
    manager = JobManager()
    process = Mock(pid=1234)
    process.poll.return_value = None
    monkeypatch.setattr(
        "core.job_manager.subprocess.run",
        Mock(side_effect=FileNotFoundError("taskkill unavailable")),
    )

    manager._terminate_process_tree(process, None)

    process.kill.assert_called_once_with()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_descendants_do_not_survive_primary_process_exit():
    manager = JobManager()
    try:
        job = manager.start("sh -c 'sleep 30 &'", shell=True, timeout=5)
        wait_for_terminal(manager, job["job_id"])

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(job["pid"], 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("a descendant remained in the completed job process group")
    finally:
        manager.shutdown()
