import math
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import job_manager as job_manager_module
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
def manager(tmp_path):
    instance = JobManager(
        max_jobs=16, max_output_lines=3, output_dir=str(tmp_path / "jobs")
    )
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
    assert result["canceled"] is True
    assert result["already_terminal"] is False
    assert completed["status"] == "canceled"


def test_cancel_is_idempotent_on_a_finished_job(manager):
    """Cancelling work that is already over is not a caller error.

    It used to answer success False with an error string, which is
    field-for-field what a failed cancel of a still-running job looks like --
    the one case the operator has to act on. The explicit canceled flag keeps
    the call from ever claiming it cancelled something it did not: success is
    True, canceled is False, and the job's real status comes back with it.
    """
    job = manager.start(python_command("print('over')"), shell=False, timeout=5)
    wait_for_terminal(manager, job["job_id"])

    result = manager.cancel(job["job_id"])

    assert result["success"] is True
    assert result["canceled"] is False
    assert result["already_terminal"] is True
    assert result["status"] == "succeeded"
    assert "succeeded" in result["note"]


def test_cancel_still_raises_for_an_unknown_job(manager):
    """Idempotence covers a job that is over, not one that never existed."""
    with pytest.raises(KeyError, match="Unknown job"):
        manager.cancel("missing")


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


def test_output_wait_clamps_excess_and_rejects_non_finite():
    """An over-max wait is clamped and reported, not rejected.

    The ceiling keeps one poll well under the harness's ~60s tool-call abort,
    which is worth keeping -- but a 400 cost the operator the entire poll for
    asking too high, and nothing advertised the bound until it tripped. The
    clamp must not hide the reduction: wait_timeout is the wait actually used,
    wait_capped says it was reduced, max_output_wait states the bound. A
    non-finite wait is still a hard error.
    """
    manager = JobManager(max_output_wait=2)
    try:
        job = manager.start(python_command("print('done')"), shell=False, timeout=60)
        wait_for_terminal(manager, job["job_id"])

        with pytest.raises(ValueError, match="finite"):
            manager.read_output(job["job_id"], timeout=math.inf)
        with pytest.raises(ValueError, match="negative"):
            manager.read_output(job["job_id"], timeout=-1)

        clamped = manager.read_output(job["job_id"], timeout=3, lines=10)
        legal = manager.read_output(job["job_id"], timeout=1, lines=10)

        assert clamped["wait_capped"] is True
        assert clamped["wait_timeout"] == 2
        assert clamped["max_output_wait"] == 2
        assert clamped["stdout"] == ["done"]
        assert legal["wait_capped"] is False
        assert legal["wait_timeout"] == 1
    finally:
        manager.shutdown()


def test_clamped_output_wait_actually_bounds_the_block():
    """The clamp is the real wait, not only a reported number.

    A running job that has printed nothing is the case the ceiling exists for:
    uncapped, this call blocks for the full requested wait, which is how a poll
    ends up abandoned by the harness instead of answering.
    """
    manager = JobManager(max_output_wait=0.2)
    try:
        job = manager.start(
            python_command("import time; time.sleep(30)"),
            shell=False,
            timeout=60,
        )

        started = time.monotonic()
        result = manager.read_output(job["job_id"], timeout=5)
        elapsed = time.monotonic() - started

        assert result["wait_capped"] is True
        assert result["wait_timeout"] == pytest.approx(0.2)
        assert elapsed < 2, f"the clamp did not bound the block ({elapsed:.2f}s)"
    finally:
        manager.shutdown()


def test_an_over_max_wait_on_an_unknown_job_reports_the_unknown_job():
    """Validation used to answer "timeout cannot exceed N" for a job that does
    not exist, which hid the real problem behind a complaint about an argument.
    Clamping first lets the lookup speak."""
    manager = JobManager(max_output_wait=2)
    try:
        with pytest.raises(KeyError, match="Unknown job"):
            manager.read_output("missing", timeout=120)
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


def test_full_output_is_teed_to_disk(manager):
    """The bounded window may drop lines; the log on disk never does.

    The ring evicts the oldest events past ``max_output_lines``, and before
    the tee those bytes were gone permanently. ``output_truncated`` now means
    "the returned window is partial", not "output was lost".
    """
    job = manager.start(
        python_command("[print('line %d' % i) for i in range(50)]"),
        shell=False,
        timeout=10,
    )
    wait_for_terminal(manager, job["job_id"])

    output = manager.read_output(job["job_id"], lines=100)

    assert output["output_truncated"] is True
    assert output["output_logged"] is True
    assert output["lines_returned"] == 3
    on_disk = Path(output["output_path"]).read_text(encoding="utf-8").splitlines()
    assert on_disk == [f"line {index}" for index in range(50)]


def test_overlong_single_line_reaches_disk_intact(tmp_path):
    """The tee must run on the raw pre-clip chunk, not the clipped line.

    ``_drain_stream`` reads with ``readline(max_line_chars + 1)``, so a line
    longer than the limit arrives as 129-char chunks that ``_append_output``
    clips to 128. Teeing the clipped line looks correct and still drops one
    byte in every 129 -- 77 of them here. Only the raw chunk reconstructs the
    stream the process actually wrote.
    """
    manager = JobManager(
        max_output_lines=20,
        max_output_chars=512,
        max_line_chars=128,
        output_dir=str(tmp_path / "jobs"),
    )
    try:
        job = manager.start(
            python_command("import sys; sys.stdout.write('x' * 10000)"),
            shell=False,
            timeout=10,
        )
        wait_for_terminal(manager, job["job_id"])

        output = manager.read_output(job["job_id"], lines=20)

        assert output["output_truncated"] is True
        assert all(len(event["line"]) <= 128 for event in output["events"])
        assert output["output_logged"] is True
        on_disk = Path(output["output_path"]).read_text(encoding="utf-8")
        assert on_disk.count("x") == 10000
        assert on_disk == "x" * 10000
    finally:
        manager.shutdown()


def test_job_starts_when_log_dir_unwritable(tmp_path):
    """A log that cannot be opened must not stop the job from running.

    ``output_logged=False`` is the one honestly lossy state: the bounded ring
    is all there is, so ``output_truncated`` means loss again.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the log directory's parent should be")
    manager = JobManager(
        max_jobs=16,
        max_output_lines=20,
        output_dir=str(blocker / "jobs"),
    )
    try:
        job = manager.start(
            python_command("print('still-runs')"),
            shell=False,
            timeout=10,
        )
        completed = wait_for_terminal(manager, job["job_id"])
        output = manager.read_output(job["job_id"], lines=10)

        assert completed["status"] == "succeeded"
        assert completed["output_logged"] is False
        assert completed["output_path"] is None
        assert output["output_logged"] is False
        assert output["output_path"] is None
        assert output["stdout"] == ["still-runs"]
    finally:
        manager.shutdown()


def test_untruncated_output_still_reports_a_log_path(manager):
    """Every job gets a log, not only the ones that overflow the ring."""
    job = manager.start(python_command("print('ready')"), shell=False, timeout=10)
    wait_for_terminal(manager, job["job_id"])

    output = manager.read_output(job["job_id"], lines=10)

    assert output["output_truncated"] is False
    assert output["output_logged"] is True
    assert Path(output["output_path"]).read_text(encoding="utf-8") == "ready\n"


def test_log_path_is_surfaced_by_get_list_and_read_output(manager):
    """One job, one path, reported identically by all three readers."""
    job = manager.start(python_command("print('surfaced')"), shell=False, timeout=10)
    wait_for_terminal(manager, job["job_id"])

    metadata = manager.get(job["job_id"])
    output = manager.read_output(job["job_id"], lines=10)
    listed = manager.list()[0]

    assert metadata["output_path"] is not None
    assert metadata["output_path"] == output["output_path"]
    assert metadata["output_path"] == listed["output_path"]
    assert job["job_id"] in metadata["output_path"]
    assert metadata["output_logged"] is True
    assert output["output_logged"] is True
    assert listed["output_logged"] is True


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


def test_line_buffer_wrap_shapes_the_launch_command(monkeypatch):
    """Where the buffering fix lives, asserted without needing GNU stdbuf.

    A C-stdio tool whose stdout is a pipe full-buffers ~4-8KB and delivers
    nothing until it fills or the process exits, so job_output showed a banner
    and then silence for the whole scan. Only the child's libc can change that,
    which is what stdbuf sets up; the parent's bufsize=1 cannot.

    The sh form is the load-bearing part: a bare `stdbuf -oL <command>` prefix
    cannot exec a shell builtin, so `cd /x && nmap` -- an ordinary job command
    here -- would stop working. The two mismatched combinations mean something
    specific to Popen and must stay unwrapped.
    """
    monkeypatch.setattr(job_manager_module, "_STDBUF_PATH", "/usr/bin/stdbuf")

    assert JobManager._line_buffered_launch("cd /x && nmap -p1 h", True) == [
        "/usr/bin/stdbuf",
        "-oL",
        "-eL",
        "/bin/sh",
        "-c",
        "cd /x && nmap -p1 h",
    ]
    assert JobManager._line_buffered_launch(["nmap", "-p1", "h"], False) == [
        "/usr/bin/stdbuf",
        "-oL",
        "-eL",
        "nmap",
        "-p1",
        "h",
    ]
    assert JobManager._line_buffered_launch(["nmap"], True) is None
    assert JobManager._line_buffered_launch("nmap", False) is None

    monkeypatch.setattr(job_manager_module, "_STDBUF_PATH", None)
    assert JobManager._line_buffered_launch("nmap -p1 h", True) is None


@pytest.mark.skipif(
    job_manager_module._STDBUF_PATH is None,
    reason="GNU stdbuf is absent on this system (non-Linux userland)",
)
def test_a_started_job_is_launched_line_buffered(manager, monkeypatch):
    """End to end: the wrap reaches Popen and the job still works.

    Also pins that the shell moved from Popen's shell=True into stdbuf's argv.
    Leaving shell=True with a list would run bare `stdbuf` on POSIX.
    """
    recorded: dict[str, object] = {}
    real_popen = subprocess.Popen

    def spy(cmd, **kwargs):
        recorded["cmd"] = cmd
        recorded["shell"] = kwargs.get("shell")
        return real_popen(cmd, **kwargs)

    monkeypatch.setattr("core.job_manager.subprocess.Popen", spy)

    job = manager.start("echo hi", shell=True, timeout=10)
    completed = wait_for_terminal(manager, job["job_id"])

    assert recorded["cmd"] == [
        job_manager_module._STDBUF_PATH,
        "-oL",
        "-eL",
        "/bin/sh",
        "-c",
        "echo hi",
    ]
    assert recorded["shell"] is False
    assert completed["status"] == "succeeded"
    assert manager.read_output(job["job_id"], lines=10)["stdout"] == ["hi"]


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


# ---------------------------------------------------------------------------
# Enumeration. Every other kind of server-side state can be listed --
# msf_session_list, ssh_sessions, hosts_list, pivot_list_tunnels -- and jobs,
# the one kind the whole background mechanism depends on, could not be. An agent
# that loses a job_id to a context compaction had an unrecoverable running scan.
# ---------------------------------------------------------------------------


def test_list_reports_every_tracked_job(manager):
    first = manager.start(python_command("print('one')"), shell=False, timeout=5)
    second = manager.start(python_command("print('two')"), shell=False, timeout=5)
    wait_for_terminal(manager, first["job_id"])
    wait_for_terminal(manager, second["job_id"])

    listed = manager.list()

    by_id = {job["job_id"]: job for job in listed}
    assert set(by_id) == {first["job_id"], second["job_id"]}
    assert by_id[first["job_id"]]["status"] == "succeeded"
    assert by_id[second["job_id"]]["status"] == "succeeded"
    assert all(job["return_code"] == 0 for job in listed)


def test_list_carries_no_output(manager):
    """A listing has to stay cheap and bounded no matter how many jobs are held
    -- max_jobs is 256, each with up to 2MB of buffered output. read_output is
    where output comes from; putting it here turns "which of my scans are still
    running" into a multi-megabyte answer."""
    job = manager.start(python_command("print('loud')"), shell=False, timeout=5)
    wait_for_terminal(manager, job["job_id"])
    assert manager.read_output(job["job_id"], lines=10)["stdout"] == ["loud"]

    entry = manager.list()[0]

    assert set(entry) <= set(manager.get(job["job_id"]))
    for banned in ("output", "stdout", "stderr", "events"):
        assert banned not in entry, f"list() leaked {banned}"


def test_list_returns_the_newest_job_first(manager):
    older = manager.start(python_command("print('older')"), shell=False, timeout=5)
    wait_for_terminal(manager, older["job_id"])
    newer = manager.start(python_command("print('newer')"), shell=False, timeout=5)
    wait_for_terminal(manager, newer["job_id"])

    assert [job["job_id"] for job in manager.list()] == [
        newer["job_id"],
        older["job_id"],
    ]


def test_list_is_empty_rather_than_an_error_when_nothing_has_run(manager):
    assert manager.list() == []
