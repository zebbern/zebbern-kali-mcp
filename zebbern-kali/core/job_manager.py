"""In-memory lifecycle management for background command jobs."""

from __future__ import annotations

import math
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence, Union


Command = Union[str, Sequence[str]]
TERMINAL_STATES = frozenset({"succeeded", "failed", "canceled", "timed_out"})


@dataclass
class _Job:
    job_id: str
    command: Command
    cwd: Optional[str]
    shell: bool
    timeout: float
    max_output_lines: int
    max_output_chars: int
    max_pending_inputs: int
    status: str = "queued"
    pid: Optional[int] = None
    process_group_id: Optional[int] = None
    return_code: Optional[int] = None
    timed_out: bool = False
    cancel_requested: bool = False
    output_truncated: bool = False
    output_closed: bool = False
    output_chars: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    events: deque[dict[str, str]] = field(default_factory=deque)
    process: Optional[subprocess.Popen[str]] = field(default=None, repr=False)
    input_queue: queue.Queue[Optional[str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.input_queue = queue.Queue(maxsize=self.max_pending_inputs)


class JobManager:
    """Own background processes and bounded I/O in one server process."""

    def __init__(
        self,
        max_jobs: int = 256,
        max_output_lines: int = 2000,
        max_output_chars: int = 2 * 1024 * 1024,
        max_line_chars: int = 4096,
        max_input_bytes: int = 64 * 1024,
        max_pending_inputs: int = 16,
        max_output_wait: float = 30,
        drain_timeout: float = 2,
    ):
        limits = {
            "max_jobs": max_jobs,
            "max_output_lines": max_output_lines,
            "max_output_chars": max_output_chars,
            "max_line_chars": max_line_chars,
            "max_input_bytes": max_input_bytes,
            "max_pending_inputs": max_pending_inputs,
        }
        for name, value in limits.items():
            if value < 1:
                raise ValueError(f"{name} must be at least 1")
        if not math.isfinite(max_output_wait) or max_output_wait < 0:
            raise ValueError("max_output_wait must be a finite non-negative value")
        if not math.isfinite(drain_timeout) or drain_timeout < 0:
            raise ValueError("drain_timeout must be a finite non-negative value")

        self.max_jobs = max_jobs
        self.max_output_lines = max_output_lines
        self.max_output_chars = max_output_chars
        self.max_line_chars = max_line_chars
        self.max_input_bytes = max_input_bytes
        self.max_pending_inputs = max_pending_inputs
        self.max_output_wait = float(max_output_wait)
        self.drain_timeout = float(drain_timeout)
        self._jobs: dict[str, _Job] = {}
        self._stopping = False
        self._condition = threading.Condition(threading.RLock())

    def start(
        self,
        command: Command,
        *,
        cwd: Optional[str] = None,
        shell: bool = True,
        timeout: float = 3600,
    ) -> dict[str, Any]:
        """Start a command and return its initial job metadata."""
        if not command:
            raise ValueError("command must not be empty")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite value greater than zero")

        job = _Job(
            job_id=str(uuid.uuid4()),
            command=command,
            cwd=cwd,
            shell=shell,
            timeout=float(timeout),
            max_output_lines=self.max_output_lines,
            max_output_chars=self.max_output_chars,
            max_pending_inputs=self.max_pending_inputs,
        )
        with self._condition:
            if self._stopping:
                raise RuntimeError("Job manager is shutting down")
            self._make_room()
            self._jobs[job.job_id] = job

        popen_options: dict[str, Any] = {
            "shell": shell,
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": cwd,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "bufsize": 1,
        }
        if os.name == "nt":
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_options["start_new_session"] = True

        try:
            process = subprocess.Popen(command, **popen_options)
        except Exception as exc:
            with self._condition:
                job.status = "failed"
                job.error = str(exc)
                job.output_closed = True
                job.finished_at = time.time()
                self._condition.notify_all()
            raise

        with self._condition:
            job.process = process
            job.pid = process.pid
            job.process_group_id = process.pid
            job.started_at = time.time()
            job.status = "running"
            cancel_after_start = job.cancel_requested
            initial_metadata = self._metadata(job)
            self._condition.notify_all()

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_thread = threading.Thread(
            target=self._drain_stream,
            args=(job, "stdout", process.stdout),
            daemon=True,
            name=f"job-{job.job_id}-stdout",
        )
        stderr_thread = threading.Thread(
            target=self._drain_stream,
            args=(job, "stderr", process.stderr),
            daemon=True,
            name=f"job-{job.job_id}-stderr",
        )
        input_thread = threading.Thread(
            target=self._write_input,
            args=(job, process),
            daemon=True,
            name=f"job-{job.job_id}-stdin",
        )
        watcher_thread = threading.Thread(
            target=self._watch,
            args=(job, process, stdout_thread, stderr_thread),
            daemon=True,
            name=f"job-{job.job_id}-watcher",
        )
        stdout_thread.start()
        stderr_thread.start()
        input_thread.start()
        watcher_thread.start()
        if cancel_after_start:
            self._terminate_process_tree(process, job.process_group_id)
        return initial_metadata

    def get(self, job_id: str) -> dict[str, Any]:
        """Return serializable metadata for one job."""
        with self._condition:
            return self._metadata(self._require_job(job_id))

    def read_output(
        self,
        job_id: str,
        *,
        timeout: float = 0,
        lines: int = 100,
    ) -> dict[str, Any]:
        """Return recent bounded output, optionally waiting for the first line."""
        if lines < 1:
            raise ValueError("lines must be at least 1")
        if not math.isfinite(timeout):
            raise ValueError("timeout must be finite")
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        if timeout > self.max_output_wait:
            raise ValueError(f"timeout cannot exceed {self.max_output_wait:g} seconds")

        with self._condition:
            job = self._require_job(job_id)
            if timeout and not job.events and job.status not in TERMINAL_STATES:
                self._condition.wait_for(
                    lambda: bool(job.events) or job.status in TERMINAL_STATES,
                    timeout=timeout,
                )

            events = list(job.events)[-lines:]
            stdout = [event["line"] for event in events if event["source"] == "stdout"]
            stderr = [event["line"] for event in events if event["source"] == "stderr"]
            return {
                "success": job.status in {"queued", "running", "succeeded"},
                "job_success": (
                    job.status == "succeeded" if job.status in TERMINAL_STATES else None
                ),
                "job_id": job.job_id,
                "session_id": job.job_id,
                "status": job.status,
                "stdout": stdout,
                "stderr": stderr,
                "events": events,
                "output": "\n".join(event["line"] for event in events),
                "lines_returned": len(events),
                "output_truncated": job.output_truncated,
            }

    def send_input(self, job_id: str, input_text: str) -> dict[str, Any]:
        """Queue bounded text for a running job's standard input."""
        input_size = len(input_text.encode("utf-8"))
        if input_size > self.max_input_bytes:
            return {
                "success": False,
                "job_id": job_id,
                "session_id": job_id,
                "error": f"Input exceeds maximum size of {self.max_input_bytes} bytes",
            }

        with self._condition:
            job = self._require_job(job_id)
            process = job.process
            if (
                job.status != "running"
                or job.cancel_requested
                or process is None
                or process.stdin is None
                or process.poll() is not None
            ):
                return {
                    "success": False,
                    "job_id": job.job_id,
                    "session_id": job.job_id,
                    "error": f"Job is not accepting input (status: {job.status})",
                }
            try:
                job.input_queue.put_nowait(input_text)
            except queue.Full:
                return {
                    "success": False,
                    "job_id": job.job_id,
                    "session_id": job.job_id,
                    "error": "Job input queue is full",
                }

        return {
            "success": True,
            "job_id": job_id,
            "session_id": job_id,
            "queued_bytes": input_size,
        }

    def cancel(self, job_id: str) -> dict[str, Any]:
        """Cancel a running job and its process group."""
        with self._condition:
            job = self._require_job(job_id)
            if job.status in TERMINAL_STATES:
                return {
                    "success": False,
                    "job_id": job.job_id,
                    "status": job.status,
                    "error": f"Job is already {job.status}",
                }
            process = job.process
            if process is None:
                job.cancel_requested = True
                self._condition.notify_all()
                return {
                    "success": True,
                    "job_id": job.job_id,
                    "status": "canceling",
                }
            if process.poll() is not None:
                return {
                    "success": False,
                    "job_id": job.job_id,
                    "status": job.status,
                    "error": "Job process has already exited and is completing",
                }
            job.cancel_requested = True
            process_group_id = job.process_group_id
            self._condition.notify_all()

        self._terminate_process_tree(process, process_group_id)
        return {
            "success": True,
            "job_id": job.job_id,
            "status": "canceling",
        }

    def shutdown(self) -> None:
        """Request cancellation for every running job owned by this manager."""
        with self._condition:
            self._stopping = True
            active_ids = [
                job_id
                for job_id, job in self._jobs.items()
                if job.status not in TERMINAL_STATES
            ]
        for job_id in active_ids:
            self.cancel(job_id)

    def _make_room(self) -> None:
        while len(self._jobs) >= self.max_jobs:
            terminal_id = next(
                (
                    job_id
                    for job_id, job in self._jobs.items()
                    if job.status in TERMINAL_STATES
                ),
                None,
            )
            if terminal_id is None:
                raise RuntimeError("Job registry is full with active jobs")
            del self._jobs[terminal_id]

    def _require_job(self, job_id: str) -> _Job:
        try:
            return self._jobs[job_id]
        except KeyError as exc:
            raise KeyError(f"Unknown job: {job_id}") from exc

    @staticmethod
    def _metadata(job: _Job) -> dict[str, Any]:
        data = {
            "success": job.status in {"queued", "running", "succeeded"},
            "job_id": job.job_id,
            "session_id": job.job_id,
            "status": job.status,
            "pid": job.pid,
            "return_code": job.return_code,
            "timed_out": job.timed_out,
            "cancel_requested": job.cancel_requested,
            "output_truncated": job.output_truncated,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
        }
        if job.error:
            data["error"] = job.error
        return data

    def _append_output(self, job: _Job, source: str, line: str) -> None:
        if len(line) > self.max_line_chars:
            line = line[:self.max_line_chars]
            job.output_truncated = True

        while job.events and (
            len(job.events) >= job.max_output_lines
            or job.output_chars + len(line) > job.max_output_chars
        ):
            removed = job.events.popleft()
            job.output_chars -= len(removed["line"])
            job.output_truncated = True

        if len(line) > job.max_output_chars:
            line = line[:job.max_output_chars]
            job.output_truncated = True

        job.events.append({"source": source, "line": line})
        job.output_chars += len(line)

    def _drain_stream(self, job: _Job, source: str, stream) -> None:
        try:
            while True:
                raw_line = stream.readline(self.max_line_chars + 1)
                if raw_line == "":
                    break
                line = raw_line.rstrip("\r\n")
                with self._condition:
                    if job.output_closed:
                        break
                    self._append_output(job, source, line)
                    self._condition.notify_all()
        finally:
            stream.close()

    @staticmethod
    def _write_input(job: _Job, process: subprocess.Popen[str]) -> None:
        assert process.stdin is not None
        while True:
            input_text = job.input_queue.get()
            if input_text is None:
                break
            try:
                process.stdin.write(input_text)
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                break

    def _watch(
        self,
        job: _Job,
        process: subprocess.Popen[str],
        stdout_thread: threading.Thread,
        stderr_thread: threading.Thread,
    ) -> None:
        terminal_status: Optional[str] = None
        try:
            return_code = process.wait(timeout=job.timeout)
        except subprocess.TimeoutExpired:
            terminal_status = "timed_out"
            self._terminate_process_tree(process, job.process_group_id)
            return_code = process.wait()

        # A shell leader can exit while descendants keep inherited pipes open.
        # A job owns its process group, so no descendant outlives completion.
        self._terminate_remaining_group(job.process_group_id)
        stdout_thread.join(timeout=self.drain_timeout)
        stderr_thread.join(timeout=self.drain_timeout)

        with self._condition:
            job.output_closed = True
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                job.output_truncated = True
            job.return_code = return_code
            if terminal_status == "timed_out":
                job.status = "timed_out"
                job.timed_out = True
                job.error = f"Command timed out after {job.timeout:g} seconds"
            elif job.cancel_requested:
                job.status = "canceled"
            else:
                job.status = "succeeded" if return_code == 0 else "failed"
            job.finished_at = time.time()
            self._condition.notify_all()

        try:
            job.input_queue.put_nowait(None)
        except queue.Full:
            pass

    @staticmethod
    def _posix_group_exists(process_group_id: int) -> bool:
        try:
            os.killpg(process_group_id, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _terminate_remaining_group(self, process_group_id: Optional[int]) -> None:
        if process_group_id is None:
            return
        if os.name == "nt":
            try:
                os.kill(process_group_id, signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError):
                pass
            return
        if self._posix_group_exists(process_group_id):
            self._terminate_posix_group(process_group_id)

    def _terminate_process_tree(
        self,
        process: subprocess.Popen[str],
        process_group_id: Optional[int],
    ) -> None:
        if os.name != "nt":
            if process_group_id is not None:
                self._terminate_posix_group(process_group_id)
            elif process.poll() is None:
                process.terminate()
            return

        try:
            taskkill = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            taskkill = None
        if taskkill is not None and taskkill.returncode == 0:
            return
        if process_group_id is not None:
            try:
                os.kill(process_group_id, signal.CTRL_BREAK_EVENT)
                process.wait(timeout=1)
                return
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            process.kill()

    def _terminate_posix_group(self, process_group_id: int) -> None:
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            return

        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if not self._posix_group_exists(process_group_id):
                return
            time.sleep(0.02)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass


job_manager = JobManager(
    max_jobs=int(os.environ.get("JOB_MAX_COUNT", "256")),
    max_output_lines=int(os.environ.get("JOB_OUTPUT_MAX_LINES", "2000")),
    max_output_chars=int(os.environ.get("JOB_OUTPUT_MAX_CHARS", str(2 * 1024 * 1024))),
    max_line_chars=int(os.environ.get("JOB_OUTPUT_MAX_LINE_CHARS", "4096")),
    max_input_bytes=int(os.environ.get("JOB_INPUT_MAX_BYTES", str(64 * 1024))),
    max_pending_inputs=int(os.environ.get("JOB_INPUT_QUEUE_SIZE", "16")),
    max_output_wait=float(os.environ.get("JOB_OUTPUT_MAX_WAIT", "30")),
)
