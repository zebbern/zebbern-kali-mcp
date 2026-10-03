"""Golden-master replay engine for the three PTY managers' read paths.

This is the SINGLE timeline-replay engine. It is written to be reused by the
later extraction work (A3): it records, *before any manager is touched*, the
exact operator-facing output of the three managers' read paths so the
extraction can be asserted byte-identical against frozen fixtures instead of
being an untestable rewrite.

Why a replay engine and not real PTYs
-------------------------------------
``pty.openpty`` does not exist on Windows, where this records, and even on Linux
a real PTY makes timing-dependent output non-deterministic. The managers never
read a PTY directly: they go through ``os.read`` / ``select.select`` /
``os.write`` and pace themselves with ``time``. So the loops can be driven
deterministically by feeding a *scripted timeline* of byte chunks through those
exact calls, with a controllable clock, and recording the full return value.

The engine reuses the suite's existing Windows seam (see
``tests/test_reverse_shell_raw_io.py``): ``sys.modules.setdefault('pty', stub)``
with ``openpty -> (0, 0)``, builds the REAL manager via its constructor (which
opens no PTY -- ``master_fd=None`` at RS:88 / MSF:81 / SSH:26), sets
``master_fd = 99``, and installs per-module proxies for the four stdlib modules
the read paths touch.

The split patch surface, stated explicitly (it matters to A3)
-------------------------------------------------------------
Each manager module is patched *in place* (its ``os`` / ``select`` / ``time`` /
``uuid`` module-level names are swapped for proxies and restored on exit), so
the global stdlib modules are never mutated and nothing leaks to the rest of the
suite. Of those names:

* ``os.read`` / ``select.select`` / ``os.write`` are the PTY I/O. A3 moved the
  fd loop into the new ``core.pty_session`` helper, but each manager still wires
  its ``PtySession`` to its OWN module-level ``os.read`` / ``select.select`` /
  ``os.write`` (the ``_read`` / ``_select`` / ``_write`` seam, resolved at call
  time), so this recorder's existing in-place patching of each manager module
  still drives the extracted loop -- no ``pty_session`` patch was needed and the
  fixtures stayed byte-identical across the extraction. They are the whole reason
  this is testable without a real PTY: inject the read/select/write and the fd
  loop has no real file descriptor behind it.
* ``time.time`` (the controllable clock) stays patched on the *manager module*,
  because the deadline loops that read it stay in the manager and are not part
  of the fd lifecycle A3 extracts: ``while time.time() - start < timeout`` at
  RS:558 / RS:727 / RS:1018 and MSF:258. ``time.sleep`` is a near-noop that only
  yields the GIL so a manager's background reader thread (MSF) can run.
* ``uuid.uuid4`` is made deterministic so the markers the managers generate
  (``START_*`` / ``END_*`` / ``SSH_END_*``) are known in advance and can be
  written into the scripted chunks.

Only ``execution_time`` is normalized out of the recorded dicts: it is a float
derived from how many times the clock was read, which a background reader thread
perturbs, so pinning it would make the fixture brittle without guarding
anything. Every other byte and flag is frozen exactly.
"""

import json
import os as _real_os
import sys
import threading
import time as _real_time
import uuid as _real_uuid
from pathlib import Path
from types import ModuleType

# --- Windows seam: stub pty before importing the managers -------------------
BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

if _real_os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

from core import metasploit_manager as msf_module  # noqa: E402
from core import reverse_shell_manager as rs_module  # noqa: E402
from core import ssh_manager as ssh_module  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "pty_golden"
MASTER_FD = 99

# Sentinel for a scripted os.read that returns b"" (EOF / far end gone).
EOF = object()


def _uuid_sequence():
    """Deterministic uuid4() replacements with distinct 8-char prefixes.

    ``str(u)[:8]`` and ``u.hex[:8]`` -- the two forms the managers slice -- both
    become 'aaaaaaaa', 'bbbbbbbb', ... so the START_/END_/SSH_END_/PRELUDE_
    markers are known and can be embedded in the scripted chunks.
    """
    for letter in "abcdefghij":
        yield _real_uuid.UUID(hex=(letter * 8) + ("0" * 24))


class _ModuleProxy:
    """Delegates every attribute to the real module except the overrides.

    Lets the manager code run unchanged (``os.read``, ``time.time`` ... resolve
    through this) while leaving the real stdlib modules untouched.
    """

    def __init__(self, real, overrides):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_overrides", overrides)

    def __getattr__(self, name):
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_real"), name)


class _Timeline:
    """A scripted sequence of byte chunks fed through os.read / select.select.

    ``select`` reports ready only once a write has happened (so a manager that
    clears its buffer and writes a command before reading sees the response, not
    stale bytes) and while chunks remain. ``read`` honours the requested size and
    carries any remainder, like a real ``os.read``. ``time`` is a monotonic clock
    advancing ``clock_step`` per call; ``clock_step == 0`` freezes it so a loop
    that must terminate on a stability/marker condition cannot time out first.
    A real-wall-clock watchdog turns an accidental infinite loop into a loud
    failure instead of a hang.
    """

    def __init__(self, chunks, clock_step, gate_on_write, watchdog=5.0):
        self._chunks = list(chunks)
        self._remainder = b""
        self._lock = threading.Lock()
        self._clock = 0.0
        self._clock_step = clock_step
        self._command_sent = not gate_on_write
        self._reader_starter = None
        self._reader_started = False
        self._watchdog = watchdog
        self._real_start = _real_time.monotonic()
        self.writes = []

    def set_reader_starter(self, starter):
        self._reader_starter = starter

    def select(self, rlist, wlist=None, xlist=None, timeout=None):
        with self._lock:
            ready = self._command_sent and (bool(self._chunks) or bool(self._remainder))
        return (list(rlist) if ready else [], [], [])

    def read(self, fd, size):
        with self._lock:
            if self._remainder:
                out, self._remainder = self._remainder[:size], self._remainder[size:]
                return out
            if not self._chunks:
                return b""
            chunk = self._chunks.pop(0)
            if chunk is EOF:
                return b""
            if len(chunk) > size:
                out, self._remainder = chunk[:size], chunk[size:]
                return out
            return chunk

    def write(self, fd, data):
        with self._lock:
            self.writes.append((fd, bytes(data)))
            self._command_sent = True
            start = (not self._reader_started) and self._reader_starter is not None
            if start:
                self._reader_started = True
        if start:
            self._reader_starter()
        return len(data)

    def time(self):
        if _real_time.monotonic() - self._real_start > self._watchdog:
            raise RuntimeError(
                "pty golden replay watchdog fired: a manager loop did not "
                "terminate within the real-time budget"
            )
        value = self._clock
        self._clock += self._clock_step
        return value

    def sleep(self, _seconds):
        # Never actually block -- a fixture must replay in milliseconds -- but
        # yield so a manager's background reader thread (MSF) is scheduled.
        _real_time.sleep(0)


class _AliveProc:
    """A stand-in process that is always running."""

    def poll(self):
        return None


class _DyingProc:
    """Running for the first ``alive_calls`` poll()s, then exited.

    Lets MSF.execute pass its 'is the session running' pre-check and then
    observe the console die inside the wait loop.
    """

    def __init__(self, alive_calls=1):
        self._alive_calls = alive_calls
        self._calls = 0

    def poll(self):
        self._calls += 1
        return None if self._calls <= self._alive_calls else 0


class PtyGoldenReplay:
    """Context manager installing the proxies on one manager module.

    Build the real manager with one of the ``reverse_shell`` / ``ssh`` / ``msf``
    helpers, then call its read-path method; the scripted timeline drives it.
    """

    def __init__(self, module, chunks, *, clock_step=0.5, gate_on_write=True,
                 watchdog=5.0):
        self.module = module
        self.timeline = _Timeline(chunks, clock_step, gate_on_write, watchdog)
        self._saved = {}
        self._threads = []

    def __enter__(self):
        module = self.module
        timeline = self.timeline
        self._saved = {
            "os": module.os,
            "select": module.select,
            "time": module.time,
            "uuid": module.uuid,
        }
        sequence = _uuid_sequence()
        module.os = _ModuleProxy(self._saved["os"],
                                 {"read": timeline.read, "write": timeline.write})
        module.select = _ModuleProxy(self._saved["select"],
                                     {"select": timeline.select})
        module.time = _ModuleProxy(self._saved["time"],
                                   {"time": timeline.time, "sleep": timeline.sleep})
        module.uuid = _ModuleProxy(self._saved["uuid"],
                                   {"uuid4": lambda: next(sequence)})
        return self

    def __exit__(self, *exc):
        # Stop any reader thread while the proxies are still installed, so it
        # never touches a restored real module on the way out.
        for _thread, stop in self._threads:
            stop()
        for thread, _stop in self._threads:
            thread.join(timeout=2.0)
        module = self.module
        module.os = self._saved["os"]
        module.select = self._saved["select"]
        module.time = self._saved["time"]
        module.uuid = self._saved["uuid"]
        return False

    # -- manager builders (constructor only: no PTY is opened) ---------------
    def reverse_shell(self, connected=True, master_fd=MASTER_FD):
        session = rs_module.ReverseShellManager(4444, "golden_rs", "netcat")
        session.is_connected = connected
        session.master_fd = master_fd
        return session

    def ssh(self, connected=True, master_fd=MASTER_FD):
        session = ssh_module.SSHSessionManager(
            "10.0.0.1", "root", session_id="golden_ssh"
        )
        session.is_connected = connected
        session.master_fd = master_fd
        return session

    def msf(self, process, master_fd=MASTER_FD):
        session = msf_module.MetasploitSession("golden_msf")
        session.master_fd = master_fd
        session.process = process
        return session

    def start_reader(self, session):
        """Register MSF's background reader; it starts on the first os.write.

        Deferring the start to the first write is what lets execute() clear its
        buffer first, so the reader only ever feeds the command's response.
        """
        session._running = True
        thread = threading.Thread(target=session._read_output, daemon=True)

        def stop():
            session._running = False

        self._threads.append((thread, stop))
        self.timeline.set_reader_starter(thread.start)


def _normalize(obj):
    """Drop only the clock-derived execution_time; freeze everything else."""
    if isinstance(obj, dict):
        return {
            key: ("<normalized:execution_time>" if key == "execution_time"
                  else _normalize(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_normalize(item) for item in obj]
    return obj


# --- the recorded cases -----------------------------------------------------
# Each returns a JSON-serialisable object (a return dict, or a list of
# {output, carry_over} for the multi-call read_output windows).

CASES = {}


def _case(name):
    def register(func):
        CASES[name] = func
        return func
    return register


# Deterministic markers, given the uuid sequence above.
_START = "START_aaaaaaaa"
_END = "END_bbbbbbbb"
_SSH_END = "SSH_END_aaaaaaaa"
_B64_CLEAN = "UmVhbCBkb3dubG9hZCB0ZXN0"                      # b64("Real download test")
_B64_CONCAT = "UmVhbCBkb3dubG9hZCB0ZXN0IDE3NTQxNDk3NTEK"    # b64("Real download test 1754149751\n")


@_case("rs_send_command_executed_marker_success")
def _rs_success():
    chunks = [
        b"echo 'START_aaaaaaaa'\r\nSTART_aaaaaaaa\r\n"
        b"whoami\r\nuid=0(root)\r\n"
        b"echo 'END_bbbbbbbb'\r\nEND_bbbbbbbb\r\n"
    ]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command("whoami", timeout=5, suppress_history=False)
    return _normalize(result)


@_case("rs_send_command_marker_echo_only_live_but_silent")
def _rs_echo_only():
    # The far end echoes the typed echo-commands but never runs them, so no
    # executed marker line appears: success False, lines_captured 0.
    chunks = [b"echo 'START_aaaaaaaa'\r\necho 'END_bbbbbbbb'\r\n"]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command("whoami", timeout=2, suppress_history=False)
    return _normalize(result)


@_case("rs_send_command_eof_mid_capture")
def _rs_eof():
    chunks = [
        b"echo 'START_aaaaaaaa'\r\nSTART_aaaaaaaa\r\n"
        b"cat /etc/passwd\r\nroot:x:0:0:root:/root:/bin/bash\r\n",
        EOF,
    ]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command(
            "cat /etc/passwd", timeout=5, suppress_history=False
        )
    return _normalize(result)


@_case("rs_send_command_timeout_no_end_marker")
def _rs_timeout():
    chunks = [
        b"echo 'START_aaaaaaaa'\r\nSTART_aaaaaaaa\r\n"
        b"sleep 100; echo done\r\nslow output line\r\n"
    ]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command(
            "sleep 100; echo done", timeout=2, suppress_history=False
        )
    return _normalize(result)


@_case("rs_send_command_base64_concatenated_trailing_echo")
def _rs_base64_concat():
    chunks = [
        b"echo 'START_aaaaaaaa'\r\nSTART_aaaaaaaa\r\n",
        b"UmVhbCBkb3dubG9hZCB0ZXN0IDE3NTQxNDk3NTEKecho 'END_bbbbbbbb'\r\n"
        b"END_bbbbbbbb\r\n",
    ]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command(
            "cat f | base64", timeout=5, suppress_history=False
        )
    return _normalize(result)


@_case("rs_send_command_base64_clean")
def _rs_base64_clean():
    chunks = [
        b"echo 'START_aaaaaaaa'\r\nSTART_aaaaaaaa\r\n",
        b"UmVhbCBkb3dubG9hZCB0ZXN0\r\necho 'END_bbbbbbbb'\r\nEND_bbbbbbbb\r\n",
    ]
    with PtyGoldenReplay(rs_module, chunks) as rep:
        session = rep.reverse_shell()
        result = session.send_command(
            "cat f | base64", timeout=5, suppress_history=False
        )
    return _normalize(result)


@_case("rs_read_output_burst_exceeds_max_lines")
def _rs_read_output_burst():
    burst = b"".join(b"line%02d\r\n" % n for n in range(1, 13))  # 12 lines
    chunks = [burst]
    with PtyGoldenReplay(rs_module, chunks, gate_on_write=False) as rep:
        session = rep.reverse_shell()
        windows = []
        for _ in range(3):
            out = session.read_output(timeout=1, max_lines=4)
            windows.append({"output": out, "carry_over": session.raw_carry_over()})
    return _normalize(windows)


@_case("rs_read_output_newline_less_remainder")
def _rs_read_output_remainder():
    chunks = [b"uid=33\r\nPassword: "]
    with PtyGoldenReplay(rs_module, chunks, gate_on_write=False) as rep:
        session = rep.reverse_shell()
        out = session.read_output(timeout=1)
        windows = [{"output": out, "carry_over": session.raw_carry_over()}]
    return _normalize(windows)


@_case("ssh_send_command_marker_success")
def _ssh_success():
    chunks = [b"whoami\r\nuid=0(root)\r\necho 'SSH_END_aaaaaaaa'\r\n"]
    with PtyGoldenReplay(ssh_module, chunks) as rep:
        session = rep.ssh()
        result = session.send_command("whoami", timeout=5)
    return _normalize(result)


@_case("ssh_send_command_timeout")
def _ssh_timeout():
    chunks = [b"uid=0(root)\r\n"]
    with PtyGoldenReplay(ssh_module, chunks) as rep:
        session = rep.ssh()
        result = session.send_command("sleep 100", timeout=2)
    return _normalize(result)


@_case("msf_execute_prompt_reached_exact_msf")
def _msf_exact_msf():
    chunks = [
        b"sessions -l\r\n\r\nActive sessions\r\n===============\r\n"
        b"No active sessions.\r\n\r\nmsf6 > "
    ]
    with PtyGoldenReplay(msf_module, chunks, clock_step=0.0) as rep:
        session = rep.msf(process=_AliveProc())
        rep.start_reader(session)
        result = session.execute("sessions -l", timeout=1_000_000.0, read_delay=0)
    return _normalize(result)


@_case("msf_execute_prompt_reached_meterpreter")
def _msf_meterpreter():
    chunks = [
        b"sysinfo\r\nComputer     : TARGET\r\nOS           : Windows\r\n"
        b"meterpreter > "
    ]
    with PtyGoldenReplay(msf_module, chunks, clock_step=0.0) as rep:
        session = rep.msf(process=_AliveProc())
        rep.start_reader(session)
        result = session.execute("sysinfo", timeout=1_000_000.0, read_delay=0)
    return _normalize(result)


@_case("msf_execute_prompt_reached_generic_prompt")
def _msf_generic():
    chunks = [
        b"shell\r\nProcess 1 created.\r\nid\r\nuid=0(root) gid=0(root)\r\n"
        b"root@target:/root# "
    ]
    with PtyGoldenReplay(msf_module, chunks, clock_step=0.0) as rep:
        session = rep.msf(process=_AliveProc())
        rep.start_reader(session)
        result = session.execute("shell", timeout=1_000_000.0, read_delay=0)
    return _normalize(result)


@_case("msf_execute_console_exited_mid_wait")
def _msf_console_exited():
    with PtyGoldenReplay(msf_module, [], clock_step=0.5) as rep:
        session = rep.msf(process=_DyingProc(alive_calls=1))
        result = session.execute("run", timeout=2, read_delay=0)
    return _normalize(result)


@_case("msf_execute_budget_expiry_timed_out")
def _msf_timeout():
    with PtyGoldenReplay(msf_module, [], clock_step=0.5) as rep:
        session = rep.msf(process=_AliveProc())
        result = session.execute("run", timeout=2, read_delay=0)
    return _normalize(result)


def run_case(name):
    """Replay a single case through the CURRENT managers and return its result."""
    return CASES[name]()


def _record_all():
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name in sorted(CASES):
        result = run_case(name)
        path = FIXTURE_DIR / f"{name}.json"
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True)
        path.write_text(text + "\n", encoding="utf-8")
        print(f"recorded {name} -> {path}")


if __name__ == "__main__":
    _record_all()
