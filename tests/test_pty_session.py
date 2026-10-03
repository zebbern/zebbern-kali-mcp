"""Unit tests for core.pty_session.PtySession, through injected io only.

``pty.openpty`` does not exist on Windows, so the fd loop cannot be driven
against a real PTY here. The whole point of the ``_select``/``_read``/
``_write``/``_killpg`` seam is that it does not have to be: ``read``'s three-way
return, ``write``'s short-write passthrough and ``close``'s escalation ladder
are reachable with scripted fakes and no PTY at all. ``spawn()`` -- the one
PTY-dependent surface -- is straight-line and left to the live backstop.

``core.pty_session`` imports ``pty`` at module top like the three managers it
extracts, so Windows needs the stub the rest of the suite already installs.
"""

import os
import signal
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

if os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

from core.pty_session import PtySession, _ANSI_RE
from core import ssh_manager as ssh_module

MASTER_FD = 99
SIGKILL = getattr(signal, "SIGKILL", 9)


class _Recorder:
    """A callable that records its positional args and returns a scripted value."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


class _Proc:
    """A stand-in Popen: scripted ``wait`` plus pid and terminate/kill flags."""

    def __init__(self, pid, wait_behaviors):
        self.pid = pid
        self._wait = list(wait_behaviors)
        self.terminated = False
        self.killed = False

    def wait(self, timeout=None):
        behavior = self._wait.pop(0)
        if isinstance(behavior, Exception):
            raise behavior
        return behavior

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def poll(self):
        return None


# --------------------------------------------------------------------------
# read: the three-way None / b'' / bytes return
# --------------------------------------------------------------------------

def test_read_returns_none_when_nothing_is_ready():
    select_fn = _Recorder(([], [], []))
    read_fn = _Recorder(b"unused")
    sess = PtySession(MASTER_FD, _select=select_fn, _read=read_fn)

    assert sess.read(0.25) is None
    # Exactly one select, over the master fd, with the caller's timeout.
    assert select_fn.calls == [([MASTER_FD], [], [], 0.25)]
    # Nothing ready means os.read is never reached.
    assert read_fn.calls == []


def test_read_returns_empty_bytes_on_eof():
    select_fn = _Recorder(([MASTER_FD], [], []))
    read_fn = _Recorder(b"")
    sess = PtySession(MASTER_FD, _select=select_fn, _read=read_fn)

    assert sess.read(0.25) == b""
    assert read_fn.calls == [(MASTER_FD, 4096)]


def test_read_returns_bytes_when_data_is_present():
    select_fn = _Recorder(([MASTER_FD], [], []))
    read_fn = _Recorder(b"loot")
    sess = PtySession(MASTER_FD, _select=select_fn, _read=read_fn)

    assert sess.read(0.25, size=1024) == b"loot"
    assert read_fn.calls == [(MASTER_FD, 1024)]


# --------------------------------------------------------------------------
# write: the short-write count is reported unchanged
# --------------------------------------------------------------------------

def test_write_returns_the_raw_short_count_unchanged():
    write_fn = _Recorder(2)  # wrote 2 of the 5 bytes
    sess = PtySession(MASTER_FD, _write=write_fn)

    assert sess.write(b"hello") == 2
    assert write_fn.calls == [(MASTER_FD, b"hello")]


# --------------------------------------------------------------------------
# close: the SIGTERM -> wait -> SIGKILL escalation / survivor-reap ladder
# --------------------------------------------------------------------------

def _pipe_fd():
    """A real, closeable fd so close()'s os.close path is exercised safely.

    A bare integer like 99 risks clobbering a live descriptor; a pipe read end
    is guaranteed to be ours.
    """
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    return read_fd


def _fd_is_closed(fd):
    try:
        os.close(fd)
    except OSError:
        return True
    return False


def test_close_escalates_to_sigkill_when_sigterm_is_ignored():
    killpg = _Recorder(None)
    proc = _Proc(pid=4321, wait_behaviors=[
        subprocess.TimeoutExpired(cmd="x", timeout=5),  # survives SIGTERM
        0,                                               # dies on SIGKILL
    ])
    fd = _pipe_fd()
    sess = PtySession(fd, process=proc, _killpg=killpg)

    sess.close()

    # SIGTERM to the group, then SIGKILL to the group; no per-process fallback.
    assert killpg.calls == [(4321, signal.SIGTERM), (4321, SIGKILL)]
    assert proc.terminated is False
    assert proc.killed is False
    # Escalation ran, so the survivor probe (killpg(pg, 0)) is skipped.
    assert (4321, 0) not in killpg.calls
    # The master fd was closed.
    assert sess.master_fd is None
    assert _fd_is_closed(fd)


def test_close_reaps_a_surviving_child_after_the_leader_exits():
    # SIGTERM lands, leader exits, but a child still holds the group open: the
    # killpg(pg, 0) probe does NOT raise, so the group is SIGKILLed.
    killpg = _Recorder(None)
    proc = _Proc(pid=777, wait_behaviors=[0])  # dies on SIGTERM
    fd = _pipe_fd()
    sess = PtySession(fd, process=proc, _killpg=killpg)

    sess.close()

    assert killpg.calls == [(777, signal.SIGTERM), (777, 0), (777, SIGKILL)]
    assert sess.master_fd is None
    assert _fd_is_closed(fd)


def test_close_leaves_fd_when_the_group_is_already_gone():
    # The survivor probe raising ProcessLookupError means nothing is left to
    # reap, so no SIGKILL follows the probe.
    class _GoneKillpg:
        def __init__(self):
            self.calls = []

        def __call__(self, pg, sig):
            self.calls.append((pg, sig))
            if sig == 0:
                raise ProcessLookupError

    killpg = _GoneKillpg()
    proc = _Proc(pid=555, wait_behaviors=[0])
    fd = _pipe_fd()
    sess = PtySession(fd, process=proc, _killpg=killpg)

    sess.close()

    assert killpg.calls == [(555, signal.SIGTERM), (555, 0)]
    assert _fd_is_closed(fd)


def test_close_is_a_noop_without_a_process():
    killpg = _Recorder(None)
    fd = _pipe_fd()
    sess = PtySession(fd, process=None, _killpg=killpg)

    sess.close()

    # Nothing signalled, and the fd we do not own a process for is untouched.
    assert killpg.calls == []
    assert sess.master_fd == fd
    os.close(fd)


# --------------------------------------------------------------------------
# poll passthrough and the shared ANSI definition
# --------------------------------------------------------------------------

def test_poll_passes_through_and_is_none_without_a_process():
    class _P:
        def poll(self):
            return 0

    assert PtySession(MASTER_FD, process=_P()).poll() == 0
    assert PtySession(MASTER_FD, process=None).poll() is None


def test_strip_for_match_strips_ansi_without_touching_the_match_input_elsewhere():
    colored = "\x1b[32mroot@box:/#\x1b[0m"
    assert PtySession.strip_for_match(colored) == "root@box:/#"


def test_ansi_regex_matches_the_reverse_shell_definition():
    # _ANSI_RE is copied verbatim from reverse_shell_manager; assert the pattern
    # string is byte-identical rather than merely equivalent.
    assert _ANSI_RE.pattern == (
        r"\x1b\[[0-9;?]*[ -/]*[@-~]"
        r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
        r"|\x1b[@-Z\\-_]"
        r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"
    )


# --------------------------------------------------------------------------
# ssh_manager.stop() adopts PtySession.close(): the deliberate teardown upgrade
# --------------------------------------------------------------------------
# This is not part of the byte-identical extraction -- teardown produces no
# captured output, so the golden masters never reach it. ssh_manager.stop() used
# a bare self.process.terminate(), which signals only the setsid leader and can
# orphan an ssh control-master child or a forked proxy. It now delegates to
# PtySession.close(), the SIGTERM -> SIGKILL -> survivor-reap group ladder the
# other two managers already use. os.killpg is absent on this host, so the real
# close() is driven with an injected _killpg -- the same seam the close() unit
# tests above use -- proving stop() takes the group path, not terminate().


def _killpg_injecting_factory(killpg):
    """Wrap ssh_module.PtySession so _pty_io() builds a real session whose group
    signalling is observable on a host without os.killpg."""
    real_pty_session = ssh_module.PtySession

    def factory(master_fd, process=None, **kwargs):
        kwargs["_killpg"] = killpg
        return real_pty_session(master_fd, process, **kwargs)

    return factory


def test_ssh_stop_tears_down_through_the_pty_group_close(monkeypatch):
    killpg = _Recorder(None)
    monkeypatch.setattr(ssh_module, "PtySession", _killpg_injecting_factory(killpg))

    proc = _Proc(pid=909, wait_behaviors=[0])  # dies on the group SIGTERM
    fd = _pipe_fd()
    session = ssh_module.SSHSessionManager("10.0.0.1", "root", session_id="teardown")
    session.master_fd = fd
    session.process = proc
    session.is_connected = True

    session.stop()

    # The group was SIGTERMed (then the survivor probe + reap), never a bare
    # per-process terminate()/kill().
    assert killpg.calls == [(909, signal.SIGTERM), (909, 0), (909, SIGKILL)]
    assert proc.terminated is False
    assert proc.killed is False
    # Session state is cleared and the master fd is closed.
    assert session.process is None
    assert session.master_fd is None
    assert session.is_connected is False
    assert _fd_is_closed(fd)


def test_ssh_stop_closes_a_dangling_fd_with_no_process(monkeypatch):
    # PtySession.close() is a no-op without a process, so stop() must still
    # release a master fd left behind when there is nothing to signal.
    killpg = _Recorder(None)
    monkeypatch.setattr(ssh_module, "PtySession", _killpg_injecting_factory(killpg))

    fd = _pipe_fd()
    session = ssh_module.SSHSessionManager("10.0.0.1", "root", session_id="nofd")
    session.master_fd = fd
    session.process = None
    session.is_connected = True

    session.stop()

    assert killpg.calls == []  # nothing to signal
    assert session.master_fd is None
    assert session.is_connected is False
    assert _fd_is_closed(fd)
