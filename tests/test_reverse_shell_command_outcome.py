"""reverse_shell_command reported success against a shell that had died.

Measured: a session whose far end was gone answered two commands in a row with
`success: true`, `lines_captured: 0`, and `end_marker_found: true`. The files
those commands were supposed to delete were still on disk afterwards. An
operator reads that as "it ran and printed nothing".

Two things combined.

The PTY read loop has three exits -- the end marker arrives, `os.read` returns
b"" because the far end is gone, or the timeout expires -- and all three fell
through to a hardcoded `"success": True`.

And `end_marker_found` was not the safety net it looks like: a PTY echoes what
is written to it, so both markers can appear in the read data as the echo of
the command line with no shell behind it at all. The marker proves the bytes
were written, not that anything executed them.

So success now requires the end marker AND the session still being open, EOF
sets is_connected False so the next call's guard fires instead of trying again,
and a timeout is reported separately from a closed session -- the first may
still be running on the target, the second definitely did not.

These drive the real loop with a stubbed PTY rather than checking for
substrings in the source, the way tests/test_tool_timeouts.py does for the MSF
wait loop, because a flag like this reads the same whichever way it is wired.
"""

import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# reverse_shell_manager imports pty at module scope for its listener PTY, and
# pty pulls in termios. The loop these tests drive never opens one.
if os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

try:
    from core import reverse_shell_manager as rs_module
except ImportError:  # pragma: no cover - no pty and no stub
    rs_module = None

requires_module = pytest.mark.skipif(
    rs_module is None,
    reason="core.reverse_shell_manager imports pty, absent on Windows",
)

MASTER_FD = 99


class _Reads:
    """Serve queued byte chunks to os.read, then behave as told at the end."""

    def __init__(self, chunks, then="eof"):
        self._chunks = list(chunks)
        self._then = then

    def read(self, fd, size):
        if self._chunks:
            return self._chunks.pop(0)
        if self._then == "eof":
            return b""          # far end gone
        return b""              # pragma: no cover

    def select(self, rlist, wlist, xlist, timeout):
        if self._chunks or self._then == "eof":
            return ([MASTER_FD], [], [])
        return ([], [], [])     # nothing ever arrives -> the timeout path


def _session():
    session = object.__new__(rs_module.ReverseShellManager)
    session.session_id = "shell_test"
    session.is_connected = True
    session.master_fd = MASTER_FD
    session.listener_type = "netcat"
    session.process = None
    return session


def _drive(monkeypatch, chunks, then="eof", timeout=1):
    """Run the real send_command against a stubbed PTY."""
    reads = _Reads(chunks, then)
    monkeypatch.setattr(rs_module.os, "read", reads.read)
    monkeypatch.setattr(rs_module.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(rs_module.select, "select", reads.select)
    return _session(), reads


def _markers(result):
    return result["debug_info"]["start_marker"], result["debug_info"]["end_marker"]


@requires_module
class TestADeadSessionIsNotSuccess:
    def test_eof_before_the_end_marker_is_a_failure(self, monkeypatch):
        """os.read returning b"" means the shell is gone. Nothing ran."""
        session, _ = _drive(monkeypatch, chunks=[])

        result = session.send_command("rm -f /tmp/thing", timeout=1)

        assert result["success"] is False, (
            "a command sent to a closed shell must not report success"
        )
        assert result["session_closed"] is True
        assert "did not run" in result["error"]

    def test_eof_marks_the_session_disconnected(self, monkeypatch):
        """So the next call is refused by the guard rather than retried."""
        session, _ = _drive(monkeypatch, chunks=[])

        session.send_command("whoami", timeout=1)

        assert session.is_connected is False

    def test_the_next_command_is_then_refused_outright(self, monkeypatch):
        session, _ = _drive(monkeypatch, chunks=[])
        session.send_command("whoami", timeout=1)

        again = session.send_command("whoami", timeout=1)

        assert again["success"] is False
        assert "No active reverse shell connection" in again["error"]


@requires_module
class TestEchoedMarkersAreNotEvidence:
    def test_markers_alone_do_not_make_a_dead_session_succeed(self, monkeypatch):
        """A PTY echoes the command line back, so both markers can arrive with
        nothing having executed. This is the exact shape that was measured:
        end_marker_found true, zero lines, and the work not done."""
        session, _ = _drive(monkeypatch, chunks=[])
        # Learn this run's markers, then replay them as the terminal echo.
        probe = session.send_command("noop", timeout=1)
        start, end = _markers(probe)

        session2 = _session()
        echo = _Reads([f"{start}\n{end}\n".encode()], then="eof")
        monkeypatch.setattr(rs_module.os, "read", echo.read)
        monkeypatch.setattr(rs_module.select, "select", echo.select)
        # The markers differ per call, so this run sees only the echo of a
        # previous one -- never its own end marker, exactly as when the far end
        # is dead and only the local echo comes back.
        result = session2.send_command("rm -f /tmp/thing", timeout=1)

        assert result["success"] is False
        assert result["lines_captured"] == 0 or result["output"] == ""


@requires_module
class TestRealCompletionStillSucceeds:
    def test_output_between_the_markers_is_returned(self, monkeypatch):
        session, _ = _drive(monkeypatch, chunks=[])
        start, end = _markers(session.send_command("noop", timeout=1))

        session2 = _session()
        # send_command builds fresh markers each call, so drive it by feeding
        # whatever it writes straight back -- a shell that answers correctly.
        written = []

        def echo_write(fd, data):
            written.append(data)
            return len(data)

        replies = []

        def replay(fd, size):
            if replies:
                return replies.pop(0)
            blob = b"".join(written).decode(errors="ignore")
            marks = [w for w in blob.split("'") if w.startswith(("START_", "END_"))]
            if len(marks) >= 2:
                replies.append(f"{marks[0]}\nuid=0(root)\n{marks[1]}\n".encode())
                return replies.pop(0)
            return b""

        monkeypatch.setattr(rs_module.os, "write", echo_write)
        monkeypatch.setattr(rs_module.os, "read", replay)
        monkeypatch.setattr(rs_module.select, "select",
                            lambda r, w, x, t: ([MASTER_FD], [], []))

        result = session2.send_command("id", timeout=2)

        assert result["success"] is True, result
        assert "uid=0(root)" in result["output"]
        assert result["session_closed"] is False
        assert result["timed_out"] is False


@requires_module
def test_a_timeout_is_distinguished_from_a_closed_session(monkeypatch):
    """The command may still be running on the target; a closed session means
    it definitely did not. Reporting both as one number loses that."""
    quiet = _Reads([], then="quiet")
    monkeypatch.setattr(rs_module.os, "read", quiet.read)
    monkeypatch.setattr(rs_module.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(rs_module.select, "select", quiet.select)

    result = _session().send_command("sleep 600", timeout=1)

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["session_closed"] is False
    assert "still" in result["error"]
