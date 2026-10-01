"""The harness's own marker lines were landing in the target's shell history.

``send_command`` runs ``echo 'START_x'``, the command, and ``echo 'END_x'`` as
real lines on the target shell, so an operator read their own scaffolding back
out of ``/home/worker/.bash_history`` and spent time treating it as the
target's activity.

This is NOT the forbidden log redaction, and the distinction is the whole
design. Nothing is withheld from the OPERATOR: every byte the shell sends still
comes back through ``send_command``'s output and through ``read_output``, and
the prelude's own bytes are logged at debug level as they are drained. What is
kept out is the operator's own injected lines, out of the TARGET's history file.

Two things the correction demanded and these tests pin:

* ``set +o history`` does not exist on dash/ash/busybox or in a restricted
  shell. Unguarded it prints an error into the session -- into the very capture
  the executed-marker fix exists to keep clean -- so each prelude command
  carries its own ``2>/dev/null`` and they are separated by ``;``, never
  ``&&``, so one failure cannot abort the rest.
* The prelude is drained up to and including its own executed marker BEFORE any
  command marker is written, so neither the prelude nor its echo can enter a
  capture.

``history_suppressed`` reports that the prelude was sent. It never claims the
target honoured it -- no shell reports that, and inferring it from a successful
write would be the same mistake as reading success off a live socket.

``core.reverse_shell_manager`` imports ``pty``, so Windows needs the stub the
rest of the suite already uses.
"""

import os
import re
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

try:
    from core import reverse_shell_manager as rs_module
except ImportError:  # pragma: no cover - no pty and no stub
    rs_module = None

requires_module = pytest.mark.skipif(
    rs_module is None,
    reason="core.reverse_shell_manager imports pty, absent on Windows",
)

MASTER_FD = 99
MARKER = re.compile(r"(?:PRELUDE|START|END)_[0-9a-f]{8}")


class _Shell:
    """A PTY in front of a shell that echoes, then runs, every line typed.

    ``history_error`` is what a dash/ash/busybox target writes when it meets
    ``set -o history``. It is queued as part of the prelude's own reply, which
    is exactly where it would land in the field.
    """

    def __init__(self, body=b"uid=0(root)", history_error=None):
        self.written = []
        self.events = []
        self.prelude_marker = None
        self._queue = []
        self._body = body
        self._history_error = history_error

    def write(self, fd, data):
        self.written.append(data)
        self.events.append(("write", data))
        self._queue.append(data)  # the PTY echoes whatever is typed
        text = data.decode(errors="ignore")
        for marker in MARKER.findall(text):
            if marker.startswith("PRELUDE"):
                self.prelude_marker = marker
                if self._history_error:
                    self._queue.append(self._history_error)
            self._queue.append(marker.encode() + b"\r\n")
            if marker.startswith("START"):
                self._queue.append(self._body + b"\r\n")
        return len(data)

    def select(self, rlist, wlist, xlist, timeout):
        return ([MASTER_FD], [], []) if self._queue else ([], [], [])

    def read(self, fd, size):
        data = self._queue.pop(0) if self._queue else b""
        self.events.append(("read", data))
        return data

    def first(self, kind, predicate):
        for index, (event_kind, data) in enumerate(self.events):
            if event_kind == kind and predicate(data):
                return index
        return None


def _session():
    session = object.__new__(rs_module.ReverseShellManager)
    session.session_id = "shell_hist"
    session.is_connected = True
    session.master_fd = MASTER_FD
    session.listener_type = "netcat"
    session.process = None
    session._history_prelude_sent = False
    session._shell_responsive = None
    session._shell_last_command_at = None
    return session


def _run(monkeypatch, shell, command="id", **kwargs):
    monkeypatch.setattr(rs_module.os, "write", shell.write)
    monkeypatch.setattr(rs_module.os, "read", shell.read)
    monkeypatch.setattr(rs_module.select, "select", shell.select)
    session = _session()
    return session, session.send_command(command, timeout=2, **kwargs)


def _prelude(shell):
    for data in shell.written:
        if b"HISTFILE" in data:
            return data.decode()
    return ""


@requires_module
class TestThePreludeIsSentOnceAndReported:
    def test_the_first_command_sends_it_before_any_marker(self, monkeypatch):
        shell = _Shell()

        _session_, result = _run(monkeypatch, shell, suppress_history=True)

        prelude = _prelude(shell)
        assert prelude, "no prelude was written"
        assert b"HISTFILE" in shell.written[0], "the prelude must come first"
        assert "set +o history" in prelude
        assert result["history_suppressed"] is True

    def test_each_prelude_command_is_guarded_on_its_own(self, monkeypatch):
        """A dash/busybox target must not be able to error into the stream, and
        one command failing must not abort the ones after it."""
        shell = _Shell()

        _run(monkeypatch, shell, suppress_history=True)

        prelude = _prelude(shell).split("echo '")[0]
        commands = [part for part in prelude.split(";") if part.strip()]
        assert len(commands) >= 3
        for command in commands:
            assert "2>/dev/null" in command, f"unguarded prelude command: {command!r}"
        assert "&&" not in prelude, "&& lets one failure abort the rest"

    def test_the_prelude_is_drained_before_the_first_marker_is_written(
        self, monkeypatch
    ):
        """Up to and including its own executed marker. Otherwise the prelude's
        echo, and a dash target's error, sit in the stream when the capture
        starts."""
        shell = _Shell()

        _run(monkeypatch, shell, suppress_history=True)

        marker = shell.prelude_marker
        assert marker, "the prelude carried no marker to drain to"
        drained = shell.first(
            "read", lambda data: data.strip() == marker.encode()
        )
        first_marker_write = shell.first(
            "write", lambda data: b"echo 'START_" in data
        )
        assert drained is not None, "the prelude marker was never read"
        assert first_marker_write is not None
        assert drained < first_marker_write, (
            "the prelude was still in the stream when the capture started"
        )

    def test_a_second_command_does_not_re_send_it(self, monkeypatch):
        shell = _Shell()
        session, _first = _run(monkeypatch, shell, suppress_history=True)

        second = session.send_command("whoami", timeout=2, suppress_history=True)

        preludes = [data for data in shell.written if b"HISTFILE" in data]
        assert len(preludes) == 1, "the prelude was re-sent"
        assert second["history_suppressed"] is True


@requires_module
class TestTheOperatorCanTurnItOff:
    def test_suppress_history_false_writes_no_prelude(self, monkeypatch):
        shell = _Shell()

        _session_, result = _run(monkeypatch, shell, suppress_history=False)

        assert not any(b"HISTFILE" in data for data in shell.written)
        assert result["history_suppressed"] is False
        assert result["success"] is True
        assert result["output"] == "uid=0(root)"


@requires_module
class TestANonBashTargetIsNotBroken:
    HISTORY_ERROR = b"sh: 1: set: Illegal option +o history\r\n"

    def test_a_dash_like_shell_still_returns_the_right_output(self, monkeypatch):
        """``set -o history`` does not exist there. The guard keeps the error
        out of the stream's meaning, and the drain keeps it out of the capture
        entirely."""
        shell = _Shell(history_error=self.HISTORY_ERROR)

        _session_, result = _run(monkeypatch, shell, suppress_history=True)

        assert result["success"] is True
        assert result["timed_out"] is False
        assert result["output"] == "uid=0(root)"
        assert "Illegal option" not in result["output"]

    def test_it_still_reports_only_that_the_prelude_was_sent(self, monkeypatch):
        """The target rejected it. history_suppressed says the prelude went
        out, not that the target honoured it -- nothing on the wire can say
        that, and claiming it would be the live-socket mistake again."""
        shell = _Shell(history_error=self.HISTORY_ERROR)

        _session_, result = _run(monkeypatch, shell, suppress_history=True)

        assert result["history_suppressed"] is True


@requires_module
def test_the_prelude_changes_no_captured_byte(monkeypatch):
    """It withholds nothing from the operator: the same shell answers the same
    command with byte-identical output whether or not the prelude ran."""
    with_prelude = _Shell()
    _s1, suppressed = _run(monkeypatch, with_prelude, suppress_history=True)

    without_prelude = _Shell()
    _s2, plain = _run(monkeypatch, without_prelude, suppress_history=False)

    assert suppressed["output"] == plain["output"]
    assert suppressed["lines_captured"] == plain["lines_captured"]
