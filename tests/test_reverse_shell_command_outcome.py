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

import base64
import os
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

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
    # The OPSEC prelude has its own file (test_reverse_shell_history_suppression)
    # and its own drain; latch it sent here so these cases drive only the marker
    # loop. Every send_command below also passes suppress_history=False.
    session._history_prelude_sent = False
    session._shell_responsive = None
    session._shell_last_command_at = None
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

        result = session.send_command("rm -f /tmp/thing", timeout=1, suppress_history=False)

        assert result["success"] is False, (
            "a command sent to a closed shell must not report success"
        )
        assert result["session_closed"] is True
        assert "did not run" in result["error"]

    def test_eof_marks_the_session_disconnected(self, monkeypatch):
        """So the next call is refused by the guard rather than retried."""
        session, _ = _drive(monkeypatch, chunks=[])

        session.send_command("whoami", timeout=1, suppress_history=False)

        assert session.is_connected is False

    def test_the_next_command_is_then_refused_outright(self, monkeypatch):
        session, _ = _drive(monkeypatch, chunks=[])
        session.send_command("whoami", timeout=1, suppress_history=False)

        again = session.send_command("whoami", timeout=1, suppress_history=False)

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
        probe = session.send_command("noop", timeout=1, suppress_history=False)
        start, end = _markers(probe)

        session2 = _session()
        echo = _Reads([f"{start}\n{end}\n".encode()], then="eof")
        monkeypatch.setattr(rs_module.os, "read", echo.read)
        monkeypatch.setattr(rs_module.select, "select", echo.select)
        # The markers differ per call, so this run sees only the echo of a
        # previous one -- never its own end marker, exactly as when the far end
        # is dead and only the local echo comes back.
        result = session2.send_command("rm -f /tmp/thing", timeout=1, suppress_history=False)

        assert result["success"] is False
        assert result["lines_captured"] == 0 or result["output"] == ""


@requires_module
class TestRealCompletionStillSucceeds:
    def test_output_between_the_markers_is_returned(self, monkeypatch):
        session, _ = _drive(monkeypatch, chunks=[])
        start, end = _markers(session.send_command("noop", timeout=1, suppress_history=False))

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

        result = session2.send_command("id", timeout=2, suppress_history=False)

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

    result = _session().send_command("sleep 600", timeout=1, suppress_history=False)

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["session_closed"] is False
    assert "still" in result["error"]


class _ReplayPty:
    """Echo the typed lines back, then optionally answer as a shell that ran them.

    The echo half is the P0: a PTY echoes whatever is written to it, so
    ``echo 'START_x'`` and ``echo 'END_x'`` come back with nothing on the far
    end having executed anything, and the TCP session stays ESTABLISHED so there
    is no EOF to notice. ``execute=False`` is exactly that shell.

    ``split`` delivers the executed answer in two reads, because the base64
    branch only re-checks for the end marker when new data lands.
    """

    CRLF = b"\r\n"

    def __init__(self, body=b"uid=0(root)", execute=True, split=False):
        self.written = []
        self.delivered = []
        self._pending = []
        self._body = body
        self._execute = execute
        self._split = split
        self._phase = 0

    def write(self, fd, data):
        self.written.append(data)
        self._pending.append(data)      # the terminal echo
        return len(data)

    def _marks(self):
        blob = b"".join(self.written).decode(errors="ignore")
        return [w for w in blob.split("'") if w.startswith(("START_", "END_"))]

    def _more(self):
        return (
            self._execute
            and self._phase < (2 if self._split else 1)
            and len(self._marks()) >= 2
        )

    def select(self, rlist, wlist, xlist, timeout):
        if self._pending or self._more():
            return ([MASTER_FD], [], [])
        return ([], [], [])             # quiet, but still open -- no EOF

    def read(self, fd, size):
        if self._pending:
            data = self._pending.pop(0)
        elif not self._more():
            data = b""
        else:
            start, end = (m.encode() for m in self._marks()[:2])
            if not self._split:
                self._phase = 1
                data = start + self.CRLF + self._body + self.CRLF + end + self.CRLF
            elif self._phase == 0:
                self._phase = 1
                data = start + self.CRLF + self._body + self.CRLF
            else:
                self._phase = 2
                data = end + self.CRLF
        self.delivered.append(data)
        return data


def _attach(monkeypatch, pty):
    monkeypatch.setattr(rs_module.os, "write", pty.write)
    monkeypatch.setattr(rs_module.os, "read", pty.read)
    monkeypatch.setattr(rs_module.select, "select", pty.select)
    return pty


@requires_module
class TestEchoedTypedLinesOnALiveSession:
    """The measured P0: a LIVE session that executed nothing reported success.

    TestEchoedMarkersAreNotEvidence above only covers the dead-session variant
    (``then="eof"``), which ``session_closed`` already caught. With the far end
    merely silent there is no EOF, so ``session_closed`` stays False and the
    echoed ``echo 'END_x'`` was the only thing deciding the outcome: substring
    containment said the end marker had arrived, and the call came back
    ``success: true, lines_captured: 0`` with the file still on disk.
    """

    def test_an_echo_only_live_session_is_a_timeout_not_a_success(self, monkeypatch):
        pty = _attach(monkeypatch, _ReplayPty(execute=False))

        result = _session().send_command(
            "rm -f /tmp/thing", timeout=1, suppress_history=False
        )

        assert any(b"echo 'END_" in chunk for chunk in pty.delivered), (
            "the echo never reached the read loop, so this proves nothing"
        )
        assert result["success"] is False
        assert result["timed_out"] is True
        assert result["session_closed"] is False
        assert result["lines_captured"] == 0
        assert result["output"] == ""
        assert result["debug_info"]["end_marker_found"] is False

    def test_the_base64_path_is_not_fooled_either(self, monkeypatch):
        """Its markers are matched against the whole buffer rather than a line,
        so it needed the same standalone-line anchor."""
        pty = _attach(monkeypatch, _ReplayPty(execute=False))

        result = _session().send_command(
            "base64 /tmp/secret", timeout=1, suppress_history=False
        )

        assert any(b"echo 'END_" in chunk for chunk in pty.delivered)
        assert result["success"] is False
        assert result["timed_out"] is True
        assert result["session_closed"] is False
        assert result["lines_captured"] == 0


@requires_module
class TestAnEchoingShellThatActuallyRunsStillSucceeds:
    """Guards against over-tightening: the real stream carries BOTH the echo of
    the typed line and the bare marker the shell printed when it ran it."""

    def test_the_echo_is_ignored_and_the_output_is_returned(self, monkeypatch):
        pty = _attach(monkeypatch, _ReplayPty(body=b"uid=0(root)"))

        result = _session().send_command("id", timeout=2, suppress_history=False)

        assert result["success"] is True, result
        assert result["output"] == "uid=0(root)"
        assert "echo '" not in result["output"]
        assert result["timed_out"] is False
        assert result["session_closed"] is False

    def test_the_base64_slice_is_anchored_on_the_executed_marker(self, monkeypatch):
        """``text_buffer.find(marker)`` returns the FIRST occurrence, which is
        the echoed ``echo 'START_x'``. Slicing clean_content from there starts
        the capture inside the echo and ends it at the echoed end marker, which
        lands before the real output ever arrives -- success, and nothing in it.
        """
        payload = base64.b64encode(b"Real download test").decode()
        pty = _attach(monkeypatch, _ReplayPty(body=payload.encode(), split=True))

        result = _session().send_command(
            "base64 /tmp/secret", timeout=3, suppress_history=False
        )

        assert result["success"] is True, result
        assert payload in result["output"], result

class _AliveProcess:
    """A listener process that has not exited."""

    def poll(self):
        return None


@requires_module
class TestStatusSeparatesALiveSocketFromAUsableChannel:
    """is_connected, actual_network_connection and process_alive all read true
    on a channel that had stopped executing anything. They are honest about the
    socket and the process, and that is the whole problem: an operator reading
    them concluded the shell was fine. A live process is not a working one, so
    responsiveness is reported from evidence -- an executed end marker -- and is
    never inferred from the socket.
    """

    def _netstat(self, monkeypatch, established=True):
        monkeypatch.setattr(
            rs_module.subprocess, "run",
            lambda *args, **kwargs: SimpleNamespace(
                stdout="tcp 0 0 10.0.0.1:4444 ESTABLISHED" if established else "",
                stderr="",
                returncode=0,
            ),
        )

    def _live(self):
        session = _session()
        session.port = 4444
        session.process = _AliveProcess()
        session.listener_thread = None
        return session

    def test_it_is_unknown_until_a_command_has_been_tried(self, monkeypatch):
        self._netstat(monkeypatch)
        session = self._live()

        status = session.get_status()

        assert status["is_connected"] is True
        assert status["shell_responsive"] is None, (
            "nothing has been run, so nothing is known about the channel"
        )

    def test_an_established_socket_does_not_make_the_channel_usable(self, monkeypatch):
        session = self._live()
        _attach(monkeypatch, _ReplayPty(execute=False))
        session.send_command("rm -f /tmp/thing", timeout=1, suppress_history=False)
        self._netstat(monkeypatch)

        status = session.get_status()

        assert status["is_connected"] is True
        assert status["actual_network_connection"] is True
        assert status["process_alive"] is True
        assert status["shell_responsive"] is False, (
            "the far end executed nothing; only the socket was healthy"
        )

    def test_a_command_that_really_ran_marks_the_channel_usable(self, monkeypatch):
        session = self._live()
        _attach(monkeypatch, _ReplayPty(body=b"uid=0(root)"))
        session.send_command("id", timeout=2, suppress_history=False)
        self._netstat(monkeypatch)

        status = session.get_status()

        assert status["shell_responsive"] is True
        assert status["shell_last_command_at"] is not None


class _PromptEchoPty:
    """A realistic interactive bash over a PTY.

    ``_ReplayPty`` above echoes the typed line back bare, the way a raw pipe
    would. A real caught ``bash -i`` prefixes every echo with its prompt, so
    the end-marker command comes back as ``root@h:~# echo 'END_x'`` -- which
    is the shape the old ``text.startswith("echo '")`` filter cannot see.

    Measured live against a real caught shell: the capture carried that line
    and the control (shipped) backend's did not.
    """

    PROMPT = b"root@h:~# "

    def __init__(self, body=(b"root",), bare_prompts=False, command=b"whoami"):
        self.written = []
        self.delivered = []
        self._body = list(body)
        self._bare = bare_prompts
        self._command = command
        self._done = False

    def write(self, fd, data):
        self.written.append(data)
        return len(data)

    def _marks(self):
        blob = b"".join(self.written).decode(errors="ignore")
        return [w for w in blob.split("'") if w.startswith(("START_", "END_"))]

    def _ready(self):
        return not self._done and len(self._marks()) >= 2

    def select(self, rlist, wlist, xlist, timeout):
        if self._ready():
            return ([MASTER_FD], [], [])
        return ([], [], [])         # quiet, but still open -- no EOF

    def read(self, fd, size):
        if not self._ready():
            return b""
        start, end = (m.encode() for m in self._marks()[:2])
        self._done = True
        lines = [self.PROMPT + b"echo '" + start + b"'", start]
        if self._bare:
            lines.append(self.PROMPT.strip())
        lines.append(self.PROMPT + self._command)
        lines.extend(self._body)
        if self._bare:
            lines.append(self.PROMPT.strip())
        lines.append(self.PROMPT + b"echo '" + end + b"'")
        lines.append(end)
        data = b"\r\n".join(lines) + b"\r\n"
        self.delivered.append(data)
        return data


@requires_module
class TestTheMarkerEchoDoesNotReachTheOperator:
    """The regression the executed-marker fix introduced, and its fix.

    Replacing ``if end_marker in text:`` with an executed-marker equality test
    was right -- the echo is not evidence that anything ran -- but it moved the
    loop's stopping point PAST the echo of ``echo 'END_x'``. The surviving
    append filter only skipped lines starting with ``echo '``, which a
    prompt-prefixed echo never does, so that line fell through into the
    capture. Measured live: the patched backend returned five lines where the
    shipped one returned four, the extra one being exactly that echo.

    Markers are scaffolding. Neither form of them belongs in operator output.
    """

    def test_the_end_marker_echo_is_not_captured(self, monkeypatch):
        pty = _attach(monkeypatch, _PromptEchoPty())

        result = _session().send_command("whoami", timeout=2, suppress_history=False)

        start, end = _markers(result)
        assert any(f"echo '{end}'".encode() in chunk for chunk in pty.delivered), (
            "the prompt-prefixed marker echo never reached the read loop, so "
            "this proves nothing"
        )
        assert f"echo '{end}'" not in result["output"], result["output"]
        assert f"echo '{start}'" not in result["output"], result["output"]
        assert not any(
            line.strip() == f"root@h:~# echo '{end}'"
            for line in result["output"].splitlines()
        ), result["output"]

    def test_only_that_line_is_dropped_and_real_output_survives(self, monkeypatch):
        _attach(monkeypatch, _PromptEchoPty())

        result = _session().send_command("whoami", timeout=2, suppress_history=False)

        # The prompt-prefixed command echo and the genuine output, and nothing
        # else. Before the fix this was 3: the end-marker echo as well.
        assert result["lines_captured"] == 2, result["output"]
        assert "root" in result["output"]
        assert "root@h:~# whoami" in result["output"]

    def test_the_outcome_fields_are_unchanged(self, monkeypatch):
        _attach(monkeypatch, _PromptEchoPty())

        result = _session().send_command("whoami", timeout=2, suppress_history=False)

        assert result["success"] is True, result
        assert result["timed_out"] is False
        assert result["session_closed"] is False
        assert result["debug_info"]["end_marker_found"] is True

    def test_the_live_whoami_shape_returns_the_control_count(self, monkeypatch):
        """The measured stream, bare prompt lines and all: four lines, the same
        count the shipped backend returned, with the marker echo gone."""
        _attach(monkeypatch, _PromptEchoPty(bare_prompts=True))

        result = _session().send_command("whoami", timeout=2, suppress_history=False)

        assert result["lines_captured"] == 4, result["output"]
        assert result["output"].splitlines() == [
            "root@h:~#",
            "root@h:~# whoami",
            "root",
            "root@h:~#",
        ], result["output"]

    def test_output_that_merely_mentions_echo_is_kept(self, monkeypatch):
        """The filter matches this call's random marker, not the word echo, so
        a genuine line about echo commands is still operator output."""
        _attach(monkeypatch, _PromptEchoPty(
            body=(b"echo 'START_of_file' >> notes.txt", b"root"),
        ))

        result = _session().send_command("whoami", timeout=2, suppress_history=False)

        assert "echo 'START_of_file' >> notes.txt" in result["output"], result
        assert result["lines_captured"] == 3, result["output"]


# ---------------------------------------------------------------------------
# The 45s default is load-bearing, and nothing was holding it.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ROUTE_SRC = (
    BACKEND_ROOT / "api" / "blueprints" / "reverse_shell.py"
).read_text(encoding="utf-8")

# The MCP harness abandons a tool call at roughly this point, above every
# deadline in this repo and outside it, so nothing here can raise it.
HARNESS_ABORT_SECONDS = 60

# A default at or near the abort races it: the backend needs room to notice its
# own budget expired and serialize the timed_out reply (with whatever partial
# output arrived) before the harness stops listening. 60 was the original value
# and lost that race; the margin is what makes the honest answer reachable.
SAFE_DEFAULT_CEILING = 55


def _registered_command_tool():
    """The MCP wrapper as registered, so this reads the real default."""
    import inspect
    from unittest.mock import MagicMock
    import mcp_tools.reverse_shell as rs

    posted = {}
    client = MagicMock()
    client.safe_post = lambda endpoint, data: posted.update(
        endpoint=endpoint, data=data
    ) or {"success": True}

    registered = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda f: registered.setdefault(f.__name__, f) or f)
    rs.register(mcp, client)

    tool = registered["reverse_shell_command"]
    return tool, inspect.signature(tool), posted


def _route_command_default():
    body = ROUTE_SRC.split("def execute_shell_command(")[1].split("\n@bp.route")[0]
    match = re.search(r'params\.get\("timeout",\s*(\d+)\)', body)
    assert match, "the /command route no longer defaults the timeout at all"
    return int(match.group(1))


class TestTheCommandTimeoutDefaultStaysUnderTheHarnessAbort:
    """45 is a measured value, not a round number, and it was unguarded.

    `reverse_shell_command`'s default moved 60 -> 45 on both tracks because 60
    was exactly the harness abort: a command that used its whole budget raced
    the harness, and the harness won, so the tool's own `timed_out` result and
    every byte of partial output it had collected never came back -- the caller
    saw `Error: Request timed out` instead, which says nothing about the target.

    Nothing asserted it. An engineer rounding it back to 60, or raising it to
    "give long commands more room", reintroduces that race with a fully green
    suite -- and the failure is invisible, because a timed-out harness call
    looks like an unreachable backend rather than a budget set too high.

    The route is read as SOURCE TEXT: `api.blueprints.reverse_shell` imports
    `core.reverse_shell_manager` and so pulls in pty/termios, which Windows does
    not have. The wrapper and the manager are introspected.
    """

    def test_the_mcp_wrapper_default_is_under_the_ceiling(self):
        _, signature, _ = _registered_command_tool()

        declared = signature.parameters["timeout"].default

        assert declared < SAFE_DEFAULT_CEILING, (
            f"reverse_shell_command defaults to {declared}s, at or past the "
            f"~{HARNESS_ABORT_SECONDS}s harness abort: its own timed_out reply "
            "and any partial output lose the race and never reach the caller"
        )

    def test_the_wrapper_actually_sends_that_default(self):
        """An unsent default is the route's default in disguise, which is how
        the two tracks drift apart."""
        tool, signature, posted = _registered_command_tool()

        tool(session_id="shell_4444", command="id")

        assert posted["data"]["timeout"] == signature.parameters["timeout"].default

    def test_the_route_default_is_under_the_ceiling_too(self):
        """It governs every direct HTTP caller, and it is on the image track --
        so it can regress in a change that never touches the wheel."""
        declared = _route_command_default()

        assert declared < SAFE_DEFAULT_CEILING, (
            f"the /command route defaults to {declared}s, which races the "
            f"~{HARNESS_ABORT_SECONDS}s harness abort"
        )

    @requires_module
    def test_the_manager_default_is_under_the_ceiling_as_well(self):
        """The innermost of the three. The route passes its own value today, so
        this one only shows up when a caller omits it -- which is exactly when
        nobody is watching."""
        import inspect

        declared = inspect.signature(
            rs_module.ReverseShellManager.send_command
        ).parameters["timeout"].default

        assert declared < SAFE_DEFAULT_CEILING, (
            f"ReverseShellManager.send_command defaults to {declared}s"
        )

    def test_all_three_agree(self):
        """Three defaults for one knob, on two release tracks. They drifted
        apart once already in this repo (the MSF chain), and a wrapper under the
        ceiling in front of a route above it still loses the race for a direct
        caller."""
        _, signature, _ = _registered_command_tool()
        wrapper = signature.parameters["timeout"].default

        assert wrapper == _route_command_default(), (
            "the wrapper and the route disagree about the command timeout"
        )
