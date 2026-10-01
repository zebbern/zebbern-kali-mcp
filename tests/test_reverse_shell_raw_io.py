"""A caught shell the marker scrape cannot read was a write-off.

``reverse_shell_command`` wraps every command in ``echo '<marker>'`` lines and
needs the far end to print the bare marker back. A target shell with no TTY, a
wedged prompt, a REPL, or ``su`` waiting on a password prints no such thing, and
there was nothing lower-level to fall back to: ``send_input``/``read_output``
resolve through ``job_manager``, which only tracks ``zebbern_exec`` jobs, never
``core.config.active_sessions``. The manager already had a ``read_output`` with
no route and no tool reaching it, and no raw write at all.

``send_raw`` is the write half and ``read_output`` the read half. Neither
pretends to more than it does: a successful write means the bytes left this
process, and an empty read window means the shell was quiet.

``read_output``'s shell-noise filter is off by default here. It drops any line
ending in ``$``, which on a raw channel is real output often enough that making
it the default would quietly withhold the operator's own bytes.

``read_output`` is a window over a stream, so it has to carry what it could not
hand back ON THE SESSION. It did not: ``buf`` and the complete-line surplus were
locals, so a newline-less prompt and every line past ``max_lines`` were read off
the PTY and then destroyed while the docstring promised the opposite. Both halves
of that are covered below, because a prompt with no newline is precisely what
this channel was added to drive.

``core.reverse_shell_manager`` imports ``pty``, so Windows needs the stub the
rest of the suite already uses.
"""

import os
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


def _session(connected=True, master_fd=MASTER_FD):
    """Built through the REAL constructor, not object.__new__.

    read_output's carry-over lives on the instance, so a session assembled
    attribute by attribute would hide an __init__ that never set it up -- the
    test helper would be supplying the fix. __init__ only assigns, it opens no
    PTY, so there is nothing to avoid.
    """
    session = rs_module.ReverseShellManager(4444, "shell_raw", "netcat")
    session.is_connected = connected
    session.master_fd = master_fd
    return session


def _explode(*_args, **_kwargs):  # pragma: no cover - asserted not to run
    raise AssertionError("the guard let a disconnected session touch the PTY")


@requires_module
class TestSendRawWritesExactlyWhatItIsGiven:
    def test_the_bytes_reach_the_pty_unchanged(self, monkeypatch):
        written = []
        monkeypatch.setattr(
            rs_module.os, "write",
            lambda fd, data: written.append((fd, data)) or len(data),
        )

        result = _session().send_raw("id\n")

        assert written == [(MASTER_FD, b"id\n")]
        assert result["success"] is True
        assert result["bytes_written"] == 3
        assert result["session_id"] == "shell_raw"

    def test_no_newline_is_appended_for_the_caller(self, monkeypatch):
        """Same contract as send_input for jobs: the caller submits the line.

        Appending one here would make it impossible to answer a password prompt
        or feed a REPL a partial line.
        """
        written = []
        monkeypatch.setattr(
            rs_module.os, "write",
            lambda fd, data: written.append(data) or len(data),
        )

        _session().send_raw("python3 -c 'import pty")

        assert written == [b"python3 -c 'import pty"]

    def test_a_short_write_is_reported_as_the_short_count(self, monkeypatch):
        """os.write may write fewer bytes than it was given. Reporting the
        length of the payload instead would claim a delivery that did not
        happen."""
        monkeypatch.setattr(rs_module.os, "write", lambda fd, data: 2)

        result = _session().send_raw("abcdef")

        assert result["bytes_written"] == 2


@requires_module
class TestSendRawRefusesADeadSession:
    def test_a_disconnected_session_is_refused_without_writing(self, monkeypatch):
        monkeypatch.setattr(rs_module.os, "write", _explode)

        result = _session(connected=False).send_raw("id\n")

        assert result["success"] is False
        assert result["bytes_written"] == 0
        assert "No active reverse shell connection" in result["error"]

    def test_a_missing_master_fd_is_refused_too(self, monkeypatch):
        monkeypatch.setattr(rs_module.os, "write", _explode)

        result = _session(master_fd=None).send_raw("id\n")

        assert result["success"] is False
        assert result["bytes_written"] == 0

    def test_a_failed_write_is_not_reported_as_delivered(self, monkeypatch):
        def refuse(fd, data):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(rs_module.os, "write", refuse)

        result = _session().send_raw("id\n")

        assert result["success"] is False
        assert result["bytes_written"] == 0
        assert "Input/output error" in result["error"]


class _Window:
    """Serve queued chunks to os.read, then report nothing ready."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, fd, size):
        return self._chunks.pop(0) if self._chunks else b""

    def select(self, rlist, wlist, xlist, timeout):
        return ([MASTER_FD], [], []) if self._chunks else ([], [], [])


@requires_module
class TestReadOutputIsAPollingWindowAndDropsNothing:
    def test_a_disconnected_session_reads_nothing_without_touching_the_pty(
        self, monkeypatch
    ):
        monkeypatch.setattr(rs_module.os, "read", _explode)
        monkeypatch.setattr(rs_module.select, "select", _explode)

        assert _session(connected=False).read_output(timeout=1) == ""

    def test_prompt_looking_lines_come_back_by_default(self, monkeypatch):
        """A line ending in '$' is output often enough that filtering it by
        default would withhold the operator's own bytes."""
        window = _Window([b"www-data@box:/$\r\nTOTAL 42$\r\nuid=33\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)

        output = _session().read_output(timeout=1)

        assert output.split("\n") == ["www-data@box:/$", "TOTAL 42$", "uid=33"]

    def test_the_noise_filter_is_opt_in(self, monkeypatch):
        window = _Window([b"www-data@box:/$\r\nuid=33\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)

        output = _session().read_output(timeout=1, drop_shell_noise=True)

        assert output == "uid=33"

    def test_max_lines_bounds_the_window_and_leaves_the_rest_behind(
        self, monkeypatch
    ):
        """The bound is how much one call returns, not a cap on the session --
        the next call picks the rest up, the way job_output's ring does."""
        window = _Window([b"one\r\n", b"two\r\n", b"three\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)
        session = _session()

        first = session.read_output(timeout=1, max_lines=2)
        second = session.read_output(timeout=1, max_lines=2)

        assert first.split("\n") == ["one", "two"]
        assert second == "three"


@requires_module
class TestANewlineLessRemainderIsNotReadOffThePtyAndThrownAway:
    """The bug the docstring denied, and the one that breaks the stated purpose.

    ``buf`` and the complete-line surplus were LOCALS. ``os.read`` had already
    taken those bytes off the PTY -- nobody else can ever see them again -- and
    the call returned only the complete lines that fitted, so the rest was
    destroyed. The docstring said "anything left is returned by the next call
    ... nothing is discarded to make room" and the MCP wrapper said "every line
    comes back as it arrived".

    What makes it worse than a dropped line: this channel exists to drive "a
    REPL or an interactive program holding stdin", and those stop on a prompt
    with NO trailing newline -- ``Password: ``, ``>>> ``, ``(gdb) ``. Those were
    exactly the bytes being destroyed, so an operator waiting on a password
    prompt saw an empty window, indistinguishable from a hung target.
    """

    def test_a_prompt_with_no_newline_comes_back_in_the_window_that_read_it(
        self, monkeypatch
    ):
        """Not merely "by the next call": a prompt one call late is useless to
        whoever is waiting on it, and it is what the operator is reading the
        window for."""
        window = _Window([b"uid=33\r\nPassword: "])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)

        output = _session().read_output(timeout=1)

        assert output.split("\n") == ["uid=33", "Password:"], output

    def test_a_remainder_a_full_window_could_not_return_survives_to_the_next(
        self, monkeypatch
    ):
        """With the ceiling already reached the remainder cannot be handed over
        now, which is the case that used to lose it outright."""
        window = _Window([b"one\r\ntwo\r\nPassword: "])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)
        session = _session()

        first = session.read_output(timeout=1, max_lines=2)
        second = session.read_output(timeout=1, max_lines=2)

        assert first.split("\n") == ["one", "two"]
        assert second == "Password:", second

    def test_the_carry_over_is_reported_so_a_full_window_is_not_the_end(
        self, monkeypatch
    ):
        """``max_lines`` lines returned no longer implies that was everything,
        and an operator who cannot tell stops polling with bytes still held."""
        window = _Window([b"one\r\ntwo\r\nthree\r\nPassword: "])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)
        session = _session()

        session.read_output(timeout=1, max_lines=2)

        assert session.raw_carry_over() == {"lines": 1, "bytes": len(b"Password: ")}

        session.read_output(timeout=1, max_lines=2)

        assert session.raw_carry_over() == {"lines": 0, "bytes": 0}


@requires_module
class TestMaxLinesIsAHardCeilingAndTheSurplusIsCarried:
    """The ceiling was tested only on the OUTER loop, so a burst of complete
    lines inside a single ``os.read`` returned all of them while the route
    reported ``window_limit: 100``.

    The fix is not to stop reading at the ceiling -- those lines are already off
    the PTY by then and breaking there would destroy them, which is the
    invariant, not a style preference. They are carried on the session instead,
    so the bound is honest AND every byte is still returned.
    """

    def test_a_burst_inside_one_read_does_not_overshoot_the_window(self, monkeypatch):
        window = _Window([b"one\r\ntwo\r\nthree\r\nfour\r\nfive\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)

        output = _session().read_output(timeout=1, max_lines=2)

        assert output.split("\n") == ["one", "two"], output

    def test_the_whole_burst_is_returned_across_windows_in_order(self, monkeypatch):
        window = _Window([b"one\r\ntwo\r\nthree\r\nfour\r\nfive\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)
        session = _session()

        collected = []
        for _ in range(3):
            collected.extend(
                line for line in session.read_output(timeout=1, max_lines=2).split("\n")
                if line
            )

        assert collected == ["one", "two", "three", "four", "five"], collected

    def test_the_noise_filter_applies_to_a_carried_line_when_it_is_returned(
        self, monkeypatch
    ):
        """The flag belongs to the call that hands a line back. Judging it when
        the line was READ would mean the filter a later caller asked for silently
        did not apply to the surplus."""
        window = _Window([b"one\r\ntwo\r\nwww-data@box:/$\r\nuid=33\r\n"])
        monkeypatch.setattr(rs_module.os, "read", window.read)
        monkeypatch.setattr(rs_module.select, "select", window.select)
        session = _session()

        session.read_output(timeout=1, max_lines=2)
        second = session.read_output(timeout=1, max_lines=2, drop_shell_noise=True)

        assert second == "uid=33", second
