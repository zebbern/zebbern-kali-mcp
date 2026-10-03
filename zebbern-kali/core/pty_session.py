#!/usr/bin/env python3
"""Shared PTY fd-lifecycle for the session managers.

``pty.openpty()`` + ``select.select`` + ``os.read`` on a master fd is
implemented independently in ``reverse_shell_manager``, ``metasploit_manager``
and ``ssh_manager``. The fd loop and the raw-bytes-versus-match-string
discipline are the same in all three; only the prompt/marker semantics differ.
``PtySession`` owns the loop once so each manager supplies only its own
semantics.

The read contract is three-way on purpose, because that is exactly the shape
the three inlined loops branch on:

* ``None``   -- the select window elapsed with nothing ready ("nothing yet").
* ``b''``    -- the fd is at EOF (reverse_shell turns this into
  ``session_closed``; ssh/msf break their loop on it).
* ``bytes``  -- data the caller decodes and appends; never capped or rewritten.

The io seam (``_select``/``_read``/``_write``/``_killpg``) is injectable so the
logic is exercisable with no real PTY -- ``pty.openpty`` does not exist on
Windows, and ``spawn()`` is the only PTY-dependent surface. ``spawn()`` is
straight-line with no branches, so it is left to the live two-container
backstop; everything a test needs to reach is driven through injected fakes.
"""

import os
import re
import select
import signal
import subprocess
from typing import Optional

import pty

# Escape sequences and readline's control bytes are stripped for the marker /
# prompt MATCH only. The bytes handed back to the operator are never rewritten.
# Copied verbatim from reverse_shell_manager (byte-identical to the
# metasploit_manager copy) so the three managers share one definition.
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"           # CSI ... final byte
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL / ST
    r"|\x1b[@-Z\\-_]"                      # two-character escapes
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"       # readline's \x01/\x02 prompt markers
)


class PtySession:
    """Owns one master fd and its process: the fd loop the managers share.

    ``process`` is ``None`` only for a session built directly in a test to
    drive ``read``/``write`` -- ``spawn()`` always supplies one. ``close()`` is
    then a no-op, so such a scaffold tears down without touching a fd it does
    not own.
    """

    def __init__(
        self,
        master_fd,
        process=None,
        *,
        _select=select.select,
        _read=os.read,
        _write=os.write,
        # os.killpg is POSIX-only and absent on Windows, where this module is
        # unit-tested with an injected fake; getattr keeps the Linux default
        # byte-identical to os.killpg while leaving import import-safe here.
        _killpg=getattr(os, "killpg", None),
    ):
        self.master_fd = master_fd
        self.process = process
        self._select = _select
        self._read = _read
        self._write = _write
        self._killpg = _killpg

    @classmethod
    def spawn(cls, command, *, shell=False, close_fds=False, env=None):
        """Open a PTY, attach ``command`` to its slave end, own the master end.

        The one shared copy of the spawn the three managers now duplicate: a
        new session group (``preexec_fn=os.setsid``) so the whole tree can be
        signalled as a group, slave wired to stdin/stdout/stderr and closed in
        the parent. Only ``command``/``shell``/``close_fds``/``env`` differ
        between callers. ``pty`` is referenced only here.
        """
        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
            shell=shell,
            close_fds=close_fds,
            env=env,
        )
        os.close(slave_fd)
        return cls(master_fd, process)

    def read(self, timeout, size=4096) -> Optional[bytes]:
        """One select window over the master fd.

        ``None`` when the window elapsed with nothing ready; otherwise the raw
        ``os.read`` result, where ``b''`` is EOF. Exactly one select per call,
        so the caller controls how long it blocks.
        """
        ready, _, _ = self._select([self.master_fd], [], [], timeout)
        if not ready:
            return None
        return self._read(self.master_fd, size)

    def write(self, data) -> int:
        """Write ``data`` to the master fd, returning the raw count unchanged.

        The count is not re-tried or rounded up: a short write is reported as
        the short count it was, which is what the raw send_raw channel relies
        on.
        """
        return self._write(self.master_fd, data)

    def poll(self):
        """``process.poll()``, or ``None`` when there is no process."""
        if self.process is None:
            return None
        return self.process.poll()

    def close(self):
        """SIGTERM the setsid group, escalate to SIGKILL, reap, close the fd.

        A no-op when there is no process. The process is spawned under
        ``os.setsid``, so it and every child it spawned share a group whose id
        is the leader's pid; signalling the leader alone would orphan the
        children. Mirrors the teardown MetasploitSession and NetworkPivotManager
        already use.
        """
        process = self.process
        if process is None:
            return
        process_group = getattr(process, "pid", None)
        uses_process_group = bool(process_group and self._killpg is not None)
        group_escalated = False
        try:
            if uses_process_group:
                self._killpg(process_group, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if uses_process_group:
                try:
                    self._killpg(process_group, getattr(signal, "SIGKILL", 9))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
                group_escalated = True
            else:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        # Leader gone but a child may still hold the group open: probe and reap.
        if uses_process_group and not group_escalated:
            try:
                self._killpg(process_group, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    self._killpg(process_group, getattr(signal, "SIGKILL", 9))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    @staticmethod
    def strip_for_match(text: str) -> str:
        """Strip ANSI/control bytes for the match only.

        The bytes handed back to the operator are never rewritten -- this is
        used to anchor a prompt/marker match against a line that readline drew
        with colour codes, nothing more.
        """
        return _ANSI_RE.sub("", text)
