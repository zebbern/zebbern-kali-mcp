#!/usr/bin/env python3
"""Metasploit Session Manager for persistent msfconsole sessions."""

import os
import re
import select
import signal
import subprocess
import threading
import time
import uuid
from typing import Dict, Any, Optional
from queue import Queue, Empty
from core.config import logger, session_state_dir
from core.state_store import StateStore
from core.pty_session import PtySession, _ANSI_RE

# _ANSI_RE now lives in core.pty_session and is imported above. Escape sequences
# are stripped for the prompt *match* only; the buffer handed back to the
# operator is never rewritten -- msfconsole draws its prompt through readline, so
# the trailing line carries colour codes that would otherwise sit between the
# ">" and the end of the line and defeat the anchor. The copy that used to sit
# here was byte-identical to reverse_shell_manager's, so one shared definition
# replaces both.

# "msf" + ">" anywhere in the last 200 characters was the old test, and it
# misses every post-exploitation workflow: a meterpreter or shell prompt after a
# successful exploit contains neither. Anchor on the trailing line instead and
# accept msf/msf6, meterpreter, and generic > # $ prompts. The msf and
# meterpreter keywords sit in named groups so execute() can report which one
# ended the wait; the generic > # $ path -- a bare shell prompt like
# root@box:/# , or the case worth measuring, a line that merely ends in
# punctuation -- is reported as "generic_prompt". Dropping the old "shell"
# alternative changes no match: [^\n]* already absorbs the word, so the boolean
# _ends_on_prompt returns is unchanged (the existing prompt tests guard that).
_PROMPT_RE = re.compile(
    r"^\s*(?:(?P<msf>msf\d*)|(?P<meterpreter>meterpreter))?[^\n]*[>#$]\s*$"
)

# Only the tail is inspected. Once output goes stable this runs every 0.5s for
# the rest of the budget -- up to 4 hours -- so it has to cost the same whether
# the buffer holds 200 bytes or 200MB. buffer.splitlines() would allocate a list
# of every line on each poll, which is the same O(n)-per-poll trap the reader
# threads in command_executor.py just came out of. No prompt is near this long.
_PROMPT_TAIL_CHARS = 512


def _prompt_kind(buffer: str) -> Optional[str]:
    """Which interactive prompt, if any, the buffer's last line ends on.

    Returns the detector name -- "exact_msf", "meterpreter" or "generic_prompt"
    -- or None when the last line is not a prompt. The cost is the same bounded
    tail slice plus one regex match _ends_on_prompt always did; the group
    lookups are reached only on a match, i.e. once, at the exit.
    """
    tail = buffer[-_PROMPT_TAIL_CHARS:]
    last_line = tail[tail.rfind("\n") + 1:]
    match = _PROMPT_RE.match(_ANSI_RE.sub("", last_line))
    if match is None:
        return None
    if match.group("msf") is not None:
        return "exact_msf"
    if match.group("meterpreter") is not None:
        return "meterpreter"
    return "generic_prompt"


def _ends_on_prompt(buffer: str) -> bool:
    """Does the buffer's last line look like an interactive prompt?"""
    return _prompt_kind(buffer) is not None


class MetasploitSession:
    """Represents a single persistent msfconsole session."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        # Console output is accumulated as a list of chunks and joined once,
        # where the whole buffer is genuinely needed. ``self.output_buffer +=``
        # on every 4096-byte PTY read rebuilds the entire string each time --
        # the same O(n^2) accumulation removed from CommandExecutor, and left
        # here on the path whose budget just went from 300s to 14400s. 64MB of
        # 4096-byte reads measured at 131.3s by concatenation (8.0ms per read)
        # against 0.004s of appends plus one 0.016s join -- the reader capped at
        # roughly half a megabyte a second, so a verbose module, or `find / -ls`
        # in a shell session, outruns it and the session stalls. It gets worse
        # with the buffer, not better: the cost per read is O(buffer).
        # ``_output_len`` and ``_output_tail`` exist so the wait loop's
        # per-poll work (a length compare and a prompt match) stays constant
        # rather than joining the buffer four times a second for four hours.
        # Nothing is capped or discarded -- output_buffer still returns every
        # byte.
        self._output_chunks: list = []
        self._output_len: int = 0
        self._output_tail: str = ""
        self.output_lock = threading.Lock()
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_ready = False
        # A restored stand-in is a session a backend restart dropped: it
        # holds no process and no fd and is rebuilt from disk only so
        # list_sessions can show it was dropped rather than letting it
        # vanish. ``restored`` stays False for every real session -- that
        # is how _cleanup_dead_sessions tells a stand-in to leave alone
        # (its old pid may be a stranger's now, rule 3) from a crashed
        # session whose process group it must reap. ``last_known_ready``
        # keeps the is_ready the session last persisted with, so a
        # stand-in can report it had reached a prompt before the drop
        # without claiming it is ready now.
        self.restored = False
        self.last_known_ready = None
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

    def _pty_io(self) -> PtySession:
        """A PtySession over the current master_fd/process.

        pty.openpty + select.select + os.read + os.write on a master fd was
        implemented independently here, in reverse_shell_manager and in
        ssh_manager; that lifecycle now lives in core.pty_session. This wraps the
        fd the session already holds so start()'s spawn, the reader thread and
        execute()'s write all drive it through one owner. os.read / select.select
        / os.write are passed as THIS module's own names, resolved at call time,
        so the suite's existing seam -- which swaps metasploit_manager.os /
        .select for a scripted timeline -- still drives the loop after the
        extraction, exactly as it did when the primitives were inlined here.
        """
        return PtySession(
            self.master_fd,
            self.process,
            _select=select.select,
            _read=os.read,
            _write=os.write,
        )

    @property
    def output_buffer(self) -> str:
        """The whole console output, as a ``str``, exactly as before.

        Deliberately does NOT take ``output_lock``: every caller already holds
        it, and ``threading.Lock`` is not reentrant, so acquiring here would
        deadlock the wait loop against itself. ``str.join`` over a list of
        ``str`` runs no Python code and so never releases the GIL, which is the
        same guarantee ``CommandExecutor._finalize_output`` relies on.
        """
        return "".join(self._output_chunks)

    @output_buffer.setter
    def output_buffer(self, value: str) -> None:
        self._output_chunks = [value] if value else []
        self._output_len = len(value)
        self._output_tail = value[-_PROMPT_TAIL_CHARS:]

    def _append_output(self, text: str) -> None:
        """Record one chunk of console output. The caller holds output_lock.

        O(len(text)), not O(len(buffer)): the running length feeds the wait
        loop's stability compare and the bounded tail feeds the prompt match,
        so neither has to touch the accumulated chunks.
        """
        if not text:
            return
        self._output_chunks.append(text)
        self._output_len += len(text)
        self._output_tail = (self._output_tail + text)[-_PROMPT_TAIL_CHARS:]

    def start(self) -> bool:
        """Start the msfconsole process with a PTY."""
        try:
            # Create a pseudo-terminal and attach msfconsole to its slave end.
            # openpty + Popen(setsid) + close-slave is the shared spawn in
            # core.pty_session now; close_fds=True is preserved from the original.
            session = PtySession.spawn(
                ["msfconsole", "-q"],  # -q for quiet mode (no banner)
                close_fds=True,
            )
            self.master_fd = session.master_fd
            self.slave_fd = None
            self.process = session.process

            # Start reader thread
            self._running = True
            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()
            
            # Wait for prompt to appear. msfconsole cold-start on a loaded
            # container can outrun this; the session is still usable, but say so
            # rather than reporting a readiness we never observed.
            self.is_ready = self._wait_for_prompt(timeout=30)
            if not self.is_ready:
                logger.warning(
                    f"Metasploit session {self.session_id} started but no prompt "
                    "appeared within 30s; output may be desynchronised"
                )
            
            logger.info(f"Metasploit session {self.session_id} started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Metasploit session: {e}")
            self.stop()
            return False
    
    def _read_output(self):
        """Continuously read output from msfconsole."""
        while self._running and self.master_fd is not None:
            try:
                # Loop-control edit, not pure relocation: the old
                # ready = select.select(...); if ready: data = os.read(...)
                # becomes consuming session.read(0.1)'s three-way return. None
                # (nothing ready) and b"" (EOF) are both falsy and skipped, as
                # the old `if ready` then `if data` pair did; only real bytes
                # are appended.
                data = self._pty_io().read(0.1, 4096)
                if data:
                    # Decoded outside the lock: the critical section is now
                    # two appends and a clock read, shorter than it was.
                    text = data.decode("utf-8", errors="replace")
                    with self.output_lock:
                        self._append_output(text)
                        self.last_activity = time.time()
            except (OSError, IOError):
                break
            except Exception as e:
                logger.error(f"Error reading output: {e}")
                break
    
    def _wait_for_prompt(self, timeout: float = 30) -> bool:
        """Wait for the msf prompt to appear."""
        start = time.time()
        while time.time() - start < timeout:
            with self.output_lock:
                if "msf" in self.output_buffer and ">" in self.output_buffer:
                    return True
            time.sleep(0.5)
        return False
    
    def execute(
        self, command: str, timeout: float = 14400, read_delay: float = 2
    ) -> Dict[str, Any]:
        """Execute a command in the msfconsole session."""
        if not self.process or self.process.poll() is not None:
            return {
                "error": "Session is not running",
                "success": False,
                "timed_out": False,
                "console_exited": True,
                "detector": "not_running",
            }

        try:
            # Clear output buffer
            with self.output_lock:
                self.output_buffer = ""
            
            # Send command
            self._pty_io().write((command + "\n").encode())
            self.last_activity = time.time()
            
            # Wait for output and prompt
            time.sleep(max(0.0, read_delay))  # Pause for a slow command to start

            start_time = time.time()
            last_output_len = 0
            stable_count = 0
            # This loop has three exits -- prompt detected, msfconsole died, or
            # the budget expired -- and they all used to fall through to one
            # unconditional success. Assume the budget expired until one of the
            # two early exits below actually clears it.
            timed_out = True
            # ...and the death exit is reported separately, because it is a
            # different fact from either of the other two. Folding it into
            # timed_out=False alone made a console that was OOM-killed
            # mid-exploit field-for-field identical to one that reached a
            # prompt, so a caller obeying "check timed_out, never success"
            # reads a crash as a completed run.
            console_exited = False
            # Which condition ends the wait, as field telemetry: in particular
            # how often the generic > # $ path (generic_prompt) stands in for a
            # real msf/meterpreter prompt. Overwritten by whichever early exit
            # fires; stays "timeout" only when the budget is what ends the loop.
            detector = "timeout"

            while time.time() - start_time < timeout:
                time.sleep(0.5)

                # msfconsole is gone: no further output can arrive, so stop
                # waiting out the rest of the budget for it. Before this, a
                # crashed console blocked for the full timeout -- survivable at
                # the old 300s default, a 4-hour uncancellable block at 14400.
                if self.process is None or self.process.poll() is not None:
                    console_exited = True
                    timed_out = False
                    detector = "console_exited"
                    # The console cannot serve another command; say so rather
                    # than keep advertising a readiness that no longer holds.
                    self.is_ready = False
                    break

                with self.output_lock:
                    current_len = self._output_len

                    # Check if output has stabilized (no new output for 2 seconds)
                    if current_len == last_output_len:
                        stable_count += 1
                        if stable_count >= 4:  # 2 seconds of stability
                            # The bounded tail is exactly
                            # buffer[-_PROMPT_TAIL_CHARS:], all _prompt_kind
                            # ever looks at.
                            kind = _prompt_kind(self._output_tail)
                            if kind is not None:
                                timed_out = False
                                detector = kind
                                break
                    else:
                        stable_count = 0
                        last_output_len = current_len

            with self.output_lock:
                output = self.output_buffer

            if timed_out:
                logger.warning(
                    f"Metasploit command in session {self.session_id} hit its "
                    f"{timeout}s budget without reaching a prompt; output is partial"
                )
            elif console_exited:
                logger.warning(
                    f"msfconsole in session {self.session_id} exited before "
                    "reaching a prompt; output is whatever it printed first"
                )

            # success stays True on a timeout deliberately: a truncated module run
            # is still worth reading, and this is the contract CommandExecutor
            # already uses. Callers must read timed_out, not success, to know the
            # command actually finished.
            return {
                "success": True,
                "output": output,
                "session_id": self.session_id,
                "execution_time": time.time() - start_time,
                "timed_out": timed_out,
                "console_exited": console_exited,
                "detector": detector,
                "partial_results": bool((timed_out or console_exited) and output),
            }

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                "error": str(e),
                "success": False,
                "timed_out": False,
                "console_exited": False,
                "detector": "error",
            }
    
    def _terminate_process_group(self):
        """SIGTERM then SIGKILL the whole msfconsole process group.

        msfconsole is spawned under preexec_fn=os.setsid, so it and every child
        it spawns -- a `shell` channel, a locally staged payload or handler --
        share a process group whose id is the leader's pid. terminate() on the
        leader alone leaves those children orphaned; signalling the group reaches
        them. Mirrors the teardown NetworkPivotManager.stop_tunnel already uses.
        """
        process = self.process
        if process is None:
            return
        process_group = getattr(process, "pid", None)
        uses_process_group = bool(process_group and hasattr(os, "killpg"))
        group_escalated = False
        try:
            if uses_process_group:
                os.killpg(process_group, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.error(
                f"SIGTERM to msf session {self.session_id} group "
                f"{process_group} denied"
            )
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if uses_process_group:
                try:
                    os.killpg(process_group, getattr(signal, "SIGKILL", 9))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    logger.error(
                        f"SIGKILL to msf session {self.session_id} group "
                        f"{process_group} denied"
                    )
                group_escalated = True
            else:
                process.kill()
            process.wait(timeout=5)
        # Leader gone but a child may still hold the group open (a landed
        # meterpreter, a `shell` channel): probe and reap it.
        if uses_process_group and not group_escalated:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    os.killpg(process_group, getattr(signal, "SIGKILL", 9))
                except ProcessLookupError:
                    pass
                except PermissionError:
                    logger.error(
                        f"SIGKILL (survivor) to msf session {self.session_id} "
                        f"group {process_group} denied"
                    )

    def stop(self):
        """Stop the msfconsole session and its whole process group."""
        self._running = False

        # Ask msfconsole to exit through its own console first, but only while
        # it is still alive to read it -- on an already-dead leader this write
        # goes nowhere and the 0.5s wait is pure latency under the manager lock
        # in _cleanup_dead_sessions. The killpg below guarantees teardown either
        # way.
        if self.master_fd is not None:
            if self.process is not None and self.process.poll() is None:
                try:
                    os.write(self.master_fd, b"exit\n")
                    time.sleep(0.5)
                except OSError:
                    pass
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        if self.slave_fd is not None:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = None

        self._terminate_process_group()
        self.process = None

        logger.info(f"Metasploit session {self.session_id} stopped")

    def is_alive(self) -> bool:
        """Check if the session is still running."""
        return self.process is not None and self.process.poll() is None


class MetasploitManager:
    """Manages multiple persistent Metasploit sessions."""
    
    def __init__(self, max_sessions: int = 5, state_dir: Optional[str] = None):
        self.sessions: Dict[str, MetasploitSession] = {}
        self.max_sessions = max_sessions
        self._lock = threading.Lock()
        # Cross-restart persistence of session METADATA only -- never the
        # Popen handle, the master fd or the pid, none of which a new
        # process can re-adopt. A backend restart (a routine `docker
        # compose up -d --force-recreate` here) drops the in-memory
        # registry, after which msf_session_list answers empty --
        # indistinguishable from "nothing was ever started".
        # msf_sessions.json rehydrates each dropped session as a dead
        # stand-in instead, the same way JobManager and
        # NetworkPivotManager already persist their registries.
        self._persisted = False
        self._store = self._open_store(state_dir)
        self._load_sessions()

    def _open_store(self, state_dir: Optional[str]) -> Optional[StateStore]:
        """Wire up the on-disk session registry, or None if impossible.

        A session operation must NEVER fail because the state directory is
        missing or read-only -- the same honest degradation job_manager
        makes with ``output_logged=False`` -- so every error here is
        swallowed, the store is left unset and ``_persisted`` stays False.
        ``state_dir`` overrides for tests; otherwise the directory comes from
        ``config.session_state_dir()`` -- the SAME resolution the reverse-shell
        and SSH registries use, so all three land on the ``$ZKM_STATE_DIR`` /
        JOB_OUTPUT_DIR-sibling ``state`` dir on the durable kali-tmp volume
        (not a container-temp subdir a force-recreate would wipe), with the OS
        temp dir only as the from-source fallback.
        """
        try:
            directory = state_dir or session_state_dir()
            os.makedirs(directory, exist_ok=True)
            store = StateStore(os.path.join(directory, "msf_sessions.json"))
            self._persisted = True
            return store
        except Exception as exc:
            logger.warning(f"MSF session persistence disabled: {exc}")
            self._persisted = False
            return None

    def _session_record(self, session: "MetasploitSession") -> Dict[str, Any]:
        """The metadata persisted for one session: id, birth, last-known ready.

        A restored stand-in carries its last-known readiness in
        ``last_known_ready`` (its live ``is_ready`` is always False), so
        saving it back reads that field or the original is lost on the next
        restart. No pid, fd or process handle is ever serialised: a new
        process cannot re-adopt them and a stale pid now points at a
        stranger (rule 3).
        """
        if getattr(session, "restored", False):
            ready = session.last_known_ready
        else:
            ready = session.is_ready
        return {
            "session_id": session.session_id,
            "created_at": session.created_at,
            "is_ready": bool(ready),
        }

    def _save_sessions(self) -> None:
        """Persist the whole registry, degrading silently on an I/O fault.

        Called under ``self._lock`` from the create/destroy paths, which
        have already mutated ``self.sessions``. A write fault flips
        ``_persisted`` False and is logged, never raised: losing
        persistence must not fail the operation that triggered the save.
        list_sessions deliberately does NOT save -- a status read must not
        gain a disk-write side effect (rule 3) -- so a session reaped only
        by _cleanup_dead_sessions is re-persisted by the next
        create/destroy, not by the read that reaped it.
        """
        if self._store is None:
            return
        try:
            self._store.save(
                {"sessions": {sid: self._session_record(s)
                              for sid, s in self.sessions.items()}}
            )
            self._persisted = True
        except Exception as exc:
            logger.warning(f"Failed to persist MSF sessions: {exc}")
            self._persisted = False

    def _restored_session(
        self, session_id: str, record: Dict[str, Any]
    ) -> "MetasploitSession":
        """A dead stand-in for a session a restart dropped.

        Built through the real constructor, which opens no PTY, then marked
        ``restored`` with its process and fd left None, so ``is_alive()``
        is False with no probe and nothing here can signal a pid that may
        now belong to a stranger (rule 3). ``is_ready`` is False -- the
        console is gone -- while ``last_known_ready`` keeps what it
        persisted with.
        """
        session = MetasploitSession(session_id)
        session.restored = True
        session._running = False
        try:
            session.created_at = float(record.get("created_at"))
        except (TypeError, ValueError):
            pass  # keep the constructor's clock; a missing birth is not fatal
        session.last_activity = session.created_at
        session.last_known_ready = bool(record.get("is_ready"))
        session.is_ready = False
        return session

    def _load_sessions(self) -> None:
        """Rehydrate dropped sessions as dead stand-ins at construction.

        An absent or unreadable file is the normal "nothing persisted yet"
        case and leaves the registry empty. Each record becomes a stand-in
        keyed by its own id; one malformed record is skipped rather than
        aborting the whole load.
        """
        if self._store is None:
            return
        try:
            data = self._store.load()
        except Exception as exc:
            logger.warning(f"Failed to load MSF sessions: {exc}")
            return
        for sid, record in (data.get("sessions") or {}).items():
            try:
                self.sessions[sid] = self._restored_session(sid, record or {})
            except Exception as exc:
                logger.warning(f"Skipping unrestorable MSF session {sid!r}: {exc}")
    
    def create_session(self) -> Dict[str, Any]:
        """Create a new Metasploit session."""
        with self._lock:
            # Check session limit
            if len(self.sessions) >= self.max_sessions:
                # Try to clean up dead sessions
                self._cleanup_dead_sessions()
                if len(self.sessions) >= self.max_sessions:
                    return {"error": f"Maximum sessions ({self.max_sessions}) reached", "success": False}
            
            session_id = str(uuid.uuid4())[:8]
            session = MetasploitSession(session_id)
            
            if session.start():
                self.sessions[session_id] = session
                self._save_sessions()
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "Metasploit session created successfully",
                    "persisted": self._persisted,
                }
            else:
                return {"error": "Failed to start Metasploit session", "success": False}
    
    def execute_command(
        self,
        session_id: str,
        command: str,
        timeout: float = 14400,
        read_delay: float = 2,
    ) -> Dict[str, Any]:
        """Execute a command in an existing session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return {
                    "error": f"Session {session_id} not found",
                    "success": False,
                    "timed_out": False,
                    "console_exited": False,
                }
            if not session.is_alive():
                # A restored stand-in is kept so it stays visible in
                # list_sessions until the operator destroys it, and is
                # never probed -- it holds no process, and its old pid may
                # belong to a stranger now (rule 3). is_alive() already
                # returned False with no probe because process is None. A
                # real session that just died is dropped here as before.
                if not getattr(session, "restored", False):
                    del self.sessions[session_id]
                return {
                    "error": f"Session {session_id} is no longer running",
                    "success": False,
                    "timed_out": False,
                    "console_exited": True,
                }

        return session.execute(command, timeout, read_delay)
    
    def list_sessions(self) -> Dict[str, Any]:
        """List all active sessions."""
        with self._lock:
            self._cleanup_dead_sessions()
            sessions_info = []
            for sid, session in self.sessions.items():
                sessions_info.append({
                    "session_id": sid,
                    "is_alive": session.is_alive(),
                    "is_ready": session.is_ready,
                    # Advisory, like connected/timed_out elsewhere, and
                    # never flips success: a restored stand-in is a session
                    # a restart dropped, shown dead rather than vanished.
                    # last_known_ready is the readiness it had before the
                    # drop (None for a live session) so it is not confused
                    # with current readiness.
                    "restored": getattr(session, "restored", False),
                    "last_known_ready": getattr(session, "last_known_ready", None),
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "uptime": time.time() - session.created_at
                })
            return {
                "success": True,
                "sessions": sessions_info,
                "count": len(sessions_info)
            }
    
    def destroy_session(self, session_id: str) -> Dict[str, Any]:
        """Destroy a specific session."""
        with self._lock:
            session = self.sessions.pop(session_id, None)
            if session:
                session.stop()
                self._save_sessions()
                return {
                    "success": True,
                    "message": f"Session {session_id} destroyed",
                    "persisted": self._persisted,
                }
            return {"error": f"Session {session_id} not found", "success": False}
    
    def destroy_all_sessions(self) -> Dict[str, Any]:
        """Destroy all sessions."""
        with self._lock:
            count = len(self.sessions)
            for session in self.sessions.values():
                session.stop()
            self.sessions.clear()
            self._save_sessions()
            return {
                "success": True,
                "message": f"Destroyed {count} sessions",
                "persisted": self._persisted,
            }
    
    def shutdown(self) -> None:
        """Stop live sessions on process exit WITHOUT clearing the registry.

        The SIGTERM handler used to call ``destroy_all_sessions`` here, which
        clears ``self.sessions`` and re-persists an EMPTY file, so a routine
        ``docker restart`` / ``docker compose up -d --force-recreate`` (both
        SIGTERM) wiped the persisted records before the new process could
        reload them -- the cross-restart persistence did nothing on the one
        path that matters. This stops each live session's process the way the
        reverse-shell and SSH managers' ``stop()`` already does on shutdown,
        but leaves ``self.sessions`` and the on-disk file UNTOUCHED: the live
        sessions were persisted at create_session time, so ``_load_sessions``
        rehydrates them as dead stand-ins after the restart instead of
        finding an emptied registry. ``destroy_all_sessions`` is deliberately
        left alone -- it is the operator tool ``msf_session_destroy_all``,
        where clearing and persisting-empty is exactly what the operator
        asked for. A restored stand-in is skipped: it holds no process and
        no pid, and a reused pid could now belong to a stranger (rule 3),
        exactly as _cleanup_dead_sessions leaves one be.
        """
        with self._lock:
            for session in self.sessions.values():
                if getattr(session, "restored", False):
                    continue
                try:
                    session.stop()
                except Exception as exc:
                    logger.error(
                        f"Error stopping MSF session {session.session_id} on "
                        f"shutdown: {exc}"
                    )
    
    def _cleanup_dead_sessions(self):
        """Remove dead sessions, tearing down any process group they leave.

        A crashed msfconsole can leave a landed meterpreter or `shell` child
        alive in its process group; dropping the session from the dict without
        signalling that group orphans the child. Route removal through stop(),
        which reaps it. Guarded because this runs under the manager lock inside
        list_sessions / create_session, which have no outer try/except.
        """
        # A restored stand-in is already dead -- a restart dropped its
        # process -- but it holds no process group to reap and its pid was
        # never persisted, so stop() would have nothing to signal and must
        # not run (rule 3: the old pid may be a stranger's). It is also
        # deliberately NOT dropped here, so list_sessions keeps showing it
        # was dropped rather than letting it vanish; only destroy_session
        # removes it. Only a genuinely crashed real session is reaped and
        # removed, as before.
        dead_sessions = [
            sid for sid, s in self.sessions.items()
            if not s.is_alive() and not getattr(s, "restored", False)
        ]
        for sid in dead_sessions:
            session = self.sessions.pop(sid, None)
            if session is not None:
                try:
                    session.stop()
                except Exception as exc:
                    logger.error(f"Error tearing down dead msf session {sid}: {exc}")


# Global manager instance
msf_manager = MetasploitManager()
