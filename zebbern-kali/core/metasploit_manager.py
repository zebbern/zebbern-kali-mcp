#!/usr/bin/env python3
"""Metasploit Session Manager for persistent msfconsole sessions."""

import os
import pty
import re
import select
import subprocess
import threading
import time
import uuid
from typing import Dict, Any, Optional
from queue import Queue, Empty
from core.config import logger

# Escape sequences are stripped for the prompt *match* only. The buffer handed
# back to the operator is never rewritten -- msfconsole draws its prompt through
# readline, so the trailing line carries colour codes that would otherwise sit
# between the ">" and the end of the line and defeat the anchor.
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"      # CSI ... final byte
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL / ST
    r"|\x1b[@-Z\\-_]"                 # two-character escapes
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"  # readline's \x01/\x02 prompt markers
)

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
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

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
            # Create a pseudo-terminal
            self.master_fd, self.slave_fd = pty.openpty()
            
            # Start msfconsole with the slave end as stdin/stdout/stderr
            self.process = subprocess.Popen(
                ["msfconsole", "-q"],  # -q for quiet mode (no banner)
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                close_fds=True
            )
            
            # Close slave fd in parent process
            os.close(self.slave_fd)
            self.slave_fd = None
            
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
                ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                if ready:
                    data = os.read(self.master_fd, 4096)
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
            os.write(self.master_fd, (command + "\n").encode())
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
    
    def stop(self):
        """Stop the msfconsole session."""
        self._running = False
        
        if self.master_fd is not None:
            try:
                os.write(self.master_fd, b"exit\n")
                time.sleep(0.5)
            except:
                pass
            try:
                os.close(self.master_fd)
            except:
                pass
            self.master_fd = None
        
        if self.slave_fd is not None:
            try:
                os.close(self.slave_fd)
            except:
                pass
            self.slave_fd = None
        
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None
        
        logger.info(f"Metasploit session {self.session_id} stopped")
    
    def is_alive(self) -> bool:
        """Check if the session is still running."""
        return self.process is not None and self.process.poll() is None


class MetasploitManager:
    """Manages multiple persistent Metasploit sessions."""
    
    def __init__(self, max_sessions: int = 5):
        self.sessions: Dict[str, MetasploitSession] = {}
        self.max_sessions = max_sessions
        self._lock = threading.Lock()
    
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
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "Metasploit session created successfully"
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
                return {"success": True, "message": f"Session {session_id} destroyed"}
            return {"error": f"Session {session_id} not found", "success": False}
    
    def destroy_all_sessions(self) -> Dict[str, Any]:
        """Destroy all sessions."""
        with self._lock:
            count = len(self.sessions)
            for session in self.sessions.values():
                session.stop()
            self.sessions.clear()
            return {"success": True, "message": f"Destroyed {count} sessions"}
    
    def _cleanup_dead_sessions(self):
        """Remove dead sessions from the manager."""
        dead_sessions = [sid for sid, s in self.sessions.items() if not s.is_alive()]
        for sid in dead_sessions:
            self.sessions.pop(sid, None)


# Global manager instance
msf_manager = MetasploitManager()
