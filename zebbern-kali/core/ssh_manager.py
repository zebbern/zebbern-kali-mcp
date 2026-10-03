#!/usr/bin/env python3
"""SSH Session Manager for Kali Server."""

import os
import time
import select
import uuid
from datetime import datetime
from typing import Dict, Any
from .config import logger, session_state_dir
from .logging_utils import render_command
from .pty_session import PtySession
from .state_store import StateStore


class SSHSessionManager:
    """Class to manage SSH sessions with interactive capabilities"""

    def __init__(self, target: str, username: str, password: str = "", key_file: str = "", port: int = 22, session_id: str = ""):
        self.target = target
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.session_id = session_id
        self.process = None
        self.master_fd = None
        self.slave_fd = None
        self.is_connected = False
        self.last_output = ""
        self.start_time = time.time()
        self.command_count = 0
        # Backend-restart persistence. A live session is created here; a
        # restored stand-in is rebuilt from ssh_sessions.json by
        # restore_sessions, which sets restored=True. created_at is
        # persisted; the password and key contents never are.
        self.created_at = datetime.now().isoformat()
        self.restored = False

    def _pty_io(self) -> PtySession:
        """A PtySession over the current master_fd/process.

        pty.openpty + select.select + os.read + os.write on a master fd was
        implemented independently here, in reverse_shell_manager and in
        metasploit_manager; that lifecycle now lives in core.pty_session. This
        wraps the fd the session already holds so start_session's spawn and
        validation, send_command and stop() all drive it through one owner.
        os.read / select.select / os.write are passed as THIS module's own
        names, resolved at call time, so the suite's existing seam -- which
        swaps ssh_manager.os / .select for a scripted timeline -- still drives
        the loop after the extraction. read_output keeps its own inlined loop on
        purpose: no route reaches it, and its carry-over-in-locals bug is left
        for a change of its own with its own golden master.
        """
        return PtySession(
            self.master_fd,
            self.process,
            _select=select.select,
            _read=os.read,
            _write=os.write,
        )

    def start_session(self) -> Dict[str, Any]:
        """Start an interactive SSH session using sshpass or key authentication"""
        try:
            import shutil
            logger.info(f"Starting SSH session to {self.username}@{self.target}:{self.port}")

            # Verify ssh binary exists
            if not shutil.which("ssh"):
                return {"success": False, "error": "ssh binary not found — install openssh-client"}
            if self.password and not self.key_file and not shutil.which("sshpass"):
                return {"success": False, "error": "sshpass binary not found — install sshpass (or use key auth)"}

            logger.info(f"Attempting SSH connection (server-side connectivity)")

            # Build SSH command
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

            if self.key_file:
                ssh_cmd.extend(["-i", self.key_file])

            ssh_cmd.extend(["-p", str(self.port), f"{self.username}@{self.target}"])

            if self.password and not self.key_file:
                # Use sshpass for password authentication
                full_cmd = ["sshpass", "-p", self.password] + ssh_cmd
            else:
                full_cmd = ssh_cmd

            # Allocate a PTY and attach SSH to its slave end. openpty +
            # Popen(setsid) + close-slave is the shared spawn in
            # core.pty_session now; close_fds=True matches the subprocess
            # default this relied on before the extraction.
            session = PtySession.spawn(full_cmd, close_fds=True)
            self.master_fd = session.master_fd
            self.slave_fd = None
            self.process = session.process

            # Wait for connection establishment
            time.sleep(2)

            # Test if connection is ready by sending a simple command
            # Note: We need to test the connection directly via the PTY before setting is_connected
            try:
                # Read initial SSH output via the shared session. session.read
                # folds select+os.read: None (nothing ready within 5s) and b""
                # (EOF) both fall through to the command test below, exactly as
                # the old select/if-ready pair did; only real bytes are checked
                # for a refusal banner.
                test_data = self._pty_io().read(5.0, 1024)
                if test_data:
                    if b"Connection refused" in test_data or b"Connection timed out" in test_data:
                        self.stop()
                        return {
                            "success": False,
                            "error": "SSH connection refused or timed out",
                            "details": test_data.decode(errors='ignore')
                        }

                # Now we can set connected flag and test with a command
                self.is_connected = True
                test_result = self.send_command("echo 'SSH_CONNECTION_TEST'", timeout=10)

                logger.info(f"SSH connection test result: {test_result}")

                # If the command executed successfully, SSH connection is working
                if test_result.get("success"):
                    output = test_result.get("output", "")
                    if "SSH_CONNECTION_TEST" in output:
                        logger.info(f"SSH session established successfully to {self.target}")
                        return {
                            "success": True,
                            "message": f"SSH session started to {self.username}@{self.target}:{self.port}",
                            "session_id": self.session_id,
                            "target": self.target,
                            "username": self.username
                        }
                    else:
                        logger.warning(f"SSH test command succeeded but output unexpected: '{output}'")
                        # Still consider it a success if command executed
                        return {
                            "success": True,
                            "message": f"SSH session started to {self.username}@{self.target}:{self.port}",
                            "session_id": self.session_id,
                            "target": self.target,
                            "username": self.username,
                            "warning": "Connection test output was unexpected but command executed"
                        }
                else:
                    logger.error(f"SSH test command failed: {test_result}")
            except Exception as test_error:
                logger.error(f"SSH connection test failed: {str(test_error)}")
                # Don't fail immediately - maybe the connection still works

            # If we get here, connection failed
            self.is_connected = False
            self.stop()
            return {
                "success": False,
                "error": "SSH connection failed or not responding",
                "test_result": test_result if 'test_result' in locals() else {"error": "Connection test failed"}
            }

        except Exception as e:
            logger.error(f"Error starting SSH session: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def send_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Send a command to the SSH session"""
        if not self.is_connected or not self.master_fd:
            return {
                "success": False,
                "error": "No active SSH connection",
                "output": ""
            }

        try:
            # Redact before truncating so a truncated flag/value pair cannot
            # bypass credential detection.
            command_metadata = render_command(command)
            if len(command_metadata) > 100:
                log_command = f"{command_metadata[:50]}...{command_metadata[-20:]}"
            else:
                log_command = command_metadata
            logger.info(f"Executing SSH command: {log_command}")
            self.command_count += 1

            # Generate unique end marker
            marker_id = str(uuid.uuid4())[:8]
            end_marker = f"SSH_END_{marker_id}"

            # Add debug flag for base64 commands
            is_base64_cmd = "base64" in command.lower()
            if is_base64_cmd:
                logger.info(f"Executing base64 command on {self.target}")

            # Send command and marker. One PtySession wraps the current fd for
            # both these writes and the read loop below.
            pty = self._pty_io()
            pty.write((command + "\n").encode())
            time.sleep(0.2)  # Increased delay for base64 commands
            pty.write((f"echo '{end_marker}'\n").encode())

            # Collect output until we see the end marker
            start_time = time.time()
            output_lines = []
            buffer = b""

            while time.time() - start_time < timeout:
                # session.read folds select+os.read: None is the old not-ready
                # case (the loop simply re-polls), b"" the EOF break, bytes the
                # data branch. The body and its OSError guard are unchanged.
                data = pty.read(1.0, 1024)
                if data is not None:
                    try:
                        if not data:
                            break

                        buffer += data

                        # Process complete lines
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            text = line.decode(errors='ignore').strip()

                            # Check for end marker
                            if end_marker in text:
                                if is_base64_cmd and text.strip() != f"echo '{end_marker}'" and not text.startswith("echo '"):
                                    # This line has content AND the end marker - split them
                                    # For base64, we need to be more careful about what we extract
                                    if end_marker in text:
                                        # Find the position of the end marker and extract everything before it
                                        marker_pos = text.find(end_marker)
                                        content_part = text[:marker_pos].strip()

                                        # For base64 commands, be very minimal in cleaning - just remove obvious shell prompts
                                        import re
                                        # Only clean if there's an obvious shell prompt at the start
                                        if re.match(r'^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:[^$]*\$\s', content_part):
                                            # Remove only the shell prompt part
                                            content_part = re.sub(r'^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:[^$]*\$\s+', '', content_part)

                                        content_part = content_part.strip()

                                        # For base64, accept almost anything that's reasonably long
                                        if len(content_part) > 5:  # Very minimal length check
                                            output_lines.append(content_part)

                                # Before returning, check if there's remaining data in buffer (base64 without newline)
                                if buffer.strip():
                                    remaining_text = buffer.decode(errors='ignore').strip()
                                    if remaining_text and not self._is_ssh_noise(remaining_text):
                                        output_lines.append(remaining_text)

                                # Clean ANSI escape sequences from all output lines before final output
                                import re
                                ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]')
                                cleaned_lines = []
                                for line in output_lines:
                                    clean_line = ansi_escape.sub('', line).strip()
                                    if clean_line:  # Only keep non-empty lines after cleaning
                                        cleaned_lines.append(clean_line)

                                output = '\n'.join(cleaned_lines)
                                if is_base64_cmd:
                                    logger.info("[SSH] Base64 command completed successfully")
                                return {
                                    "success": True,
                                    "output": output,
                                    "command": command_metadata,
                                    "session_id": self.session_id,
                                    "execution_time": time.time() - start_time
                                }

                            # Skip command echo and end marker echo, but be much more permissive
                            should_skip = False

                            # Skip exact command echo
                            if text == command:
                                should_skip = True
                            # Skip end marker echo
                            elif text.startswith("echo '") and end_marker in text:
                                should_skip = True
                            # For base64 commands, be more permissive and don't filter potential base64 content
                            elif is_base64_cmd:
                                # Don't filter base64 content - only filter obvious shell prompts and noise
                                if self._is_shell_prompt_only(text):
                                    should_skip = True
                            # Only skip obvious noise for non-base64 commands
                            elif self._is_ssh_noise(text):
                                should_skip = True

                            if not should_skip and text:
                                output_lines.append(text)

                    except OSError:
                        break

            # Timeout reached - clean ANSI sequences from output before returning
            import re
            ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]')
            cleaned_lines = []
            for line in output_lines:
                clean_line = ansi_escape.sub('', line).strip()
                if clean_line:  # Only keep non-empty lines after cleaning
                    cleaned_lines.append(clean_line)

            output = '\n'.join(cleaned_lines)
            if is_base64_cmd:
                logger.info("[SSH] Base64 command timed out")
            return {
                "success": True,
                "output": output,
                "command": command_metadata,
                "session_id": self.session_id,
                "execution_time": time.time() - start_time,
                "timeout": True
            }

        except Exception as e:
            logger.error(f"Error executing SSH command: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": ""
            }

    def _is_ssh_noise(self, line):
        """Check if a line is SSH noise that should be filtered out"""
        stripped = line.strip()

        # Don't filter empty lines
        if not stripped:
            return True

        # Clean ANSI escape sequences FIRST before any other checks
        import re
        ansi_pattern = r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]|\x1b\[[?0-9]+[lh]'
        clean_line = re.sub(ansi_pattern, '', stripped).strip()

        # Don't filter content that looks like command output (starts and ends with single quotes)
        if clean_line.startswith("'") and clean_line.endswith("'") and len(clean_line) > 2:
            return False

        # Don't filter potential checksums (64-char hex strings like SHA256)
        if len(clean_line) == 64 and all(c in '0123456789abcdef' for c in clean_line.lower()):
            return False

        # Don't filter potential base64 content (longer than 10 chars)
        if len(clean_line) > 10 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in clean_line):
            return False

        # If after removing ANSI codes, the line is empty, it's noise
        if not clean_line:
            return True

        # Filter obvious shell prompts and login messages (use clean_line, not stripped)
        noise_patterns = [
            "Last login:",
            "Welcome to",
            "bash-",
        ]

        for pattern in noise_patterns:
            if pattern in clean_line:
                return True

        # Filter shell prompts ($ or # at end, or username@hostname patterns)
        if clean_line.endswith('$') or clean_line.endswith('#') or clean_line == '$' or clean_line == '#':
            return True
        if clean_line.endswith('$ ') or clean_line.endswith('# '):
            return True

        # Filter username@hostname patterns more specifically (but allow normal content)
        if '@' in clean_line and (clean_line.endswith('$') or clean_line.endswith('#')):
            # Check if it looks like a shell prompt (user@host:path$ or user@host#)
            if ':' in clean_line and (clean_line.endswith('$') or clean_line.endswith('#')):
                return True
            # Simple user@host$ pattern
            if clean_line.count('@') == 1 and (clean_line.endswith('$') or clean_line.endswith('#')):
                return True

        # Don't filter actual command output - be more permissive
        return False

    def _is_shell_prompt_only(self, line):
        """Check if a line is ONLY a shell prompt (more restrictive than _is_ssh_noise)"""
        stripped = line.strip()

        if not stripped:
            return True

        # Clean ANSI escape sequences first
        import re
        ansi_pattern = r'\x1b\[[0-9;]*[mGKHlh]|\x1b\[[?0-9;]*[lh]|\x1b\[[?0-9]+[lh]'
        clean_line = re.sub(ansi_pattern, '', stripped).strip()

        if not clean_line:
            return True

        # Only filter obvious shell prompts - be very restrictive
        if clean_line.endswith('$') or clean_line.endswith('#'):
            if '@' in clean_line and ':' in clean_line:
                # Looks like user@host:path$ or user@host:path#
                return True
            elif clean_line == '$' or clean_line == '#':
                # Just $ or #
                return True

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get the status of the SSH session"""
        if getattr(self, "restored", False):
            # Rebuilt from ssh_sessions.json after a backend restart. No
            # process and no master_fd are held, so process.poll() is never
            # reached -- this returns a fixed stopped report rather than
            # probing a handle it does not own (CLAUDE.md rule 3). The
            # password was never persisted, so a reloaded entry cannot
            # reconnect; it is a tombstone, not a usable session.
            return {
                "session_id": self.session_id,
                "target": self.target,
                "username": self.username,
                "port": self.port,
                "created_at": getattr(self, "created_at", None),
                "status": "stopped",
                "is_connected": False,
                "process_alive": False,
                "restored": True,
                "start_time": self.start_time,
                "command_count": self.command_count,
                "note": (
                    "the backend restarted; this SSH session is gone. "
                    "The record survived but the connection did not, and "
                    "the credential was never persisted, so commands are "
                    "refused -- start a new session."
                ),
            }
        return {
            "session_id": self.session_id,
            "target": self.target,
            "username": self.username,
            "port": self.port,
            "created_at": self.created_at,
            "is_connected": self.is_connected,
            "process_alive": self.process and self.process.poll() is None,
            "restored": False,
            "start_time": self.start_time,
            "command_count": self.command_count
        }

    def read_output(self, timeout: int = 5, max_lines: int = 100) -> str:
        """Read any pending output from the PTY without sending a command."""
        if not self.is_connected or not self.master_fd:
            return ""
        lines = []
        buf = b""
        deadline = time.time() + timeout
        consecutive_empty = 0
        while time.time() < deadline and len(lines) < max_lines:
            ready, _, _ = select.select([self.master_fd], [], [], 0.5)
            if self.master_fd in ready:
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        consecutive_empty += 1
                        if consecutive_empty >= 3:
                            break
                        continue
                    consecutive_empty = 0
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        text = line.decode(errors="ignore").strip()
                        if text and not self._is_ssh_noise(text):
                            lines.append(text)
                except OSError:
                    break
            else:
                if lines:
                    break
        return "\n".join(lines)

    def stop(self):
        """Stop the SSH session.

        Teardown now goes through PtySession.close(), a DELIBERATE upgrade over
        the old bare self.process.terminate(): SSH is spawned under os.setsid, so
        a plain terminate() signalled only the leader and could orphan an ssh
        control-master child or a proxy it had forked. close() signals the whole
        process group -- SIGTERM, escalate to SIGKILL on a timeout, then probe
        and reap a surviving child -- and closes the master fd, the same ladder
        reverse_shell_manager and metasploit_manager already use. Not a byte of
        captured output is involved, so the golden masters do not reach it; it is
        covered by
        tests/test_pty_session.py::test_ssh_stop_tears_down_through_the_pty_group_close.
        """
        try:
            if self.process is not None:
                logger.info(f"Stopping SSH session to {self.target}")
                self._pty_io().close()
                self.process = None
                self.master_fd = None
            elif self.master_fd is not None:
                # No process to signal, but a dangling fd still to release --
                # close() is a no-op without a process, so close it directly.
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                self.master_fd = None

        except Exception as e:
            logger.error(f"Error stopping SSH session: {str(e)}")

        self.is_connected = False
        logger.info("SSH session stopped")

    def upload_content(self, content: str, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """Upload content with checksum verification using FileTransferManager."""
        try:
            from utils.transfer_manager import transfer_manager
            return transfer_manager.upload_via_ssh_with_verification(
                ssh_manager=self,
                content=content,
                remote_file=remote_file,
                encoding=encoding
            )
        except Exception as e:
            logger.error(f"Error in SSH upload: {str(e)}")
            return {"error": str(e), "success": False}

    def download_content(self, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """Download content with checksum verification using FileTransferManager."""
        try:
            from utils.transfer_manager import transfer_manager
            return transfer_manager.download_via_ssh_with_verification(
                ssh_manager=self,
                remote_file=remote_file,
                encoding=encoding
            )
        except Exception as e:
            logger.error(f"Error in SSH download: {str(e)}")
            return {"error": str(e), "success": False}


_SSH_STATE_FILENAME = "ssh_sessions.json"


def _ssh_store() -> StateStore:
    """StateStore over ``<session_state_dir>/ssh_sessions.json``.

    Resolved at call time so the state dir honours ZKM_STATE_DIR / the
    job-dir sibling without caching a path from import.
    """
    return StateStore(os.path.join(session_state_dir(), _SSH_STATE_FILENAME))


def persist_sessions(active_ssh_sessions) -> bool:
    """Write SSH session METADATA to ssh_sessions.json. Never raises.

    Called on create and on stop -- never on an is_connected flip. Stores
    only the PATH to a key file, NEVER its contents and NEVER the
    password: a dead reloaded entry cannot use a credential, and writing
    one would create a secret-at-rest the memory-only state never had.
    This is not log redaction -- no operator-visible output is withheld; a
    field that was never persisted is simply not added. Returns whether
    the write landed (``persisted``); an unwritable state dir degrades to
    False and the session operation carries on (CLAUDE.md rule 2).
    """
    records = {}
    for session_id, manager in list(active_ssh_sessions.items()):
        records[str(session_id)] = {
            "session_id": manager.session_id,
            "target": manager.target,
            "username": manager.username,
            "port": manager.port,
            "key_file": manager.key_file or "",
            "created_at": getattr(manager, "created_at", None),
        }
    try:
        os.makedirs(session_state_dir(), exist_ok=True)
        _ssh_store().save({"sessions": records})
        return True
    except Exception as exc:
        logger.warning(f"Could not persist SSH sessions: {exc}")
        return False


def restore_sessions(active_ssh_sessions) -> int:
    """Rebuild restored stand-ins from a prior process's ssh_sessions.json.

    Run once at backend start. Each stand-in is a lightweight
    SSHSessionManager carrying NO process, NO master_fd and NO password
    (the constructor leaves process/master_fd None; password defaults to
    ""), so send_command refuses it on its existing ``not is_connected or
    not master_fd`` guard and nothing polls a pid on its behalf (CLAUDE.md
    rule 3). get_status reports it as status=stopped, is_connected=False,
    process_alive=False, restored=True. Never raises: a missing or corrupt
    file leaves the registry empty, exactly as a fresh boot would. Returns
    how many stand-ins were registered.
    """
    try:
        state = _ssh_store().load()
    except Exception as exc:
        logger.warning(f"Could not load SSH sessions: {exc}")
        return 0
    records = state.get("sessions")
    if not isinstance(records, dict):
        return 0
    restored = 0
    for session_id, record in records.items():
        if not isinstance(record, dict) or session_id in active_ssh_sessions:
            continue
        try:
            manager = SSHSessionManager(
                record.get("target", ""),
                record.get("username", ""),
                password="",
                key_file=record.get("key_file", "") or "",
                port=record.get("port", 22),
                session_id=record.get("session_id", session_id),
            )
        except Exception:
            continue
        manager.restored = True
        manager.created_at = record.get("created_at") or manager.created_at
        active_ssh_sessions[session_id] = manager
        restored += 1
    return restored
