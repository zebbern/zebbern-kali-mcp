#!/usr/bin/env python3
"""Metasploit Session Manager for persistent msfconsole sessions."""

import os
import pty
import select
import subprocess
import threading
import time
import uuid
from typing import Dict, Any, Optional
from queue import Queue, Empty
from core.config import logger

class MetasploitSession:
    """Represents a single persistent msfconsole session."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.output_buffer: str = ""
        self.output_lock = threading.Lock()
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_ready = False
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        
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
            
            # Wait for prompt to appear
            self._wait_for_prompt(timeout=30)
            self.is_ready = True
            
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
                        with self.output_lock:
                            self.output_buffer += data.decode("utf-8", errors="replace")
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
    
    def execute(self, command: str, timeout: float = 300) -> Dict[str, Any]:
        """Execute a command in the msfconsole session."""
        if not self.process or self.process.poll() is not None:
            return {"error": "Session is not running", "success": False}
        
        try:
            # Clear output buffer
            with self.output_lock:
                self.output_buffer = ""
            
            # Send command
            os.write(self.master_fd, (command + "\n").encode())
            self.last_activity = time.time()
            
            # Wait for output and prompt
            time.sleep(0.5)  # Brief pause for command to start
            
            start_time = time.time()
            last_output_len = 0
            stable_count = 0
            
            while time.time() - start_time < timeout:
                time.sleep(0.5)
                
                with self.output_lock:
                    current_len = len(self.output_buffer)
                    
                    # Check if output has stabilized (no new output for 2 seconds)
                    if current_len == last_output_len:
                        stable_count += 1
                        if stable_count >= 4:  # 2 seconds of stability
                            # Check for prompt
                            if "msf" in self.output_buffer[-200:] and ">" in self.output_buffer[-200:]:
                                break
                    else:
                        stable_count = 0
                        last_output_len = current_len
            
            with self.output_lock:
                output = self.output_buffer
            
            return {
                "success": True,
                "output": output,
                "session_id": self.session_id,
                "execution_time": time.time() - start_time
            }
            
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {"error": str(e), "success": False}
    
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
    
    def execute_command(self, session_id: str, command: str, timeout: float = 300) -> Dict[str, Any]:
        """Execute a command in an existing session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return {"error": f"Session {session_id} not found", "success": False}
            if not session.is_alive():
                del self.sessions[session_id]
                return {"error": f"Session {session_id} is no longer running", "success": False}
        
        return session.execute(command, timeout)
    
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
