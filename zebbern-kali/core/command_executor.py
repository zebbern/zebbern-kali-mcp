#!/usr/bin/env python3
"""Command Executor Manager for Kali Server."""

import os
import subprocess
import threading
from typing import Dict, Any, Callable
from .config import logger, COMMAND_TIMEOUT
from .logging_utils import render_command

KILL_MSG_DIR = "/app/tmp/.kill_messages"


class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line

    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line

    def _read_stdout_with_streaming(self, on_output):
        """Thread function to continuously read stdout with streaming callback"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
            if on_output and line.strip():
                try:
                    on_output("stdout", line.strip())
                except Exception as e:
                    logger.error(f"Error in streaming callback: {e}")

    def _read_stderr_with_streaming(self, on_output):
        """Thread function to continuously read stderr with streaming callback"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
            if on_output and line.strip():
                try:
                    on_output("stderr", line.strip())
                except Exception as e:
                    logger.error(f"Error in streaming callback: {e}")

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info("Executing command: %s", render_command(self.command))

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()

                # Update final output
                self.return_code = -1

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
            self._inject_kill_message(result)
            return result

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }

    def _inject_kill_message(self, result: Dict[str, Any]) -> None:
        """Check if the user left a message when killing this process."""
        if self.process is None:
            return
        msg_path = os.path.join(KILL_MSG_DIR, str(self.process.pid))
        try:
            if os.path.exists(msg_path):
                with open(msg_path, "r") as f:
                    user_msg = f.read().strip()
                os.remove(msg_path)
                if user_msg:
                    result["user_killed"] = True
                    result["user_message"] = user_msg
                    logger.info(f"Kill message for PID {self.process.pid}: {user_msg}")
        except OSError:
            pass

    def execute_with_streaming(self, on_output: Callable[[str, str], None]) -> Dict[str, Any]:
        """Execute the command with streaming output via callback"""
        logger.info("Executing command with streaming: %s", render_command(self.command))

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Start threads to read output continuously with streaming
            self.stdout_thread = threading.Thread(target=self._read_stdout_with_streaming, args=(on_output,))
            self.stderr_thread = threading.Thread(target=self._read_stderr_with_streaming, args=(on_output,))
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()

                # Update final output
                self.return_code = -1

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "streaming_enabled": True
            }
            self._inject_kill_message(result)
            return result

        except Exception as e:
            logger.error(f"Error executing command with streaming: {str(e)}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "streaming_enabled": True
            }


def execute_command(command: str, on_output: Callable[[str, str], None] = None, timeout: int = None) -> Dict[str, Any]:
    """
    Execute a shell command with optional streaming and tool-specific behavior.

    Args:
        command: The command to execute
        on_output: Optional callback function for streaming output (source, line)
        timeout: Optional timeout override (uses tool-specific timeout if not provided)

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    from .tool_config import is_streaming_tool, get_tool_timeout

    # Parse the command to detect the tool
    command_parts = command.strip().split()
    if not command_parts:
        return {
            "success": False,
            "error": "Empty command provided",
            "stdout": "",
            "stderr": "",
            "return_code": -1
        }

    tool_name = command_parts[0]

    # Get tool-specific timeout if not provided
    if timeout is None:
        timeout = get_tool_timeout(tool_name)

    # Check if the tool requires streaming
    requires_streaming = is_streaming_tool(tool_name)

    # Create executor with appropriate timeout
    executor = CommandExecutor(command, timeout=timeout)

    # If streaming callback is provided or tool requires streaming, enable streaming
    if on_output or requires_streaming:
        return executor.execute_with_streaming(on_output)
    else:
        return executor.execute()


def execute_command_argv(argv: list, on_output: Callable[[str, str], None] = None, timeout: int = None) -> Dict[str, Any]:
    """
    Execute a command using an argv list, quoting arguments for shell execution.

    Args:
        argv: List of command arguments (e.g., ['nmap', '-sV', '192.168.1.1'])
        on_output: Optional callback function for streaming output (source, line)
        timeout: Optional timeout override

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    import shlex

    if not argv or len(argv) == 0:
        return {
            "success": False,
            "error": "Empty argv provided",
            "stdout": "",
            "stderr": "",
            "return_code": -1
        }

    # Keep the tool name unquoted and quote arguments to handle special characters safely.
    tool_name = argv[0]
    if len(argv) > 1:
        quoted_args = ' '.join(shlex.quote(arg) for arg in argv[1:])
        command = f"{tool_name} {quoted_args}"
    else:
        command = tool_name

    # Use the existing execute_command function for timeout and streaming behavior.
    return execute_command(command, on_output=on_output, timeout=timeout)


def stream_command_execution(
    command: str,
    streaming: bool = False,
    timeout: int = None,
):
    """
    Execute a command with optional streaming support.

    Args:
        command: The command to execute
        streaming: Whether streaming was explicitly requested
        timeout: Optional execution timeout override

    Yields:
        Server-sent events for streaming response
    """
    import json
    import queue
    import threading
    from .tool_config import is_streaming_tool

    def sse_event(event_type: str, **fields) -> str:
        payload = {"type": event_type, **fields}
        return f"data: {json.dumps(payload)}\n\n"

    # Check if streaming is requested or auto-detect
    tool_name = command.split()[0] if command.strip() else ""
    should_stream = streaming or is_streaming_tool(tool_name)

    if not should_stream:
        # Non-streaming execution
        result = execute_command(command, timeout=timeout)
        yield sse_event(
            "result",
            success=result["success"],
            return_code=result["return_code"],
            timed_out=result.get("timed_out", False),
        )
        yield sse_event("complete")
        return

    # Bound the handoff queue and apply backpressure when the client is slow.
    output_queue = queue.Queue(maxsize=1024)
    consumer_closed = threading.Event()
    done = object()

    def enqueue(item) -> bool:
        while not consumer_closed.is_set():
            try:
                output_queue.put(item, timeout=0.2)
                return True
            except queue.Full:
                continue
        return False

    def handle_output(source, line):
        enqueue(sse_event("output", source=source, line=line))

    # Execute command in separate thread
    result_container = {}

    def execute_in_thread():
        try:
            result = execute_command(
                command,
                on_output=handle_output,
                timeout=timeout,
            )
            result_container['result'] = result
        except Exception as e:
            result_container['error'] = str(e)
        finally:
            enqueue(done)

    thread = threading.Thread(
        target=execute_in_thread,
        daemon=True,
        name="command-stream-worker",
    )
    thread.start()

    try:
        while True:
            try:
                item = output_queue.get(timeout=1)
            except queue.Empty:
                yield sse_event("heartbeat")
                continue
            if item is done:
                break
            yield item

        thread.join()

        if 'result' in result_container:
            result = result_container['result']
            yield sse_event(
                "result",
                success=result["success"],
                return_code=result["return_code"],
                timed_out=result.get("timed_out", False),
            )
        elif 'error' in result_container:
            yield sse_event(
                "error",
                message=f"Server error: {result_container['error']}",
            )

        yield sse_event("complete")
    finally:
        consumer_closed.set()
