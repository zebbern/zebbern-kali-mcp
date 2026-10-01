"""Consolidated reverse shell management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register all reverse shell tools (consolidated from revshell_* and reverse_shell_*)."""

    @mcp.tool()
    def reverse_shell_listener_start(
        port: int = 4444, session_id: str = "",
        listener_type: str = "netcat",
    ) -> Dict[str, Any]:
        """
        Start a reverse shell listener on the specified port.

        WARNING -- a blocking interactive shell HOLDS the exploited process.
        Catching `bash -i` from a single-threaded target (an SQS poll loop, a
        worker, a cron script, an appliance daemon) blocks that process for as
        long as you hold the shell: its own work stops, and any other RCE
        channel through it stops with it. Nothing reports this --
        reverse_shell_status stays healthy throughout, because the socket and
        the listener really are fine. If the target has other work to do, send
        a backgrounded or short-lived payload instead of an interactive shell,
        and expect to lose the second channel while you hold the first.

        There used to be an `auto_upgrade` flag here, documented as attempting
        a TTY upgrade on connection. Nothing in the backend read it and no
        upgrade code exists, so it was a capability the schema advertised and
        the tool did not have. To upgrade a shell once it lands, send the
        spawn yourself with reverse_shell_command, e.g.
        `python3 -c 'import pty; pty.spawn("/bin/bash")'`, and read the reply
        to see whether it took.

        Args:
            port: Port to listen on (default: 4444)
            session_id: Optional session identifier (auto-generated as shell_{port} if empty)
            listener_type: Type of listener - 'netcat' or 'pwncat' (default: netcat)

        Returns:
            Session ID and listener status
        """
        data = {
            "port": port,
            "session_id": session_id or f"shell_{port}",
            "listener_type": listener_type,
        }
        return kali_client.safe_post("api/reverse-shell/listener/start", data)

    @mcp.tool()
    def reverse_shell_command(
        session_id: str, command: str, timeout: int = 45,
        suppress_history: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a command in an active reverse shell session.

        Check `timed_out` and `session_closed`, never `success`. The backend
        wraps the command in marker lines and only the marker line the shell
        ACTUALLY EXECUTED counts -- a PTY echoes the typed `echo 'START_x'`
        back, and treating that echo as evidence used to report
        `success: true, lines_captured: 0` on a live shell that ran nothing.
        A live socket is not a usable channel.

        When the capture comes back `timed_out` or empty, the session is not a
        write-off: drive it with reverse_shell_send_input and
        reverse_shell_read_output, which need no markers at all.

        WARNING -- a blocking interactive shell HOLDS the exploited process.
        A `bash -i` caught from a single-threaded target freezes that process's
        own work, and any other RCE channel through it, for as long as you hold
        the shell. reverse_shell_status reports healthy throughout.

        Args:
            session_id: The session ID (e.g., 'shell_4444')
            command: Command to execute on the target
            timeout: Command timeout in seconds. Default 45, under the MCP
                harness's ~60s abort, so this tool's own timed_out result (with
                whatever partial output arrived) gets back to you instead of the
                call being abandoned. Raising it past ~55 trades that honest
                answer for a harness-level timeout; for long work, run it with
                reverse_shell_send_input and poll reverse_shell_read_output.
            suppress_history: On the first command of a session, send a prelude
                that keeps THIS TOOL'S OWN marker lines out of the TARGET's
                shell history (HISTFILE/HISTSIZE/`set +o history`, each guarded
                with its own 2>/dev/null so a dash/ash/busybox target cannot
                error into your capture). It withholds nothing from you: all
                output still comes back, and the prelude and its echo are
                drained before any capture starts. The returned
                `history_suppressed` says the prelude was sent, not that the
                target honoured it.

        Returns:
            Command output from the target system
        """
        data = {
            "command": command,
            "timeout": timeout,
            "suppress_history": suppress_history,
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/command", data)

    @mcp.tool()
    def reverse_shell_send_input(session_id: str, input_text: str) -> Dict[str, Any]:
        """
        Write raw bytes to a caught reverse shell. No markers, no capture.

        The fallback for everything reverse_shell_command's marker scrape cannot
        do: a target shell with no TTY, a wedged prompt, a REPL, `su`/`ssh`
        asking for a password, or a command that needs longer than one
        synchronous call. `send_input` and `read_output` only reach zebbern_exec
        jobs through job_manager; reverse shells are separate, and this is their
        equivalent.

        You supply any trailing newline -- nothing is appended. A successful
        write means the bytes left the MCP backend, NOT that the far end ran
        them; read the reply with reverse_shell_read_output.

        Args:
            session_id: The reverse shell session ID
            input_text: Exact bytes to write, including the newline if you want
                the line submitted (e.g. "id\\n")

        Returns:
            bytes_written, plus success for whether the write itself landed
        """
        return kali_client.safe_post(
            f"api/reverse-shell/{session_id}/send-raw", {"input": input_text}
        )

    @mcp.tool()
    def reverse_shell_read_output(
        session_id: str, timeout: int = 5, max_lines: int = 100,
        drop_shell_noise: bool = False,
    ) -> Dict[str, Any]:
        """
        Read whatever a caught reverse shell has sent, without sending anything.

        The read half of the raw path paired with reverse_shell_send_input. It
        is a bounded polling WINDOW, not a transcript: `max_lines` bounds one
        call and the surplus is CARRIED on the session for the next one, so
        poll until `carry_over` is empty and you stop getting output. Nothing
        read off the shell is dropped to honour the bound. `success: true` with
        an empty `output` means the window ran and the shell was quiet -- it is
        not a failure, and it is not proof the channel works either (see
        reverse_shell_status' shell_responsive).

        A prompt with no trailing newline -- `Password: `, `>>> `, `(gdb) `,
        i.e. the whole reason this channel exists -- comes back in the window
        that read it rather than being held for the next one. A long line split
        across two windows therefore arrives in two pieces, in order.

        Args:
            session_id: The reverse shell session ID
            timeout: Longest this window waits, in seconds. It returns as soon
                as the shell goes quiet with something in hand, so a prompt
                does not cost the whole budget.
            max_lines: Lines returned by this call; the rest waits in
                `carry_over` for the next one
            drop_shell_noise: Off by default, so every line comes back as it
                arrived (stripped of surrounding whitespace, blank lines
                skipped -- as this channel has always done). On, it filters
                listener banners and prompt-looking lines -- including any line
                ending in '$', which is real output often enough that it is not
                the default, and those lines ARE dropped, which is why you ask
                for it explicitly.

        Returns:
            output, lines_returned, the window_limit that bounded it, and
            carry_over {lines, bytes} still held for the next call
        """
        return kali_client.safe_get(
            f"api/reverse-shell/{session_id}/read-output",
            params={
                "timeout": timeout,
                "lines": max_lines,
                "drop_shell_noise": str(bool(drop_shell_noise)).lower(),
            },
        )

    @mcp.tool()
    def reverse_shell_send_payload(session_id: str, payload_command: str, timeout: int = 10, wait_seconds: int = 5) -> Dict[str, Any]:
        """
        Send a payload command to trigger a reverse shell connection in a non-blocking way.

        Executes the payload in a background thread to avoid blocking the server.
        Waits then returns session status to verify the connection was established.

        Args:
            session_id: The session ID of the reverse shell listener
            payload_command: The payload command to execute (e.g., curl with reverse shell)
            timeout: Timeout for the payload execution in seconds (default: 10)
            wait_seconds: Seconds to wait before checking session status (default: 5)

        Returns:
            Payload execution status and session info
        """
        data = {
            "payload_command": payload_command,
            "timeout": timeout,
            "wait_seconds": wait_seconds,
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/send-payload", data)

    @mcp.tool()
    def reverse_shell_status(session_id: str = "") -> Dict[str, Any]:
        """
        Get the status of reverse shell sessions.

        `is_connected`, `actual_network_connection` and `process_alive` are
        TCP-and-process facts only. All three read true on a channel that had
        stopped executing anything -- the socket stays ESTABLISHED while the far
        end sits on a wedged prompt, holds stdin inside an interactive program,
        or echoes with no shell behind it. A live process is not a working one.
        `shell_responsive` is the only field here that reflects the CHANNEL: it
        is None until a command has been tried, True only when one reached its
        executed end marker on a live session, and False when the last one timed
        out or the session closed. For anything stronger, run a command and read
        its `timed_out`/`session_closed`, or poll reverse_shell_read_output.

        Listeners and caught shells live in backend memory only. A backend
        restart drops them and this returns empty with no error, which reads
        exactly like a payload that never called back -- check whether the
        backend was recreated before concluding the target never fired.

        Args:
            session_id: Optional specific session ID to check (if empty, shows all sessions)

        Returns:
            Status information for reverse shell sessions
        """
        if session_id:
            return kali_client.safe_get(f"api/reverse-shell/{session_id}/status")
        return kali_client.safe_get("api/reverse-shell/sessions")

    @mcp.tool()
    def reverse_shell_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop a reverse shell session.

        Args:
            session_id: The session ID to stop

        Returns:
            Stop operation result
        """
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/stop", {})

    @mcp.tool()
    def reverse_shell_upload_content(
        session_id: str, content: str, remote_file: str,
        method: str = "base64", encoding: str = "base64",
    ) -> Dict[str, Any]:
        """
        Upload content directly to the target via reverse shell.

        Args:
            session_id: The reverse shell session ID
            content: Base64 encoded content to upload
            remote_file: Path where to save the file on the target
            method: Upload method (base64)
            encoding: How to treat `content` before writing. "base64"
                decodes it, which is what the content argument above
                describes and the default. Pass "utf-8" only to write the
                string through literally -- with base64 content that lands
                as the base64 text itself, and the checksum still matches
                because both ends hash the same wrong bytes.
        """
        data = {
            "session_id": session_id,
            "content": content,
            "remote_file": remote_file,
            "method": method,
            "encoding": encoding,
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/upload-content", data)

    @mcp.tool()
    def reverse_shell_download_content(session_id: str, remote_file: str, method: str = "base64") -> Dict[str, Any]:
        """
        Download file content from target via reverse shell and return as base64.

        Args:
            session_id: The reverse shell session ID
            remote_file: Path to the file on the target
            method: Download method (base64, cat)
        """
        data = {"remote_file": remote_file, "method": method}
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/download-content", data)

    @mcp.tool()
    def reverse_shell_generate_payload(
        local_ip: str, local_port: int = 4444,
        payload_type: str = "bash", encoding: str = "base64",
    ) -> Dict[str, Any]:
        """
        Generate reverse shell payloads for manual execution on targets.

        Args:
            local_ip: Your local IP address that the target should connect back to
            local_port: Local port to connect back to (default: 4444)
            payload_type: Type of payload (bash, python, nc, php, powershell, perl)
            encoding: Encoding format (plain, base64, url, hex)

        Returns:
            Generated payload in various formats ready for manual execution
        """
        data = {
            "local_ip": local_ip,
            "local_port": local_port,
            "payload_type": payload_type,
            "encoding": encoding,
        }
        return kali_client.safe_post("api/reverse-shell/generate-payload", data)
