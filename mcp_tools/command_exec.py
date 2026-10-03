"""Command execution and system info tools."""

import importlib.metadata
import json
import logging
import re
from typing import Dict, Any

import requests
from mcp.server.fastmcp import FastMCP

from ._autopromote import run_promotable

logger = logging.getLogger(__name__)

# A negative return_code is a signal number, not an exit status. Only these
# three are worth naming; anything else falls through unannotated rather than
# guessing.
_SIGNAL_EXITS = {-15: "SIGTERM", -9: "SIGKILL", -2: "SIGINT"}

# Commands that choose their victims INDIRECTLY -- by pattern, by process name,
# or by who holds a resource -- and so can reach the shell running them. Maps a
# binary to the flag that turns on indirect selection, or None when it always
# selects that way.
#
# `kill` is deliberately absent: it names PIDs, so it cannot self-match, and
# attaching the hint to `kill -TERM 4567` blamed a self-match that never
# happened on what is usually an outside kill. `pgrep` is absent too -- it kills
# nothing on its own, and `pgrep -f x | xargs kill` carries no token this can
# key on without guessing.
_PATTERN_KILLERS = {
    "pkill": ("f", "full"),     # -f matches the full argv, which holds this command
    "fuser": ("k", "kill"),     # -k kills whoever holds the named file/port
    "killall": None,            # always by process name, and ours is sh/bash
}

# Shell separators, so a flag in one segment cannot be credited to a binary in
# another (`pkill nginx && echo -f` is not a `pkill -f`).
_SEGMENT_SPLIT = re.compile(r"[;\n|&()]+")


def _selects_processes_by_pattern(command: str) -> bool:
    """True when *command* picks processes indirectly, so its own shell is a
    candidate victim.

    Token equality on the binary's basename, never a substring: `grep killer`,
    `./skillall` and `nmap --script ssl-kill` are not kill commands, and the
    substring test this replaced annotated all of them.
    """
    if not isinstance(command, str):
        return False
    for segment in _SEGMENT_SPLIT.split(command):
        tokens = segment.split()
        for index, token in enumerate(tokens):
            flags = _PATTERN_KILLERS.get(token.rsplit("/", 1)[-1], False)
            if flags is False:
                continue  # not one of them (None is a real entry: always matches)
            if flags is None:
                return True
            short, long_name = flags
            for later in tokens[index + 1:]:
                if later == f"--{long_name}":
                    return True
                # Bundled short flags (-fi), but only a clean flag token: a
                # quote fragment out of `pkill 'foo -f bar'` is not a flag.
                if re.fullmatch(rf"-[A-Za-z]*{short}[A-Za-z]*", later):
                    return True
    return False


def _note_signal_exit(command: str, result: Any) -> None:
    """Explain a signal exit that produced nothing. Additive, never rewriting.

    A shell killed by a signal comes back as a negative ``return_code`` with
    empty stdout/stderr and ``success: False`` -- field-for-field identical to a
    command that ran and printed nothing. Naming the signal is the always-true
    half and is unconditional.

    What killed it is NOT observed here, so the note does not claim it. An
    outside kill (``job_cancel``, the OOM killer, a stopped backend) looks
    exactly the same, and the self-match clause is offered as a possibility only
    for the commands that can actually self-match -- see ``_PATTERN_KILLERS``.

    Nothing is dropped or rewritten -- stdout/stderr/return_code/success are
    untouched and ``setdefault`` keeps the truncation note (mutually exclusive
    anyway: that one requires output, this one requires none).
    """
    if not isinstance(result, dict):
        return
    if result.get("finished") is False:
        return  # a still-running handoff has no exit yet
    if result.get("timed_out"):
        return  # the budget expired; -1 is that sentinel, not a signal
    if result.get("stdout") or result.get("stderr"):
        return  # there is output, so the exit is not the whole story
    name = _SIGNAL_EXITS.get(result.get("return_code"))
    if not name:
        return
    message = (
        f"Process exited on signal {-result['return_code']} ({name}) and produced "
        "no output. Nothing here observed what sent it: an outside kill looks the "
        "same (job_cancel, the OOM killer, a stopped backend)."
    )
    if _selects_processes_by_pattern(command):
        message += (
            " One possibility to rule out, not a diagnosis: this command selects "
            "processes indirectly rather than by PID, so the shell running it is "
            "a candidate -- `pkill -f` matches that shell's own argv, which "
            "contains the command text, `killall` matches its name (sh/bash), and "
            "`fuser -k` kills whoever holds the named file or port. If that is "
            "what happened, narrow the pattern or exclude this shell's own PID."
        )
    result.setdefault("note", message)


def _client_version() -> str:
    """This MCP server's own version, or "" when it cannot be read."""
    try:
        return importlib.metadata.version("zebbern-kali-mcp")
    except Exception:
        return ""


def register(mcp: FastMCP, kali_client) -> None:
    """Register command execution and system info tools."""

    @mcp.tool()
    def zebbern_exec(command: str, timeout: int = 0, cwd: str = "", background: bool = False) -> Dict[str, Any]:
        """
        Execute ANY command on the Kali server with full root access.

        This ALWAYS starts a background job first and then waits inline for it for
        ~50s. That is not a limit on the command, it is what makes a long one
        recoverable: the MCP harness abandons a tool call at roughly 60s, and
        before this the abandoned foreground command kept running with nobody
        listening and nothing on disk. Now every call is teed in full to the job
        log, so an abort costs a poll, never the output.

        Args:
            command: The command to execute (any shell command, pipes, chains, etc.)
            timeout: Backstop seconds after which the JOB is terminated. It
                bounds the job, not this call. The default 0 is a sentinel
                meaning "omit it": with no timeout on the wire the api/exec
                background branch resolves the backstop from the command's
                TOOL_TIMEOUTS tier (e.g. hydra 86400, sqlmap 28800, nmap
                14400), so a `hydra ...` run here gets hydra's own tier
                automatically instead of a flat one-hour cap. Pass an explicit
                value only to SHORTEN that tier-derived budget; it is still
                the job's backstop, never a limit on this call.
            cwd: Optional working directory for the command. This is a per-process
                cwd (Popen(cwd=...)), so it affects this command only. Left empty
                the command inherits the backend's cwd, which is /root -- note
                that Python there puts /root on sys.path and a stray /root/*.py
                can shadow a stdlib module.
            background: If True, skip the inline wait and return the job_id
                immediately. Use it for anything you will drive yourself with
                send_input / read_output, and for a run you do not want to wait on
                at all.

        Returns:
            Finished inside the wait: {success, finished: true, status, job_id,
            stdout, stderr, events, return_code, timed_out, partial_results,
            output_truncated, output_path}. Still running: {success: true,
            finished: false, status: "running", job_id, partial_output,
            output_path} -- drive it with job_status / job_output / job_cancel.
            Check `finished` and `timed_out`, never `success`. A `note` is added
            when a signal killed the command and it printed nothing: it names the
            signal, which is observed, and does not claim what sent it.

        Composing raw scanner commands -- a capability cheat-sheet
        ----------------------------------------------------------
        zebbern_exec is where a scanner is driven by hand when no typed
        wrapper stands between you and the binary, so the defaults a wrapper
        used to supply are now yours to pass. The footguns that bite hardest,
        each one a command that looks like it ran and did nothing useful:

        - sqlmap: ALWAYS pass `--batch`, or it stops at an interactive prompt
          with nobody to answer it; the job then runs until killed and, past
          the ~60s harness abort, orphans with the prompt still unanswered.
          Add `--disable-coloring` so the log is clean. Tier: 28800s.
        - nmap: host discovery is NOT skipped for you. Pass `-Pn` yourself
          against a host that blocks ping, or the scan calls it down and
          scans nothing; choose timing (`-T4`) and `--script` explicitly too.
          Tier: 14400s.
        - hydra: there is no implicit `-l admin` / `-P rockyou.txt`. Name the
          login (`-l` / `-L`), the wordlist (`-P` / `-p`) and the service
          yourself, or the run does nothing. Tier: 86400s.
        - msfconsole: drive it non-interactively with `-q -x '<resource
          commands>; exit'`, never bare, or it waits at its own prompt until
          the budget expires.
        - masscan: set `--rate` explicitly -- masscan's own default is 100,
          not the 1000 the wrapper used, so an unset rate is ~10x slower than
          you expect. `--wait 0` exits promptly. Tier: 7200s.
        - nikto: `nikto -h <url>`. Bound it with `-maxtime <N>s`; it has no
          self-limit and will run for hours. Tier: 7200s.
        - gobuster: `gobuster <dir|dns|fuzz|vhost> -u <url> -w <wordlist>
          --no-color`. There is no default wordlist -- the usual one is
          /usr/share/wordlists/dirb/common.txt. Tier: 7200s.
        - wpscan: add `--no-banner --random-user-agent --disable-tls-checks`;
          without them it banners, fingerprints as wpscan and fails on a lab
          cert. `--api-token` and `-e <enum>` as needed. Tier: 14400s.
        - john: no implicit wordlist -- without `--wordlist=` it falls back to
          single/incremental mode and looks like it is working. Cracking is
          only half of it: `john --show <hashfile>` is what prints the
          credentials. Tier: 86400s.
        - enum4linux: pass `-a` yourself; it is the full-enumeration flag and
          without it the run is nearly silent. Tier: 3600s.
        - sslscan: `sslscan --no-colour <host:port>`; append the port only for
          non-443.
        - ssh-audit: `ssh-audit -j <host>` (`-p` for non-22). `-j` emits JSON
          on stdout and you parse it. Collapsing this one is an upgrade, not a
          trade: its typed route ran a bare subprocess with no job, no disk tee
          and a 40s cap that ignored its own 1800s tier.
        - fierce: `fierce --domain <d> --dns-servers <server>`. It queries
          PUBLIC DNS by default -- scope it deliberately.
        - subzy: `subzy run --target <url>`, or `--targets <file>` for a list.
          It reaches every target over the network.
        - httpx: `httpx -silent -u <url>` (`-l <file>` for a list); without
          `-silent` the banner drowns the results.
        - ffuf: `ffuf -u <url>/FUZZ -w <wordlist> -mc <codes> -rate <n> -json
          -s -timeout 10`. `-json -s` gives one ndjson hit per line; pipe to
          `wc -l` for a count. Tier: 7200s.
        - nuclei: `nuclei -u <url> -jsonl -rate-limit 150 -timeout 10
          -retries 1` (`-t`/`-tags` to scope). Findings appear only after the
          banner and often minutes in; `jq 'group_by(.info.severity)'` for a
          rollup. Tier: 7200s.

        A backgrounded command inherits its binary's TOOL_TIMEOUTS tier
        automatically now (see `timeout` above), so you restate a tier only
        when you mean to shorten it.

        When the wrapper-collapse pilot is active, a suppressed scanner
        wrapper is composed here by hand instead, and this sheet is the
        source of truth for its safe defaults -- extend it as the pilot's
        env set widens.
        """
        data: Dict[str, Any] = {"command": command}
        if cwd:
            data["cwd"] = cwd
        if timeout != 0:
            data["timeout"] = timeout
        # heavy=False: this must not become a heavy_tool_post caller holding one of
        # five semaphore slots. run_promotable sets background in the body itself
        # and takes heavy/background explicitly, so zebbern_exec is deliberately
        # absent from PROMOTED_TOOLS (that map is the fourteen tools_* wrappers).
        result = run_promotable(
            kali_client, "api/exec", data,
            heavy=False, background=background,
        )
        _note_signal_exit(command, result)
        return result

    @mcp.tool()
    def exec_stream(command: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Run a command and return its COMPLETE output once it finishes, with each
        line tagged by source ([stdout]/[stderr]) in arrival order. Despite the
        SSE transport this does NOT stream to you incrementally and does NOT
        evade the ~60s tool-call abort -- you get one response at the end, same
        as a synchronous call. Effective ceiling is ~50s regardless of `timeout`.

        Use it only for SHORT commands where interleaved-by-arrival output or
        truncation detection (the `incomplete` flag) matters. For anything that
        may run longer, use the tools_* wrappers (they auto-promote to a
        background job) or zebbern_exec(background=True) with job_status /
        job_output / job_cancel -- exec_stream registers no job and cannot be
        cancelled.

        Args:
            command: The command to execute
            timeout: Backstop seconds for a hung process (default: 3600)

        Returns:
            {success, output, return_code, timed_out, streamed}, plus
            incomplete/error when the stream ends without a result frame.
        """
        response = None
        try:
            response = kali_client.request(
                "POST",
                "api/command",
                json={"command": command, "streaming": True, "timeout": timeout},
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=(10, timeout),
            )
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" not in content_type:
                return response.json()

            # requests derives the decode charset from the Content-Type, and a
            # text/* type carrying no charset yields ISO-8859-1. The backend
            # escapes non-ASCII today, so this only bites if that ever changes.
            response.encoding = "utf-8"

            output_lines: list[str] = []
            result_data: Dict[str, Any] = {}
            saw_result = False

            # One JSON object per `data:` line is safe, not luck. This tool only
            # ever reads api/command, served by stream_command_execution in
            # zebbern-kali/core/command_executor.py, which serializes each payload
            # with default json.dumps -- no indent=, so embedded newlines are
            # escaped and a frame is always a single physical line. requests
            # reassembles frames split across chunk boundaries before yielding.
            # An emitter that added indent= would break this; a test in
            # tests/test_command_streaming.py guards against it.
            for line in response.iter_lines(decode_unicode=True):
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        if not isinstance(event_data, dict):
                            # `data: null` and friends parse cleanly but are not
                            # frames; .get() on them escapes this handler, which
                            # only catches JSONDecodeError.
                            continue
                        event_type = event_data.get("type", "")
                        if event_type == "output":
                            output_lines.append(
                                f"[{event_data.get('source', 'out')}] {event_data.get('line', '')}"
                            )
                        elif event_type == "result":
                            result_data = event_data
                            saw_result = True
                        elif event_type == "error":
                            return {"success": False, "error": event_data.get("message", "Unknown error")}
                        elif event_type == "complete":
                            break
                    except json.JSONDecodeError:
                        continue

            if not saw_result:
                # No result frame means the stream was cut short: a killed
                # worker, a proxy cutoff, a close on a chunk boundary. Defaulting
                # to success reported a truncated command as a clean run, which
                # is the failure mode streaming long scans invites.
                return {
                    "success": False,
                    "incomplete": True,
                    "output": "\n".join(output_lines),
                    "return_code": None,
                    "timed_out": False,
                    "streamed": True,
                    "error": (
                        "stream ended without a result event; the command may "
                        "have been truncated or killed"
                    ),
                }

            return {
                "success": result_data.get("success", True),
                "output": "\n".join(output_lines),
                "return_code": result_data.get("return_code", 0),
                "timed_out": result_data.get("timed_out", False),
                "streamed": True,
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Streaming request failed: {str(e)}")
            return {"error": f"Streaming request failed: {str(e)}", "success": False}
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if close:
                    close()

    @mcp.tool()
    def health() -> Dict[str, Any]:
        """
        Check the Kali API server, and this client's own version against it.

        `version` is the BACKEND's. `client_version` is this MCP server's. They
        ship on separate tracks and drift silently: `uvx zebbern-kali-mcp` with
        no version reuses whatever environment it cached, so restarting the MCP
        does not pick up a newer wheel. A client can sit several releases behind
        a freshly pulled backend while this call still looks perfectly healthy,
        because the version it reported was never the client's.

        Check `version_match` before concluding a missing tool or an ignored
        argument is a bug -- it usually means the client is stale.

        Returns:
            Server health, plus client_version, version_match, and a note when
            they disagree.
        """
        reply = kali_client.check_health()
        if not isinstance(reply, dict):
            return reply
        client_version = _client_version()
        reply["client_version"] = client_version
        backend_version = reply.get("version")
        if client_version and backend_version:
            reply["version_match"] = client_version == backend_version
            if client_version != backend_version:
                reply["version_note"] = (
                    f"This MCP client is {client_version} but the backend is "
                    f"{backend_version}. Tools added after {client_version} are "
                    "missing and newer arguments are ignored. Reinstall the "
                    "client (uvx --refresh, or pin the version in the MCP "
                    "config) and restart it."
                )
        return reply

    @mcp.tool()
    def job_list(status: str = "", limit: int = 20) -> Dict[str, Any]:
        """List background jobs the Kali server still tracks, newest first.

        Use this to get back to work you already started: job_status and
        job_output both need a job_id you are still holding, so after a context
        compaction -- or whenever you are simply unsure whether a scan you
        launched is still running -- this is the only way to find one again.
        Also the way to check what is running before starting something heavy.

        Args:
            status: Optional filter, e.g. "running" to see only live work.
                Empty means every state.
            limit: Newest N to return (default 20). The server keeps up to 256,
                and a busy session fills them: an unbounded listing was 147 jobs
                and 62KB, which is a poor trade for a call whose whole job is to
                find one id. Nothing is hidden -- `count` is always the true
                total and `returned` says how many came back.

        Returns each job's id, status, pid, return_code and timestamps, without
        its output; read that with job_output once you have the id. Jobs live in
        server memory only, so a backend restart empties this list.
        """
        reply = kali_client.safe_get("api/jobs")
        if not isinstance(reply, dict) or not isinstance(reply.get("jobs"), list):
            return reply
        jobs = reply["jobs"]
        if status:
            jobs = [job for job in jobs if job.get("status") == status]
        matched = len(jobs)
        if limit and limit > 0 and matched > limit:
            reply["note"] = (
                f"{matched} jobs matched; showing the newest {limit}. Raise "
                "limit, or filter with status, to see the rest."
            )
            jobs = jobs[:limit]
        reply["jobs"] = jobs
        reply["returned"] = len(jobs)
        if status:
            reply["matched"] = matched
            reply["filtered_by_status"] = status
        return reply

    @mcp.tool()
    def job_status(job_id: str) -> Dict[str, Any]:
        """Return state and exit metadata for a background command job.

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
        """
        return kali_client.safe_get(f"api/jobs/{job_id}")

    @mcp.tool()
    def job_output(job_id: str, timeout: int = 0, lines: int = 100) -> Dict[str, Any]:
        """Poll recent bounded stdout and stderr from a background job.

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
            timeout: Seconds to block waiting for new output (default: 0).
                Bounded by the backend's JOB_OUTPUT_MAX_WAIT (default 30s),
                which exists because the MCP harness abandons a tool call at
                roughly 60s. A larger value is clamped, not rejected, and the
                reply states what it actually did: `wait_timeout` is the wait
                used, `wait_capped` says it was reduced, `max_output_wait` is
                the bound. A backend older than that change answers 400
                "timeout cannot exceed N seconds" instead -- the clamp ships in
                the Docker image, this docstring on the wheel, and the two do
                not land together.
            lines: Maximum recent lines to return (default: 100). The window is
                bounded, but nothing is lost: every byte is also teed to the
                job's log, whose path comes back as `output_path`.
        """
        return kali_client.safe_get(
            f"api/jobs/{job_id}/output",
            params={"timeout": timeout, "lines": lines},
        )

    @mcp.tool()
    def job_cancel(job_id: str) -> Dict[str, Any]:
        """Cancel a running background job and its child process group.

        Idempotent: cancelling a job that already finished is not an error. It
        returns success with `canceled: false` and `already_terminal: true`,
        and the job's own `status` tells you how it ended. Check `canceled`,
        not `success` -- `canceled: true` means this call issued the kill, so
        poll job_status for the terminal state rather than assuming it is
        already reaped. A backend older than that change answers 409 "Job is
        already succeeded" for the same call (image track; see job_output).

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
        """
        return kali_client.safe_post(f"api/jobs/{job_id}/cancel", {})

    @mcp.tool()
    def system_network_info() -> Dict[str, Any]:
        """
        Get comprehensive network information for the Kali Linux system.

        Returns:
            Network information including interfaces, IP addresses, routing table, etc.
        """
        return kali_client.safe_get("api/system/network-info")

    @mcp.tool()
    def send_input(session_id: str, input_text: str, session_type: str = "auto") -> Dict[str, Any]:
        """
        Send text input to a running background command job.

        Use this together with read_output() to have a full interactive conversation
        with a long-running process:
          1. Start a job with zebbern_exec(..., background=True)
          2. send_input(session_id, "some command\\n")
          3. read_output(session_id) to collect the response

        Args:
            session_id: The job identifier returned by zebbern_exec.
            input_text: The text to send to the session's stdin. Include a trailing
                        newline (\\n) if the target process expects one.
            session_type: Compatibility hint retained for existing clients.

        Returns:
            dict with at minimum:
              - success (bool): whether the input was accepted
              - session_id (str): echo of the session targeted
              - error (str, optional): present only on failure
        """
        return kali_client.safe_post(
            f"api/jobs/{session_id}/input",
            {"input": input_text, "type": session_type},
        )

    @mcp.tool()
    def read_output(session_id: str, timeout: int = 5, lines: int = 100) -> Dict[str, Any]:
        """
        Read or poll bounded output from a background command job.

        Typical workflow:
          1. send_input(session_id, "whoami\\n")
          2. read_output(session_id, timeout=5)  ->  returns the command's output

        The backend will wait up to `timeout` seconds for new output before
        returning whatever is available (which may be empty if the process has
        not produced anything yet).

        Args:
            session_id: The session identifier to read from.
            timeout: Maximum seconds the backend should wait for new output
                     before returning (default: 5). Bounded by the backend's
                     JOB_OUTPUT_MAX_WAIT (default 30s), which keeps one poll
                     under the ~60s MCP tool-call abort. A larger value is
                     clamped rather than rejected, and the reply reports
                     `wait_timeout` (what it waited for), `wait_capped` and
                     `max_output_wait`; an older backend answers 400 instead.
                     Waiting longer is not how you follow a slow scan -- poll
                     repeatedly, or read the full log at `output_path`.
            lines: Maximum number of output lines to return (default: 100).
                   Older lines are trimmed first when the buffer exceeds this.

        Returns:
            dict with at minimum:
              - success (bool): whether the read succeeded
              - output (str): the collected output text
              - session_id (str): echo of the session targeted
              - lines_returned (int): number of lines in output
              - error (str, optional): present only on failure
        """
        return kali_client.safe_get(
            f"api/jobs/{session_id}/output",
            params={"timeout": timeout, "lines": lines},
        )
