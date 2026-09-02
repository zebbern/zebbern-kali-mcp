"""Guards on the tool timeout table.

These numbers are backstops for a hung process, not budgets for a slow one. A
5-minute default silently truncated sqlmap, hydra and john mid-run and reported
the partial output as a clean success, so the floor and the long-running tools
are asserted here rather than left to a future edit's judgement.
"""

import inspect
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.tool_config import (  # noqa: E402
    TOOL_TIMEOUTS,
    get_command_timeout,
    get_tool_timeout,
    resolve_tool_names,
)

BACKSTOP_FLOOR = 3600


def test_the_default_is_a_backstop_not_a_five_minute_cap():
    assert TOOL_TIMEOUTS["default"] >= BACKSTOP_FLOOR


@pytest.mark.parametrize("tool", ["hydra", "john", "sqlmap"])
def test_tools_that_run_for_hours_outrank_the_default(tool):
    """These three used to be absent from the table entirely, so a password
    crack or a blind-SQLi enumeration was killed at five minutes."""
    assert tool in TOOL_TIMEOUTS
    assert TOOL_TIMEOUTS[tool] > TOOL_TIMEOUTS["default"]


@pytest.mark.parametrize("tool", ["nmap", "nuclei", "amass", "wpscan", "msfconsole"])
def test_full_surface_scanners_get_at_least_the_backstop(tool):
    assert TOOL_TIMEOUTS[tool] >= BACKSTOP_FLOOR


def test_no_entry_falls_below_the_shortest_declared_tier():
    """Nothing may sneak back under five minutes."""
    assert min(TOOL_TIMEOUTS.values()) >= 300


def test_an_unknown_tool_gets_the_backstop_rather_than_a_short_default():
    assert get_tool_timeout("some-tool-nobody-listed") == TOOL_TIMEOUTS["default"]


@pytest.mark.parametrize(
    "command",
    [
        "nmap -sV 10.0.0.1",
        "sudo nmap -sV 10.0.0.1",
        "/usr/bin/nmap -p- 10.0.0.1",
        "timeout 4h nmap -p- 10.0.0.1",
        "proxychains nmap -p- 10.0.0.1",
        "env FOO=bar nmap 10.0.0.1",
        "FOO=bar nmap 10.0.0.1",
        "nice -n 5 nmap 10.0.0.1",
        "nmap -oX - 10.0.0.1 | grep open",
    ],
)
def test_wrappers_and_absolute_paths_do_not_drop_a_tool_to_the_default(command):
    """The lookup keyed on the raw first shell token, so every one of these
    missed the nmap entry and silently collapsed to the default."""
    assert get_command_timeout(command) == TOOL_TIMEOUTS["nmap"]


def test_a_pipeline_inherits_its_longest_running_member():
    """`echo x | waybackurls` ran as `echo`; the tool doing the work is second."""
    assert resolve_tool_names("echo example.com | /home/kali/go/bin/waybackurls") == [
        "echo",
        "waybackurls",
    ]
    assert get_command_timeout("echo example.com | /home/kali/go/bin/waybackurls") == (
        TOOL_TIMEOUTS["waybackurls"]
    )


def test_a_pipeline_takes_its_longest_member_not_its_first():
    """The test above cannot tell max() from first-wins: `echo` is not in the
    table, so max(), min() and known[0] all return waybackurls' entry and
    replacing max with known[0] in tool_config.py leaves the suite green.

    Both members here are in the table and the longest one is second, so the
    three rules give three different answers. The regression it guards is real:
    under a first-wins rule `assetfinder example.com | httpx -silent` is killed
    at assetfinder's 900s and its partial output returned as a clean success.
    """
    command = "assetfinder example.com | httpx -silent"

    assert resolve_tool_names(command) == ["assetfinder", "httpx"]
    # If a re-tiering ever makes these equal, this fixture stops distinguishing
    # the rules and the test above is all that is left -- fail loudly instead.
    assert TOOL_TIMEOUTS["assetfinder"] < TOOL_TIMEOUTS["httpx"]
    assert get_command_timeout(command) == TOOL_TIMEOUTS["httpx"]


def test_a_command_with_no_known_tool_gets_the_backstop():
    assert get_command_timeout("sh -c 'sleep 100'") == TOOL_TIMEOUTS["default"]
    assert get_command_timeout("") == TOOL_TIMEOUTS["default"]


def test_command_timeout_default_tracks_the_table_backstop():
    """core.config.COMMAND_TIMEOUT is the CommandExecutor fallback; letting it
    drift below the table reintroduces a short cap by the back door."""
    from core.config import COMMAND_TIMEOUT

    assert COMMAND_TIMEOUT >= TOOL_TIMEOUTS["default"]


KALI_TOOLS_SRC = (BACKEND_ROOT / "tools" / "kali_tools.py").read_text(encoding="utf-8")
MSF_SRC = (BACKEND_ROOT / "core" / "metasploit_manager.py").read_text(encoding="utf-8")
MSF_ROUTE_SRC = (
    BACKEND_ROOT / "api" / "blueprints" / "metasploit.py"
).read_text(encoding="utf-8")


def test_no_tool_wrapper_shadows_the_table_with_an_inline_literal():
    """Every run_* wrapper used to carry its own timeout=N, so raising the table
    changed nothing for the tool the operator actually called.

    Matched on ``"execute_command("`` and so covered only 16 of the 24 call
    sites: the character after ``execute_command`` in ``execute_command_argv(``
    is ``_``, not ``(``, so all 8 argv wrappers were invisible to the guard that
    exists to protect them. Match the bare name, which covers both forms.
    """
    offenders = [
        line.strip()
        for line in KALI_TOOLS_SRC.splitlines()
        if "execute_command" in line and "timeout=" in line
    ]
    assert offenders == []


def test_the_inline_literal_guard_covers_both_call_forms():
    """A guard that cannot see a call site is worse than no guard. Assert the
    argv wrappers actually exist, so this does not quietly pass the day someone
    renames or deletes them and leaves the pattern matching nothing."""
    assert KALI_TOOLS_SRC.count("execute_command_argv(") >= 8
    assert KALI_TOOLS_SRC.count("execute_command(") >= 8


# metasploit_manager imports pty, so it cannot be imported on Windows; assert on
# the source text instead, the same way the rest of the suite does.
def test_metasploit_execute_reports_truncation():
    """Both loop exits fell through to one unconditional success, so a module
    that outran its budget was indistinguishable from one that finished."""
    assert '"timed_out": timed_out,' in MSF_SRC
    assert "timed_out = False" in MSF_SRC
    assert "timed_out = True" in MSF_SRC


def test_metasploit_keeps_success_true_on_a_timeout():
    """Partial results are the point of an offensive tool; this matches
    CommandExecutor, which also pairs success=True with timed_out=True."""
    assert '"success": False,\n                "timed_out": timed_out' not in MSF_SRC
    assert '"success": True,\n                "output": output,' in MSF_SRC


class _RecordingMCP:
    """Capture the raw functions an mcp_tools module registers."""

    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.tools[name or function.__name__] = function
            return function

        return decorator


class _RecordingClient:
    """Record the request body a tool builds instead of sending it."""

    def __init__(self):
        self.calls = []

    def safe_post(self, endpoint, data):
        self.calls.append((endpoint, data))
        return {"success": True}


def _msf_session_execute():
    """The msf_session_execute function plus the client it posts through."""
    from mcp_tools import metasploit as msf_tools

    recording, client = _RecordingMCP(), _RecordingClient()
    msf_tools.register(recording, client)
    return recording.tools["msf_session_execute"], client


def test_every_layer_of_the_metasploit_timeout_chain_agrees():
    """Three separate 300s defaults sat in this chain and the outermost won, so
    raising the inner ones alone was a no-op for every real request."""
    assert "timeout: float = 300" not in MSF_SRC
    assert 'params.get("timeout", 300)' not in MSF_ROUTE_SRC
    assert MSF_SRC.count("timeout: float = 14400") == 2
    assert 'params.get("timeout", 14400)' in MSF_ROUTE_SRC

    # The outermost layer, and the decisive one: msf_session_execute always puts
    # `timeout` in the body, so the route's params.get("timeout", 14400) above
    # never fires for an MCP caller. Reverting *this* default to 300 re-caps
    # every MSF call at five minutes while the two assertions above stay green.
    # It is also the only one of the three on the PyPI/wheel track, so it can
    # regress in a wheel-only change that never touches the image.
    #
    # Asserted on the imported function's real default rather than a source
    # substring: mcp_tools is import-safe on Windows, and a reformat must not be
    # able to fool the guard.
    execute_tool, _client = _msf_session_execute()
    declared = inspect.signature(execute_tool).parameters["timeout"].default
    assert declared == 14400


def test_the_mcp_layer_always_sends_a_timeout_so_the_route_default_never_fires():
    """Why the layer above is decisive rather than merely one of three. If this
    ever stopped shipping `timeout` in the body, the route's default would take
    over and the two would have to be kept in step by hand instead."""
    execute_tool, client = _msf_session_execute()

    execute_tool("abc123", "run")

    endpoint, body = client.calls[0]
    assert endpoint == "api/msf/session/execute"
    assert body["timeout"] == 14400


def test_the_client_read_timeout_has_one_definition():
    """mcp_server.py and _client.py used to carry separate defaults for the same
    concept, which is exactly the drift CLAUDE.md warns about for VERSION."""
    import mcp_server
    from mcp_tools._client import DEFAULT_REQUEST_TIMEOUT, KaliToolsClient

    assert mcp_server.DEFAULT_REQUEST_TIMEOUT is DEFAULT_REQUEST_TIMEOUT
    assert KaliToolsClient("http://127.0.0.1:5000").timeout == DEFAULT_REQUEST_TIMEOUT


def test_the_client_read_timeout_outlives_the_longest_tool_budget():
    """The client must outlive the backend, or a timed-out scan's partial output
    is destroyed: requests raises ReadTimeout before the backend can serialize
    its reply, so the caller sees only "Request failed: ReadTimeout" and the
    subprocess keeps running orphaned.

    This compared against one arbitrary entry (nmap) with >=, which passed while
    eight entries -- hydra and john at 86400 among them -- sat at or above the
    client cap. Compare against the whole table, strictly, so the two release
    tracks cannot drift back past each other.
    """
    from mcp_tools._client import DEFAULT_REQUEST_TIMEOUT

    assert DEFAULT_REQUEST_TIMEOUT > max(TOOL_TIMEOUTS.values())


def test_the_password_spray_deadline_stays_under_the_client(tmp_path, monkeypatch):
    """The one backend deadline that is a FORMULA rather than a TOOL_TIMEOUTS
    entry, so the headroom guard above cannot see it.

    `max(300, len(users) * 5)` unclamped turns a SecLists username file (~8.3M
    lines) into ~41,500,000s. The client gives up at 90000s, `requests` raises
    ReadTimeout, safe_post returns {"error": "... ReadTimeout"} and the partial
    spray -- including every credential already parsed out of it -- is
    destroyed. Clamping discards nothing: the TimeoutExpired handler returns the
    partial output and its hits, which is strictly more than that.
    """
    from core.ad_tools import ADTools, SPRAY_TIMEOUT_CEILING, SPRAY_TIMEOUT_FLOOR
    from mcp_tools._client import DEFAULT_REQUEST_TIMEOUT

    assert SPRAY_TIMEOUT_CEILING < DEFAULT_REQUEST_TIMEOUT

    # 20000 users * 5 == 100000s, comfortably past the ceiling and past the
    # client, without writing an 8M-line file to disk.
    users = 20000
    assert users * 5 > SPRAY_TIMEOUT_CEILING
    userlist = tmp_path / "users.txt"
    userlist.write_text(
        "".join(f"user{index}\n" for index in range(users)), encoding="utf-8"
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    import shutil as _shutil

    tools = object.__new__(ADTools)
    tools.available_tools = {"netexec": True}
    monkeypatch.setattr(
        _shutil, "which", lambda name: "/usr/bin/netexec" if name == "netexec" else None
    )
    monkeypatch.setattr(subprocess, "run", fake_run)

    tools.password_spray(
        target="10.0.0.10", userlist=str(userlist), password="Spring2026!", delay=0
    )

    assert captured["timeout"] == SPRAY_TIMEOUT_CEILING
    assert captured["timeout"] < DEFAULT_REQUEST_TIMEOUT
    assert SPRAY_TIMEOUT_FLOOR <= captured["timeout"]


def test_the_connect_timeout_stays_short():
    """An unreachable server must fail fast no matter how long the read timeout
    gets; these are different failures."""
    from mcp_tools._client import DEFAULT_CONNECT_TIMEOUT, KaliToolsClient

    assert DEFAULT_CONNECT_TIMEOUT == 10
    assert KaliToolsClient("http://127.0.0.1:5000")._connect_timeout == 10


# ---------------------------------------------------------------------------
# Semantic guards on MetasploitSession.execute
#
# Everything above about the MSF timeout is a source-substring check, and those
# would pass just as happily with timed_out fully inverted -- a reviewer already
# misread the flag as inverted for exactly that reason. These drive the real
# wait loop with a stubbed process and assert on what it returns.
# ---------------------------------------------------------------------------

# metasploit_manager imports pty for its console PTY. Stub only that
# import-time boundary on Windows, the way test_command_metadata_verbatim.py
# already does -- the wait loop these tests drive never opens a PTY. Without it
# the block runs or skips depending on whether an earlier test module happened
# to install the same stub first, which is not a property a guard should have.
if os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

try:
    from core import metasploit_manager as msf_module
except ImportError:  # pragma: no cover - no pty and no stub
    msf_module = None

requires_msf_module = pytest.mark.skipif(
    msf_module is None,
    reason="core.metasploit_manager imports pty, which does not exist on Windows",
)


class _StubProcess:
    """Returns each queued poll() value once, then repeats the last forever."""

    def __init__(self, *poll_results):
        self._queued = list(poll_results)
        self._last = poll_results[-1]

    def poll(self):
        if self._queued:
            return self._queued.pop(0)
        return self._last


class _ModuleShim:
    """Replace one attribute of a stdlib module for the module under test only,
    so nothing else running in this process sees the patch."""

    def __init__(self, real, **overrides):
        self._real = real
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._real, name)


def _drive_execute(monkeypatch, *, reply, poll_results=(None,), timeout=2.0):
    """Run the real wait loop against a stubbed console.

    ``os.write`` stands in for the pty send and delivers ``reply`` into the
    buffer the way the reader thread would, and ``time.sleep`` is dropped so the
    loop's 0.5s pacing costs microseconds rather than seconds.
    """
    session = msf_module.MetasploitSession("test-session")
    session.process = _StubProcess(*poll_results)
    session.master_fd = -1  # never used: the shimmed write ignores the fd

    def fake_write(_fd, data):
        # Through _append_output, exactly as the reader thread does it, so the
        # running length and the bounded prompt tail the wait loop reads are
        # maintained by the code under test rather than by the test.
        with session.output_lock:
            session._append_output(reply)
        return len(data)

    monkeypatch.setattr(msf_module, "os", _ModuleShim(os, write=fake_write))
    monkeypatch.setattr(
        msf_module, "time", _ModuleShim(time, sleep=lambda _seconds: None)
    )
    return session.execute("version", timeout=timeout, read_delay=0)


@requires_msf_module
@pytest.mark.parametrize(
    "prompt",
    [
        "msf6 > ",
        "msf6 exploit(multi/handler) > ",
        "meterpreter > ",
        "root@target:/# ",
    ],
)
def test_msf_execute_clears_timed_out_when_it_reaches_a_prompt(monkeypatch, prompt):
    """The happy path. timed_out starts True and only the prompt exit clears it,
    so this is the assertion the source-substring guards cannot make.

    Driven through execute() rather than through _ends_on_prompt directly: a
    helper-only test passes even when the wait loop never calls the helper,
    which is exactly the shape of guard this file has already got wrong twice.
    The meterpreter and shell prompts are the ones the old "msf" + ">" substring
    search missed, and they are what you wait on after an exploit lands.
    """
    result = _drive_execute(
        monkeypatch,
        reply="[*] Meterpreter session 1 opened\n" + prompt,
    )
    assert result["timed_out"] is False
    assert result["console_exited"] is False
    assert result["success"] is True
    assert result["partial_results"] is False
    assert result["execution_time"] < 1.0
    assert "session 1 opened" in result["output"]


@requires_msf_module
def test_msf_execute_reports_timed_out_with_the_partial_output_intact(monkeypatch):
    """A module that outruns its budget still returns success plus whatever it
    printed; the caller distinguishes the two cases on timed_out alone."""
    result = _drive_execute(
        monkeypatch,
        reply="[*] Started reverse TCP handler on 10.0.0.1:4444\n",
        timeout=0.02,
    )
    assert result["timed_out"] is True
    assert result["console_exited"] is False
    assert result["partial_results"] is True
    assert result["success"] is True
    assert "reverse TCP handler" in result["output"]


@requires_msf_module
def test_msf_execute_stops_waiting_once_msfconsole_dies(monkeypatch):
    """A dead console produces no further output, so waiting out the rest of the
    budget is pure hang -- 4 hours of it at the current default.

    execution_time is asserted as well as the flag: without the poll() exit the
    loop still ends, it just ends by burning the whole budget, so the flag alone
    would let a regression read as a slow pass. The budget is small for the same
    reason -- a guard that hangs for the length of a real budget before going
    red is not one anybody will run twice.
    """
    result = _drive_execute(
        monkeypatch,
        reply="[-] Handler failed to bind\n",
        poll_results=(None, 1),
        timeout=2.0,
    )
    assert result["timed_out"] is False
    assert result["success"] is True
    assert "failed to bind" in result["output"]
    assert result["execution_time"] < 1.0
    # The death is reported as its own fact, and it makes the output partial --
    # the console never got to finish printing.
    assert result["console_exited"] is True
    assert result["partial_results"] is True


@requires_msf_module
def test_a_dead_console_is_distinguishable_from_a_clean_finish(monkeypatch):
    """The poll() exit sets timed_out=False, so without a separate field a
    console that was OOM-killed mid-exploit returns a dict field-for-field
    identical to one that reached a prompt. CLAUDE.md tells callers to check
    timed_out and never success to know a command finished -- under that rule,
    identical dicts mean a crash reads as a completed run.

    Neither `success` nor `timed_out` may move to carry this: success=True keeps
    the partial output worth reading, and timed_out has to keep meaning "the
    budget expired", which is a different fact from "the console died".
    """
    finished = _drive_execute(monkeypatch, reply="msf6 > ")
    died = _drive_execute(
        monkeypatch, reply="[-] Handler failed to bind\n", poll_results=(None, 1)
    )

    assert finished["timed_out"] is died["timed_out"] is False
    assert finished["success"] is died["success"] is True
    assert finished["console_exited"] is False
    assert died["console_exited"] is True
    assert finished["partial_results"] is False
    assert died["partial_results"] is True

    comparable = ("success", "timed_out", "console_exited", "partial_results")
    assert {key: finished[key] for key in comparable} != {
        key: died[key] for key in comparable
    }


@requires_msf_module
def test_a_dead_console_stops_advertising_itself_as_ready(monkeypatch):
    """is_ready is what msf_session_list reports. A console that exited cannot
    serve another command, so leaving it True is a claim the object cannot
    back."""
    session = msf_module.MetasploitSession("dead-session")
    session.process = _StubProcess(None, 1)
    session.master_fd = -1
    session.is_ready = True

    monkeypatch.setattr(
        msf_module, "os", _ModuleShim(os, write=lambda _fd, data: len(data))
    )
    monkeypatch.setattr(
        msf_module, "time", _ModuleShim(time, sleep=lambda _seconds: None)
    )
    result = session.execute("run", timeout=2.0, read_delay=0)

    assert result["console_exited"] is True
    assert session.is_ready is False


@requires_msf_module
def test_the_console_exited_flag_survives_the_route_and_the_mcp_wrapper():
    """Nothing between the session and the MCP caller may reshape the dict, or
    the new field never reaches anyone. The route does `jsonify(result)` and
    safe_post does `response.json()`; assert that rather than trust it."""
    assert "jsonify(result)" in MSF_ROUTE_SRC
    assert "console_exited" not in MSF_ROUTE_SRC  # nothing to thread: not rebuilt

    from mcp_tools import metasploit as msf_tools

    recording, client = _RecordingMCP(), _RecordingClient()
    client.safe_post = lambda endpoint, data: {
        "success": True,
        "output": "",
        "timed_out": False,
        "console_exited": True,
    }
    msf_tools.register(recording, client)

    returned = recording.tools["msf_session_execute"]("abc123", "run")
    assert returned["console_exited"] is True


@requires_msf_module
@pytest.mark.parametrize(
    "tail",
    [
        "msf > ",
        "msf6 > ",
        "msf6 exploit(multi/handler) > ",
        "meterpreter > ",
        "shell> ",
        "root@target:/#",
        "www-data@box:/var/www$ ",
        "\x1b[4mmsf6\x1b[0m exploit(multi/handler) > ",
    ],
)
def test_every_post_exploitation_prompt_ends_the_wait(tail):
    """The old test was `"msf" in last_200 and ">" in last_200`, which misses a
    meterpreter or shell prompt -- the prompt you get after an exploit lands,
    and so the most common thing to wait on."""
    assert msf_module._ends_on_prompt("[*] Meterpreter session 1 opened\n" + tail)


@requires_msf_module
@pytest.mark.parametrize(
    "buffer",
    [
        "",
        "\n",
        "[*] Started reverse TCP handler on 10.0.0.1:4444\n",
        "Framework: 6.3.55-dev\n",
        "msf6 > version\n[*] still working",
    ],
)
def test_mid_command_output_is_not_mistaken_for_a_prompt(buffer):
    """Including a buffer whose *earlier* lines hold a prompt: only the trailing
    line counts, or echoing the command back would end the wait immediately."""
    assert not msf_module._ends_on_prompt(buffer)


# ---------------------------------------------------------------------------
# The console buffer's accumulation shape.
#
# _read_output did `self.output_buffer += data.decode(...)` on every 4096-byte
# PTY read while holding output_lock -- the same O(n^2) accumulation removed
# from CommandExecutor, left on the path whose budget this change raised from
# 300s to 14400s. Measured on this host: 64MB of 4096-byte reads costs 131.3s
# by concatenation (8.0ms per read) against 0.004s of appends plus a single
# 0.016s join. That caps the reader at roughly half a megabyte a second, so a
# verbose module -- or `find / -ls` in a shell session -- outruns it and the
# session stalls.
# ---------------------------------------------------------------------------

# Only the reader's own body, so this cannot be satisfied by an append that
# happens to live in some other method.
_READER_SRC = MSF_SRC.split("def _read_output")[1].split("def _wait_for_prompt")[0]


def test_the_pty_reader_appends_a_chunk_rather_than_rebuilding_the_buffer():
    """Every other assertion in this file survives a revert to `+=`: the
    output_buffer setter recomputes the running length and the tail, so the
    wait loop and the returned output stay correct and only get slow. The chunk
    list is the one thing that tells the two apart.
    """
    assert "output_buffer +=" not in _READER_SRC
    assert "_append_output(" in _READER_SRC


@requires_msf_module
def test_appending_output_keeps_the_length_and_the_prompt_tail_in_step():
    session = msf_module.MetasploitSession("chunked")
    for chunk in ("first\n", "second\n", "msf6 > "):
        session._append_output(chunk)

    assert session._output_chunks == ["first\n", "second\n", "msf6 > "]
    assert session.output_buffer == "first\nsecond\nmsf6 > "
    assert session._output_len == len(session.output_buffer)
    # The tail is exactly the slice _ends_on_prompt used to take itself, so
    # feeding it the tail cannot change which buffers match.
    assert session._output_tail == session.output_buffer[
        -msf_module._PROMPT_TAIL_CHARS:
    ]


@requires_msf_module
def test_the_output_buffer_is_still_a_str_holding_every_byte():
    """output_buffer is public and was a plain str. Nothing may cap it: the
    bounded tail exists for the prompt match only, and a buffer many times
    longer than that tail must still come back whole."""
    session = msf_module.MetasploitSession("large")
    body = "A" * (msf_module._PROMPT_TAIL_CHARS * 40)
    session._append_output(body)
    session._append_output("msf6 > ")

    assert isinstance(session.output_buffer, str)
    assert session.output_buffer == body + "msf6 > "
    assert len(session.output_buffer) == len(body) + len("msf6 > ")
    assert session._output_len == len(session.output_buffer)


@requires_msf_module
def test_assigning_to_the_output_buffer_still_works():
    """`self.output_buffer = ""` is how execute() clears the buffer before each
    command, and the derived length and tail have to follow it."""
    session = msf_module.MetasploitSession("assigned")
    session._append_output("stale output\nmsf6 > ")

    session.output_buffer = ""

    assert session.output_buffer == ""
    assert session._output_len == 0
    assert session._output_tail == ""
    assert not msf_module._ends_on_prompt(session._output_tail)


@requires_msf_module
def test_execute_returns_output_far_longer_than_the_prompt_tail(monkeypatch):
    """End to end through the real wait loop: the join happens where the output
    is taken, and it takes everything, not the tail the prompt match reads."""
    body = "[*] " + "B" * (msf_module._PROMPT_TAIL_CHARS * 10) + "\n"
    result = _drive_execute(monkeypatch, reply=body + "msf6 > ")

    assert result["timed_out"] is False
    assert result["output"] == body + "msf6 > "
