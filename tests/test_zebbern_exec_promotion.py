"""zebbern_exec auto-promotes, and a signal exit says so.

Two things are asserted here, both of them things that read as a working tool
until you look at what came back.

The first is the escape. ``zebbern_exec`` used to be a plain synchronous POST to
``api/exec``, and the foreground branch of that route is the one execution path
in the repo that tees nowhere. So when the MCP harness abandoned the call at
~60s the subprocess kept running with nobody listening and no log on disk: the
output was gone, and an operator who had passed ``timeout=300`` had no way to
tell that their value never mattered. Promoting means a job exists before any
waiting happens, so the abort costs a poll.

The second is legibility. A shell killed by a signal returns a negative
``return_code``, empty stdout and ``success: False`` -- identical to a command
that ran fine and printed nothing. ``pkill -f`` matching the shell running it
is the common way to land there, and nothing said so.

Legibility is not licence to guess, though. The note's first sentence is the part
that was observed -- a signal, no output -- and is unconditional; the self-match
clause is a possibility offered only to the commands that can actually
self-match. It used to fire on any command whose text merely contained "kill", so
``kill -TERM 4567``, which names a PID and cannot self-match, was told it had
killed its own shell when something outside it (a ``job_cancel``, an OOM kill)
had done the killing.

Contract-level with the ``_RecordingMCP``/``_RecordingClient`` pattern the rest
of the suite uses: these prove the request the client builds and the note it
attaches, not that a command runs.
"""

import pytest

from mcp_tools.command_exec import (
    _SIGNAL_EXITS,
    _note_signal_exit,
    _selects_processes_by_pattern,
)


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
    """Record the request body a wrapper builds instead of sending it."""

    def __init__(self, reply=None):
        self.calls = []
        self.posters = []
        self.reply = reply if reply is not None else {"success": True}

    def safe_post(self, endpoint, json_data, read_timeout=None):
        self.calls.append((endpoint, json_data))
        self.posters.append("safe_post")
        return self.reply

    def heavy_tool_post(self, endpoint, json_data, semaphore_timeout=120, read_timeout=None):
        self.calls.append((endpoint, json_data))
        self.posters.append("heavy_tool_post")
        return self.reply

    def safe_get(self, endpoint, params=None, read_timeout=None):
        # Only reached when a reply carries a job_id. The default reply does not,
        # so these stay body-shape tests rather than turning into timing tests.
        return {"status": "running"}


def _exec_tools(reply=None):
    from mcp_tools import command_exec

    recording, client = _RecordingMCP(), _RecordingClient(reply)
    command_exec.register(recording, client)
    return recording.tools, client


def test_a_plain_call_starts_a_background_job():
    """The fix. Without background in the body the backend takes its foreground
    branch, which tees nowhere -- a harness abort there loses every byte and
    leaves an untracked subprocess running."""
    tools, client = _exec_tools()

    tools["zebbern_exec"](command="whoami")

    endpoint, body = client.calls[-1]
    assert endpoint == "api/exec"
    assert body["background"] is True, (
        "zebbern_exec still runs in the foreground, so a command outrunning the "
        "~60s harness abort is orphaned with no log and no job_id"
    )
    assert body["command"] == "whoami", "the caller's own command must survive"
    assert body["timeout"] == 3600


def test_the_promotion_does_not_take_a_heavy_semaphore_slot():
    """heavy_tool_post holds one of five slots. zebbern_exec is the general
    escape hatch and is called constantly; putting it in that group would let a
    handful of shell commands starve the fourteen heavy scanners."""
    tools, client = _exec_tools()

    tools["zebbern_exec"](command="whoami")

    assert client.posters[-1] == "safe_post", (
        f"posted via {client.posters[-1]}, so zebbern_exec now competes for "
        "MAX_HEAVY_TASKS"
    )


def test_background_true_still_asks_for_a_background_job():
    """background=True narrowed to "do not wait inline" -- it must not stop
    being a job."""
    tools, client = _exec_tools()

    tools["zebbern_exec"](command="nc -lvnp 4444", background=True)

    _endpoint, body = client.calls[-1]
    assert body["background"] is True
    assert body["command"] == "nc -lvnp 4444"


def test_cwd_is_only_sent_when_given():
    tools, client = _exec_tools()

    tools["zebbern_exec"](command="ls")
    _endpoint, body = client.calls[-1]
    assert "cwd" not in body

    tools["zebbern_exec"](command="ls", cwd="/mnt/work")
    _endpoint, body = client.calls[-1]
    assert body["cwd"] == "/mnt/work"


def test_zebbern_exec_is_not_one_of_the_fourteen():
    """PROMOTED_TOOLS is the tools_* map, and a cross-track test pins every key
    in it to a TOOL_TIMEOUTS tier >= 3600. run_promotable takes heavy/background
    explicitly and never reads the map, so adding a bare-exec name there would
    buy nothing and break that guard."""
    from mcp_tools._autopromote import PROMOTED_TOOLS

    assert len(PROMOTED_TOOLS) == 14
    for name in ("zebbern_exec", "exec", "bash"):
        assert name not in PROMOTED_TOOLS


# --------------------------------------------------------------- signal legibility

def test_a_signal_exit_with_no_output_is_explained():
    result = {"success": False, "finished": True, "return_code": -15,
              "stdout": "", "stderr": ""}

    _note_signal_exit("pkill -f 'sleep 600'", result)

    assert "SIGTERM" in result["note"]
    assert "15" in result["note"]
    assert "pattern" in result["note"], (
        "a pkill that matched its own shell is the usual cause and the note has "
        "to name it"
    )


def test_sigkill_is_named_too():
    result = {"return_code": -9, "stdout": "", "stderr": ""}

    _note_signal_exit("sleep 5", result)

    assert "SIGKILL" in result["note"]
    # Not a kill command, so no self-match hint to mislead with.
    assert "pattern" not in result["note"]


def test_a_signal_exit_that_produced_output_is_left_alone():
    """The output is the explanation. Annotating here would be noise on a result
    that already says what happened."""
    result = {"return_code": -15, "stdout": "scanned 400 hosts", "stderr": ""}

    _note_signal_exit("pkill -f nmap", result)

    assert "note" not in result
    assert result["stdout"] == "scanned 400 hosts", "output must never be touched"


def test_a_timeout_is_not_reported_as_a_signal():
    """timed_out is its own flag and -1 is the timeout sentinel, not a signal.
    Calling it SIGTERM would contradict the flag the caller is told to check."""
    result = {"return_code": -15, "timed_out": True, "stdout": "", "stderr": ""}

    _note_signal_exit("pkill -f nmap", result)

    assert "note" not in result


def test_a_running_handoff_is_not_annotated():
    """finished=False means the job is still going: there is no exit to explain,
    and the handoff note telling the agent how to poll must survive."""
    result = {"success": True, "finished": False, "status": "running",
              "job_id": "jb", "return_code": None, "note": "Still running after ~50s."}

    _note_signal_exit("pkill -f nmap", result)

    assert result["note"] == "Still running after ~50s."


def test_an_ordinary_nonzero_exit_is_not_annotated():
    """Only negative codes are signals. A grep that matched nothing exits 1 and
    needs no story."""
    result = {"return_code": 1, "stdout": "", "stderr": ""}

    _note_signal_exit("grep nope /etc/passwd", result)

    assert "note" not in result


def test_the_truncation_note_is_never_clobbered():
    """setdefault, not assignment. The truncation note says where the full log
    is; losing it would hide 100% of the output behind a tail."""
    result = {"return_code": -15, "stdout": "", "stderr": "",
              "note": "Output exceeded the in-memory window"}

    _note_signal_exit("pkill -f nmap", result)

    assert result["note"] == "Output exceeded the in-memory window"


@pytest.mark.parametrize("result", ["not a dict", None, 42, []])
def test_a_non_dict_reply_is_survived(result):
    """safe_post can hand back an error dict, and a backend could hand back
    anything. The annotator must not be the thing that raises."""
    _note_signal_exit("pkill -f nmap", result)


# ----------------------------------------------- the base sentence is unconditional

@pytest.mark.parametrize("code,signal_name", sorted(_SIGNAL_EXITS.items()))
def test_every_signal_the_table_declares_is_named(code, signal_name):
    """Driven from the table, so an entry cannot be added without being covered.

    -2/SIGINT was declared and exercised by nothing: deleting or mistyping it
    went green while that signal went back to the unexplained shape the whole
    note exists to remove.
    """
    result = {"success": False, "finished": True, "return_code": code,
              "stdout": "", "stderr": ""}

    _note_signal_exit("sleep 5", result)

    assert signal_name in result["note"], (
        f"return_code {code} is in _SIGNAL_EXITS but produced no note naming "
        f"{signal_name}"
    )
    assert str(-code) in result["note"], "the signal number itself has to appear"


@pytest.mark.parametrize("code,signal_name", [
    (-15, "SIGTERM"), (-9, "SIGKILL"), (-2, "SIGINT"),
])
def test_the_table_still_declares_the_three_signals_it_claims_to(code, signal_name):
    """The parametrized test above covers whatever is present, which is exactly
    why deletion needs its own assertion: drop an entry and that test simply
    yields one case fewer and stays green. Additions are still free."""
    assert _SIGNAL_EXITS.get(code) == signal_name


# ------------------------------------------- the self-match clause is a possibility

def test_a_direct_kill_by_pid_is_not_blamed_for_a_self_match():
    """`kill -TERM 4567` selects a PID; it cannot match its own shell. The old
    substring test on "kill" annotated it anyway, so an operator whose job was
    terminated from outside (job_cancel, an OOM kill) was handed a confident
    explanation of something that had not happened."""
    result = {"success": False, "finished": True, "return_code": -15,
              "stdout": "", "stderr": ""}

    _note_signal_exit("kill -TERM 4567", result)

    assert "SIGTERM" in result["note"], "the observed half must still be there"
    assert "pattern" not in result["note"], (
        "a PID kill was told its pattern matched its own shell"
    )


@pytest.mark.parametrize("command", [
    "grep killer /var/log/auth.log",
    "./skillall --report",
    "nmap --script ssl-kill 10.0.0.1",
    "echo 'fuserconf' > /tmp/x",
    "kill -9 4567",
    "pkill nginx",            # by name: the shell is sh/bash, not nginx
    "pkill firefox",          # ditto, and the name itself contains an "f"
    "fuser 8080/tcp",         # a query, not a kill
    "pgrep -f 'sleep 600'",   # kills nothing on its own
    "pkill nginx && echo -f", # the -f belongs to echo, not to pkill
])
def test_commands_that_cannot_self_match_do_not_get_the_clause(command):
    assert not _selects_processes_by_pattern(command), command


@pytest.mark.parametrize("command", [
    "pkill -f 'sleep 600'",
    "pkill -if nmap",
    "pkill --full nmap",
    "sudo pkill -f nmap",
    "/usr/bin/pkill -f nmap",
    "killall nmap",
    "fuser -k 8080/tcp",
    "fuser -ki 8080/tcp",
    "echo start; pkill -f nmap",
])
def test_commands_that_select_indirectly_do_get_the_clause(command):
    assert _selects_processes_by_pattern(command), command


def test_the_clause_reads_as_a_possibility_not_a_finding():
    """The tool observed a signal and no output. It did not observe a self-match,
    and must not say it did."""
    result = {"success": False, "finished": True, "return_code": -15,
              "stdout": "", "stderr": ""}

    _note_signal_exit("pkill -f 'sleep 600'", result)

    note = result["note"]
    assert "possibility" in note
    assert "may have matched the shell" not in note, (
        "restored wording that states the cause"
    )


def test_the_unconditional_half_names_the_outside_kill():
    """A signal with no output is also what job_cancel and the OOM killer look
    like, and that is true whatever the command was."""
    result = {"return_code": -9, "stdout": "", "stderr": ""}

    _note_signal_exit("sleep 5", result)

    assert "job_cancel" in result["note"]


@pytest.mark.parametrize("command", [None, 42, [], {"command": "pkill -f x"}])
def test_a_non_string_command_is_survived(command):
    """The annotator is never the thing that raises -- the same rule as the
    non-dict reply above."""
    result = {"return_code": -15, "stdout": "", "stderr": ""}

    _note_signal_exit(command, result)

    assert "SIGTERM" in result["note"]
    assert "pattern" not in result["note"]
