"""zebbern_exec's timeout is a sentinel, and the cheat-sheet is load-bearing.

Two contracts, both invisible to the rest of the suite until you read what the
wrapper actually puts on the wire.

The first is the timeout sentinel. The old signature hardcoded ``timeout=3600``
and sent it on every call, so ``zebbern_exec('hydra ...')`` was capped at one
hour no matter hydra's 86400 TOOL_TIMEOUTS tier: the api/exec background branch
takes the operator's number verbatim and does no tier resolution of its own.
The fix makes the default a 0 sentinel that is OMITTED from the request body, so
the branch sees nothing and resolves the tier itself; a real operator value is
still forwarded, now only to SHORTEN the budget. So the contract that matters is
which KEY reaches run_promotable's data dict, not what value -- and that is what
these assert, at the run_promotable seam, before the ``background`` key is added.

The second is the cheat-sheet. zebbern_exec is where raw scanner commands get
composed by hand once a typed wrapper is suppressed, so the footguns the wrapper
used to hide (sqlmap blocking without ``--batch``, nmap not applying ``-Pn`` for
you, hydra naming no implicit wordlist, and each binary's tier) have to live in
the docstring or they are lost. These are literal-string assertions: a silent
edit dropping ``--batch`` or a tier number is the exact regression they guard,
and nothing else in the suite would catch it.

Import-safe: this touches only ``mcp_tools.command_exec`` -- never the backend
(``pty``/``termios``), which cannot be imported on Windows.
"""

import mcp_tools.command_exec as command_exec


class _RecordingMCP:
    """Capture the raw functions an mcp_tools module registers."""

    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.tools[name or function.__name__] = function
            return function

        return decorator


def _zebbern_exec_capturing_data(monkeypatch):
    """Register zebbern_exec with run_promotable stubbed, and hand back both the
    tool and a dict the stub fills with the data it was called with.

    Stubbing at ``command_exec.run_promotable`` (the name zebbern_exec looks up
    as a module global at call time) captures the wrapper's own data dict, before
    run_promotable merges in ``{"background": True}``. So "omits timeout" is
    asserted against what zebbern_exec built, not against the merged body.
    """
    captured = {}

    def _stub(kali_client, endpoint, data, *, heavy, background):
        captured["endpoint"] = endpoint
        captured["data"] = data
        captured["heavy"] = heavy
        captured["background"] = background
        return {"success": True, "finished": True}

    monkeypatch.setattr(command_exec, "run_promotable", _stub)
    recording = _RecordingMCP()
    command_exec.register(recording, object())
    return recording.tools["zebbern_exec"], captured


def test_a_default_call_omits_timeout_so_the_backend_resolves_the_tier(monkeypatch):
    """No ``timeout`` key on the wire is the whole fix: it is what lets the
    api/exec background branch resolve the backstop from the command's
    TOOL_TIMEOUTS tier. The old hardcoded 3600 was sent on every call and capped
    a ``hydra ...`` run at one hour regardless of hydra's 86400 tier."""
    zebbern_exec, captured = _zebbern_exec_capturing_data(monkeypatch)

    zebbern_exec(command="hydra -l admin -P rockyou.txt ssh://10.0.0.1")

    assert captured["data"] == {
        "command": "hydra -l admin -P rockyou.txt ssh://10.0.0.1"
    }
    assert "timeout" not in captured["data"], (
        "a default call still sends a timeout, so the backend cannot resolve the "
        "command's tier and the budget is capped at whatever flat default was sent"
    )


def test_zero_is_the_omit_sentinel_not_a_zero_second_budget(monkeypatch):
    """``timeout=0`` is the documented default and must behave as "omit it",
    never as a real zero-second backstop that would kill every job instantly."""
    zebbern_exec, captured = _zebbern_exec_capturing_data(monkeypatch)

    zebbern_exec(command="whoami", timeout=0)

    assert "timeout" not in captured["data"]


def test_an_explicit_timeout_is_forwarded_to_shorten_the_budget(monkeypatch):
    """A real operator value is still sent on the wire -- its only remaining use
    is to SHORTEN the tier-derived backstop."""
    zebbern_exec, captured = _zebbern_exec_capturing_data(monkeypatch)

    zebbern_exec(command="sqlmap -u http://t/ --batch", timeout=120)

    assert captured["data"]["timeout"] == 120


def test_cwd_is_still_only_sent_when_given(monkeypatch):
    """The sentinel change must not disturb the pre-existing cwd contract."""
    zebbern_exec, captured = _zebbern_exec_capturing_data(monkeypatch)

    zebbern_exec(command="ls")
    assert "cwd" not in captured["data"]

    zebbern_exec(command="ls", cwd="/mnt/work")
    assert captured["data"]["cwd"] == "/mnt/work"


def test_the_cheat_sheet_keeps_the_load_bearing_strings():
    """The footguns a typed wrapper used to hide survive only in this docstring
    once the pilot suppresses that wrapper, so each is a literal-string check:
    a silent drop of any of these is a regression with no other signal."""
    recording = _RecordingMCP()
    command_exec.register(recording, object())
    doc = recording.tools["zebbern_exec"].__doc__ or ""

    for needle in ("--batch", "-Pn", "86400", "28800", "14400"):
        assert needle in doc, f"cheat-sheet lost {needle!r}"
