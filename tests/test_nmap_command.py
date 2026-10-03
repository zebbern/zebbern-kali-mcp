"""run_nmap silently dropped its own -T4 -Pn whenever additional_args was given.

`additional_args = params.get("additional_args", "") or "-T4 -Pn"` made
`-T4 -Pn` the *default value* of additional_args, so passing any additional_args
REPLACED it instead of adding to it. Asking for `--script vuln` dropped -Pn, and
a host that blocks ping then read as down -- the scan quietly answered the wrong
question while still reporting success. The fix applies -T4 -Pn as a baseline on
every scan, after the ports segment and before additional_args, so additional_args
augments it; nmap honours the last -T template, so an operator -Tn still wins.

Same pattern as tests/test_gowitness_command.py: load run_nmap from the backend
and capture the command string handed to a patched execute_command.
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from tools import kali_tools  # noqa: E402


def _built_command(monkeypatch, params):
    captured = {}
    monkeypatch.setattr(
        kali_tools, "execute_command",
        lambda command, **kw: captured.update(command=command, kw=kw) or {"success": True},
    )
    kali_tools.run_nmap(params)
    return captured["command"]


def test_additional_args_augment_the_baseline_they_do_not_replace_it(monkeypatch):
    command = _built_command(
        monkeypatch, {"target": "t", "additional_args": "--script vuln"}
    )

    assert "-Pn" in command, (
        "additional_args used to REPLACE the -T4 -Pn default, so --script vuln "
        "dropped -Pn and a ping-blocking host read as down"
    )
    assert "--script vuln" in command


def test_baseline_is_applied_when_no_additional_args_are_given(monkeypatch):
    command = _built_command(monkeypatch, {"target": "t"})

    assert "-T4" in command and "-Pn" in command


def test_baseline_precedes_additional_args_so_an_operator_timing_wins(monkeypatch):
    """nmap honours the last -T template, so the operator's -T2 must come after
    the baseline -T4 for the operator to win."""
    command = _built_command(
        monkeypatch, {"target": "t", "additional_args": "-T2"}
    )

    assert command.index("-T4") < command.index("-T2")
