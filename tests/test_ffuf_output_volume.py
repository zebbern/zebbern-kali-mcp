"""A backgrounded ffuf returned 105KB to say 14 things.

The background branch swaps -o for -json so findings land on stdout, where the
job log tees them. But ffuf also repaints a progress counter on stderr, and
with no TTY attached every repaint is a fresh line. One default common.txt run
against a live target measured:

    stdout   4,566 chars   14 findings          <- the answer
    stderr  38,597 chars  430 lines             <- banner and progress
    events  60,562 chars  445 entries           <- all 445 already above

105KB, of which 4% was signal. That is past what an MCP client will put in
front of a model, so the agent that ran the scan could not read its own
results.

-s drops the banner and the progress entirely (971 -> 5 bytes on a 40-word
list) and leaves the JSON records on stdout unchanged, verified equal
finding-for-finding ignoring FFUFHASH, which is random per run.

nuclei deliberately does NOT get the same treatment: its stderr is a bounded
17-line startup banner, not a per-request counter, and it is the only sign of
life during the minutes of template loading before findings appear.
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import api_security  # noqa: E402

SOURCE = (BACKEND_ROOT / "core" / "api_security.py").read_text(encoding="utf-8")


def _background_cmd(monkeypatch, **kwargs):
    seen = {}
    monkeypatch.setattr(
        api_security, "execute_command_argv",
        lambda cmd, **kw: seen.update(cmd=list(cmd), kw=kw) or {"job_id": "j"},
    )
    api_security.api_tester.ffuf_fuzz(url="http://t/FUZZ", background=True, **kwargs)
    return seen["cmd"]


def test_backgrounded_ffuf_is_silent(monkeypatch):
    cmd = _background_cmd(monkeypatch)

    assert "-s" in cmd, (
        "without this, 430 lines of progress repaints ride back with 14 findings"
    )


def test_backgrounded_ffuf_still_emits_the_findings(monkeypatch):
    """-s must not cost the machine-readable output it exists to protect."""
    cmd = _background_cmd(monkeypatch)

    assert "-json" in cmd
    assert "-o" not in cmd, "the parse never runs on a background job"


def test_silencing_did_not_leak_into_the_synchronous_branch():
    """The synchronous branch writes -o and parses the file afterwards; it is
    the path a direct HTTP caller still gets and stays untouched."""
    start = SOURCE.index("def ffuf_fuzz")
    body = SOURCE[start:SOURCE.index("def ", start + 10)]
    sync = body[body.index("output_file = os.path.join"):]

    assert '"-of", "json"' in sync or "-of" in sync, "sync branch still writes a file"
    assert '"-s"' not in sync, "the synchronous branch was not part of this change"


def test_nuclei_keeps_its_startup_output(monkeypatch):
    """Its stderr is 17 bounded lines of banner and template counts, and the
    only sign of life while templates load. Silencing it would make an
    already-empty-looking job completely dark."""
    seen = {}
    monkeypatch.setattr(
        api_security, "execute_command_argv",
        lambda cmd, **kw: seen.update(cmd=list(cmd)) or {"job_id": "j"},
    )
    api_security.api_tester.nuclei_api_scan(target="http://t", background=True)

    assert "-silent" not in seen["cmd"]
    assert "-jsonl" in seen["cmd"]
