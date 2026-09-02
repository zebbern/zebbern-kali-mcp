"""End-to-end guards on CommandExecutor's output and its flag types.

Every other test of the executor is contract-level with a mocked client, so the
class that actually collects a tool's output had no test that ran it. That
matters more than it used to: ``stdout_data``/``stderr_data`` are no longer
appended to directly, they are *derived* from the chunk lists by
``_finalize_output()``. Delete the two ``_finalize_output()`` calls on the
normal paths and the whole suite still passed while
``CommandExecutor("echo hello").execute()`` returned ``stdout=''`` with
``success=True`` -- every tool's output vanishing, reported as a clean success.
Dropping the ``bool(...)`` wrappers around ``partial_results`` was invisible in
the same way.

So these run real processes. ``sys.executable`` rather than bash, because the
suite has to pass on the Windows host as well as in the container.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.command_executor import CommandExecutor  # noqa: E402

# CommandExecutor runs everything through ``shell=True``, so the argv has to be
# rendered back into a command line the local shell parses the same way.
_quote = (
    subprocess.list2cmdline
    if sys.platform == "win32"
    else (lambda argv: " ".join(__import__("shlex").quote(part) for part in argv))
)

OUT_MARKER = "OUT-MARKER-8f21"
ERR_MARKER = "ERR-MARKER-8f21"

# Long enough that a 2s budget cannot reach it by accident, short enough that a
# process orphaned by the shell wrapper is gone before the suite finishes.
_RUNAWAY_SLEEP = 15


def _python(code: str) -> str:
    return _quote([sys.executable, "-c", code])


def _completing_command() -> str:
    return _python(
        "import sys; "
        f"sys.stdout.write('{OUT_MARKER}\\n'); "
        f"sys.stderr.write('{ERR_MARKER}\\n')"
    )


def _runaway_command() -> str:
    """Print, flush, then outlive any budget the caller gives it."""
    return _python(
        "import sys, time; "
        f"sys.stdout.write('{OUT_MARKER}\\n'); "
        "sys.stdout.flush(); "
        f"time.sleep({_RUNAWAY_SLEEP})"
    )


def _collect(_source, _line):
    """A streaming callback that does nothing but exist."""


# ---------------------------------------------------------------------------
# A command that completes: the output has to survive, and the flags have to be
# real bools. partial_results is asserted by identity, not truthiness -- the
# reverted form yields the stdout *string* on the timeout path, and a test
# written as ``assert not result["partial_results"]`` would accept it.
# ---------------------------------------------------------------------------


def test_execute_returns_the_output_of_a_command_that_finishes():
    result = CommandExecutor(_completing_command(), timeout=60).execute()

    assert OUT_MARKER in result["stdout"]
    assert ERR_MARKER in result["stderr"]
    assert result["return_code"] == 0
    assert result["success"] is True
    assert result["timed_out"] is False
    assert result["partial_results"] is False


def test_execute_with_streaming_returns_the_output_of_a_command_that_finishes():
    streamed = []

    result = CommandExecutor(_completing_command(), timeout=60).execute_with_streaming(
        lambda source, line: streamed.append((source, line))
    )

    assert OUT_MARKER in result["stdout"]
    assert ERR_MARKER in result["stderr"]
    assert result["return_code"] == 0
    assert result["success"] is True
    assert result["timed_out"] is False
    assert result["partial_results"] is False
    assert result["streaming_enabled"] is True
    # The callback and the accumulated buffer are two separate paths through the
    # reader thread; a regression in either one alone would be worth catching.
    assert any(OUT_MARKER in line for _source, line in streamed)


# ---------------------------------------------------------------------------
# A command that outruns its budget: success stays True, the printed line is
# still there, and both flags say so. This is the pairing CLAUDE.md pins --
# callers read timed_out, never success, to know a command finished.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_a_command_that_outruns_its_budget_keeps_what_it_printed(streaming):
    executor = CommandExecutor(_runaway_command(), timeout=2)

    started = time.monotonic()
    if streaming:
        result = executor.execute_with_streaming(_collect)
    else:
        result = executor.execute()
    elapsed = time.monotonic() - started

    assert OUT_MARKER in result["stdout"]
    assert result["timed_out"] is True
    assert result["partial_results"] is True
    assert result["success"] is True
    # 2s budget + the executor's 5s terminate grace. Asserting the clock as well
    # as the flags is what proves the budget was enforced rather than the child
    # merely being slow: without it a test whose command exited on its own would
    # read as a pass.
    assert elapsed < _RUNAWAY_SLEEP, f"the budget did not fire: {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# The derived attributes themselves.
# ---------------------------------------------------------------------------


def test_the_public_output_attributes_are_populated_strings():
    """stdout_data/stderr_data are public and were plain strings before the
    chunk lists went in. Anything reading the executor object rather than the
    result dict still sees strings holding the same bytes."""
    executor = CommandExecutor(_completing_command(), timeout=60)
    result = executor.execute()

    assert isinstance(executor.stdout_data, str)
    assert isinstance(executor.stderr_data, str)
    assert OUT_MARKER in executor.stdout_data
    assert ERR_MARKER in executor.stderr_data
    assert executor.stdout_data == result["stdout"]
    assert executor.stderr_data == result["stderr"]


def test_a_large_output_comes_back_whole():
    """Nothing between the reader thread and the result dict may cap or drop
    operator output -- that is the same sin as redacting it."""
    lines = 20000
    # One physical line: a `-c` body containing a newline does not survive the
    # shell CommandExecutor runs everything through.
    command = _python(
        "import sys; "
        f"sys.stdout.writelines('line-%d\\n' % i for i in range({lines}))"
    )

    result = CommandExecutor(command, timeout=120).execute()

    assert result["timed_out"] is False
    assert result["stdout"].count("\n") == lines
    assert "line-0\n" in result["stdout"]
    assert f"line-{lines - 1}\n" in result["stdout"]
