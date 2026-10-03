"""The CommandExecutor timeout path must join its reader threads before it
snapshots the chunk lists, or a timed-out scan's buffered tail is dropped.

The normal path joins both readers (command_executor lines ~102-103); the
timeout path did not, and there is no later call on that path for a straggling
append to be picked up by, so whatever the readers had buffered at the moment of
the kill was finalized away and never returned. The fix adds bounded
``join(timeout=5)`` calls in the ``except subprocess.TimeoutExpired`` block
before ``_finalize_output()``.

This guard is deterministic: no sleeps, no real subprocess, no scheduler
dependence. The ruling's ``object.__new__`` approach cannot work here because
``execute()`` reassigns ``self.stdout_thread``/``self.stderr_thread`` at the top
of its ``try`` (lines ~91-92), overwriting any pre-seeded doubles. So the module
itself is faked:

  * ``_FakeProcess.wait`` raises ``TimeoutExpired`` on the first call (the budget
    wait at line ~100) and returns 0 on the second (the terminate-grace wait at
    line ~112), landing execution in the except block with no real child;
  * ``_FakeThread.start`` is a no-op, so no reader runs and the normal-path join
    is never reached once ``wait`` has raised;
  * ``_FakeThread.join`` appends a sentinel line to the executor's
    ``_stdout_chunks``. The sentinel can reach ``result['stdout']`` only if the
    except-block join actually ran before ``_finalize_output`` collapsed the
    chunk lists. Delete the two except-block joins and the sentinel is absent.
"""

import subprocess
import sys
from pathlib import Path

# Load command_executor by path, the way the other executor tests do: the
# backend cannot be imported wholesale on Windows (pty/termios), but core.* is
# import-safe. Importing the module object (not just the class) is what lets us
# monkeypatch its module-level ``subprocess`` and ``threading`` references.
BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import core.command_executor as command_executor  # noqa: E402


class _FakeProcess:
    """Times out on the first wait, terminates cleanly on the second."""

    def __init__(self, *args, **kwargs):
        self.pid = 4242
        self._waits = 0
        self.stdout = None
        self.stderr = None

    def wait(self, timeout=None):
        self._waits += 1
        if self._waits == 1:
            # The budget wait at the top of execute()'s inner try.
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
        # The 5s terminate grace inside the except block.
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


class _FakeThread:
    """start() reads nothing; join() drops a sentinel into the executor's
    stdout chunk list. Only the except-block join can trigger that here."""

    def __init__(self, target=None, args=(), **kwargs):
        self._target = target
        self.daemon = False

    def start(self):
        # No reader runs, so the normal-path join at lines ~102-103 is never
        # reached (wait already raised). The only output is what join() injects.
        pass

    def join(self, timeout=None):
        if self._target is not None:
            # target is a bound method of the executor (self._read_stdout /
            # self._read_stderr); __self__ is the executor instance.
            executor = self._target.__self__
            executor._stdout_chunks.append("TAIL\n")


def test_timeout_path_joins_readers_before_finalizing(monkeypatch):
    monkeypatch.setattr(command_executor.subprocess, "Popen", _FakeProcess)
    monkeypatch.setattr(command_executor.threading, "Thread", _FakeThread)

    executor = command_executor.CommandExecutor("sleep 999", timeout=1)
    result = executor.execute()

    assert result["timed_out"] is True
    # The sentinel reaches the result iff the except-block join ran before
    # _finalize_output snapshotted the chunk lists. Without the joins the
    # readers are never joined on this path and stdout comes back empty.
    assert "TAIL" in result["stdout"]
