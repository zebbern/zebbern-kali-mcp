"""Stopping a reverse-shell listener has to actually free the port.

The listener is spawned with ``shell=True`` under ``preexec_fn=os.setsid``, so
the tracked process is the SHELL and the real ``nc``/``socat`` is its child in
the same process group. ``terminate()`` on the leader alone killed the shell and
left the listener bound -- ``ss`` showed ``nc`` still LISTENING with ``ppid 1``
while ``stop()`` returned and the route answered ``{"success": true}``.

That is the same shape as the ``MetasploitSession`` teardown and
``NetworkPivotManager.stop_tunnel``: signal the group, not the leader.

``core.reverse_shell_manager`` imports ``pty``, so Windows needs the stub the
rest of the suite already uses.
"""

import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

if os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

try:
    from core import reverse_shell_manager as rs_module
except ImportError:  # pragma: no cover - no pty and no stub
    rs_module = None

requires_rs_module = pytest.mark.skipif(
    rs_module is None,
    reason="core.reverse_shell_manager imports pty, which does not exist on Windows",
)


class _ShellLeader:
    """The shell Popen wraps. Its child is what actually holds the port."""

    def __init__(self, pid=4242, wait_raises=False):
        self.pid = pid
        self._wait_raises = wait_raises
        self.terminated = False
        self.killed = False

    def wait(self, timeout=None):
        if self._wait_raises:
            self._wait_raises = False
            raise subprocess.TimeoutExpired(cmd="nc", timeout=timeout)
        return 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


def _listener_with_recorded_signals(monkeypatch, wait_raises=False):
    manager = rs_module.ReverseShellManager.__new__(rs_module.ReverseShellManager)
    manager.process = _ShellLeader(wait_raises=wait_raises)
    manager.master_fd = None
    manager.port = 19005

    signals = []
    group_alive = {"value": True}

    def fake_killpg(pgid, sig):
        if sig == 0:
            if not group_alive["value"]:
                raise ProcessLookupError()
            return None
        signals.append((pgid, sig))
        if sig == getattr(rs_module.signal, "SIGKILL", 9):
            group_alive["value"] = False

    monkeypatch.setattr(rs_module.os, "killpg", fake_killpg, raising=False)
    return manager, signals


@requires_rs_module
def test_stop_signals_the_whole_group_not_just_the_shell(monkeypatch):
    manager, signals = _listener_with_recorded_signals(monkeypatch)

    manager.stop()

    assert (4242, rs_module.signal.SIGTERM) in signals, (
        "only the shell was signalled, so nc keeps the port bound"
    )
    assert manager.process is None


@requires_rs_module
def test_stop_reaps_a_listener_that_outlives_the_shell(monkeypatch):
    """The leader exits but the child still holds the port -- exactly the state
    observed in the container, nc with ppid 1 on a dead shell's pgid."""
    manager, signals = _listener_with_recorded_signals(monkeypatch)

    manager.stop()

    sigkill = getattr(rs_module.signal, "SIGKILL", 9)
    assert signals == [(4242, rs_module.signal.SIGTERM), (4242, sigkill)], (
        f"the surviving listener was never reaped: {signals!r}"
    )


@requires_rs_module
def test_stop_escalates_when_the_group_ignores_sigterm(monkeypatch):
    manager, signals = _listener_with_recorded_signals(monkeypatch, wait_raises=True)

    manager.stop()

    sigkill = getattr(rs_module.signal, "SIGKILL", 9)
    assert (4242, sigkill) in signals, f"never escalated: {signals!r}"
