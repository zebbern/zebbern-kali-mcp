"""Reverse-shell and SSH session registries survive a backend restart.

Jobs, reverse-shell listeners and SSH sessions are in-memory only, so a backend
restart -- a routine ``docker compose up -d --force-recreate`` here -- drops the
registry and the ``*_status``/``list`` tools answer empty, indistinguishable
from "nothing ever started" (CLAUDE.md "Session lifetime"). job_manager already
persists its registry via ``core.state_store.StateStore``; this item extends the
same discipline to ``active_sessions`` (reverse shell) and ``active_ssh_sessions``
(SSH), writing METADATA on create/stop and reloading lightweight restored
stand-ins at backend start.

What a restored stand-in must report, and must NOT do, is the whole contract:

* ``status='stopped'``, ``is_connected=False``, ``process_alive=False``,
  ``restored=True`` (reverse shell also ``shell_responsive=None`` -- a channel
  that can never be established again is not the same as one that was tried and
  failed, so None, not False), plus a note that the backend restarted.
* It carries NO process and NO master_fd, so ``send_command`` / ``send_raw`` /
  ``read_output`` refuse it on their existing ``not is_connected`` /
  ``master_fd is None`` guards, and nothing poll()s it or probes it by pid/port
  (CLAUDE.md rule 3). The ``subprocess.run`` sentinel below proves a stand-in's
  status/teardown shells out to nothing.
* The SSH credential is NEVER written: a dead reloaded entry has no use for it,
  and persisting it would create a secret-at-rest the memory-only state never
  had. Only the key-file PATH is kept. This is not log redaction -- a field that
  was never persisted is simply not added.

``core.state_store`` and the two managers are pure-stdlib (plus the shared PTY
helper), so they import on the Windows test host once ``pty`` is stubbed -- the
same seam the rest of the suite installs. ``pty.openpty`` does not exist here and
is never needed: a stand-in opens no PTY, and every assertion is reached through
the constructors and the persistence helpers.
"""

import os
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

from core import config  # noqa: E402
from core import reverse_shell_manager as rs  # noqa: E402
from core import ssh_manager as ssh  # noqa: E402


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Point the managers' state dir at a writable tmp dir for one test."""
    target = tmp_path / "state"
    monkeypatch.setenv("ZKM_STATE_DIR", str(target))
    monkeypatch.delenv("JOB_OUTPUT_DIR", raising=False)
    return target


class _DeadProc:
    """A Popen stand-in whose poll() reports an exited process."""

    def poll(self):
        return 0


def _live_rs(session_id="shell_4444", port=4444, listener_type="netcat"):
    manager = rs.ReverseShellManager(port, session_id, listener_type)
    manager.is_connected = True
    manager.master_fd = 99
    manager.process = _DeadProc()
    return manager


def _live_ssh(session_id="ssh_x"):
    manager = ssh.SSHSessionManager(
        "10.0.0.5", "root",
        password="SUPERSECRET", key_file="/home/op/id_rsa",
        port=2222, session_id=session_id,
    )
    manager.is_connected = True
    manager.master_fd = 99
    manager.process = _DeadProc()
    return manager


# --------------------------------------------------------------- reverse shell
def test_reverse_shell_persist_then_restore_reports_stopped_standin(state_dir):
    live = _live_rs()
    created = live.created_at
    assert rs.persist_sessions({"shell_4444": live}) is True
    assert (state_dir / "sessions.json").is_file()

    # A fresh process: nothing in the registry until the file is reloaded.
    registry = {}
    assert rs.restore_sessions(registry) == 1

    stand_in = registry["shell_4444"]
    assert stand_in.process is None and stand_in.master_fd is None
    assert stand_in.restored is True
    assert stand_in.created_at == created

    status = stand_in.get_status()
    assert status["status"] == "stopped"
    assert status["is_connected"] is False
    assert status["process_alive"] is False
    assert status["restored"] is True
    assert status["shell_responsive"] is None
    assert status["port"] == 4444
    assert status["listener_type"] == "netcat"
    assert "restarted" in status["note"]


def test_reverse_shell_standin_refuses_io_and_probes_nothing(state_dir, monkeypatch):
    rs.persist_sessions({"shell_4444": _live_rs()})
    registry = {}
    rs.restore_sessions(registry)
    stand_in = registry["shell_4444"]

    # Any shell-out on the stand-in's status/teardown path is a rule-3 breach:
    # its old pid/port now belong to a stranger. Make them impossible.
    def _boom(*args, **kwargs):
        raise AssertionError("a restored stand-in shelled out (netstat/lsof)")

    monkeypatch.setattr(rs.subprocess, "run", _boom)

    assert stand_in.get_status()["status"] == "stopped"

    cmd = stand_in.send_command("id")
    assert cmd["success"] is False and "No active" in cmd["error"]
    raw = stand_in.send_raw("id\n")
    assert raw["success"] is False and raw["bytes_written"] == 0
    assert stand_in.read_output(1) == ""

    # stop() must forget the record without the lsof/kill-by-port cleanup.
    stand_in.stop()
    assert stand_in.is_connected is False


def test_live_reverse_shell_status_carries_restored_false(state_dir):
    # The field is present on the live path too, so a caller can always branch
    # on it; a dead fake process keeps get_status off the netstat branch.
    status = _live_rs().get_status()
    assert status["restored"] is False


# ----------------------------------------------------------------------- SSH
def test_ssh_persist_never_writes_credential_only_key_path(state_dir):
    assert ssh.persist_sessions({"ssh_x": _live_ssh()}) is True
    raw = (state_dir / "ssh_sessions.json").read_text(encoding="utf-8")
    assert "SUPERSECRET" not in raw
    assert "/home/op/id_rsa" in raw
    assert '"password"' not in raw
    for field in ("ssh_x", "10.0.0.5", "root", "2222"):
        assert field in raw


def test_ssh_restore_reports_stopped_standin_and_refuses_commands(state_dir):
    live = _live_ssh()
    created = live.created_at
    ssh.persist_sessions({"ssh_x": live})

    registry = {}
    assert ssh.restore_sessions(registry) == 1
    stand_in = registry["ssh_x"]

    assert stand_in.process is None and stand_in.master_fd is None
    assert stand_in.password == ""          # never persisted, never restored
    assert stand_in.key_file == "/home/op/id_rsa"
    assert stand_in.created_at == created

    status = stand_in.get_status()
    assert status["status"] == "stopped"
    assert status["is_connected"] is False
    assert status["process_alive"] is False
    assert status["restored"] is True
    assert "restarted" in status["note"]

    refused = stand_in.send_command("id")
    assert refused["success"] is False and "No active" in refused["error"]


def test_live_ssh_status_carries_restored_false(state_dir):
    assert _live_ssh().get_status()["restored"] is False


# --------------------------------------------------------- degradation & edges
def test_persist_degrades_to_false_when_state_dir_unwritable(tmp_path, monkeypatch):
    # A file where a directory must be: makedirs raises, persist swallows it and
    # reports persisted=false; the session operation is never failed.
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ZKM_STATE_DIR", str(blocker / "state"))
    monkeypatch.delenv("JOB_OUTPUT_DIR", raising=False)

    assert rs.persist_sessions({"shell_4444": _live_rs()}) is False
    assert ssh.persist_sessions({"ssh_x": _live_ssh()}) is False


def test_restore_with_no_file_is_a_clean_empty_boot(state_dir):
    rs_registry = {}
    ssh_registry = {}
    assert rs.restore_sessions(rs_registry) == 0
    assert ssh.restore_sessions(ssh_registry) == 0
    assert rs_registry == {} and ssh_registry == {}


def test_stopping_a_standin_drops_it_from_the_next_restart(state_dir):
    rs.persist_sessions({"shell_4444": _live_rs()})
    registry = {}
    rs.restore_sessions(registry)
    assert "shell_4444" in registry

    # The stop route does: manager.stop(); del registry[id]; persist(registry).
    registry["shell_4444"].stop()
    del registry["shell_4444"]
    assert rs.persist_sessions(registry) is True

    after = {}
    assert rs.restore_sessions(after) == 0


def test_state_dir_defaults_beside_the_job_log_dir(monkeypatch):
    monkeypatch.delenv("ZKM_STATE_DIR", raising=False)
    monkeypatch.setenv("JOB_OUTPUT_DIR", os.path.join("x", "app", "tmp", "jobs"))
    resolved = config.session_state_dir()
    assert os.path.basename(resolved) == "state"
    assert os.path.dirname(resolved) == os.path.join("x", "app", "tmp")


def test_state_dir_explicit_env_wins(monkeypatch):
    monkeypatch.setenv("ZKM_STATE_DIR", os.path.join("explicit", "here"))
    monkeypatch.setenv("JOB_OUTPUT_DIR", os.path.join("x", "jobs"))
    assert config.session_state_dir() == os.path.join("explicit", "here")
