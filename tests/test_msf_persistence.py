"""A backend restart must not make a Metasploit session look like it never ran.

MSF sessions were in-memory only, so a restart -- a routine ``docker compose up
-d --force-recreate`` here -- dropped the registry and left ``msf_session_list``
answering empty, which reads exactly like "nothing was ever started".
``MetasploitManager`` now persists each session's METADATA to
``msf_sessions.json`` (via ``core.state_store.StateStore``, under ``$ZKM_STATE_DIR``)
and rehydrates dropped sessions as dead stand-ins at construction. These tests
pin the contract that matters:

* a session the previous process left running reloads as a stand-in --
  ``is_alive()`` False, ``is_ready`` False, ``restored`` True -- so
  ``list_sessions`` SHOWS it was dropped rather than letting it vanish, and its
  ``last_known_ready`` keeps whether it had reached a prompt before the drop;
* a reloaded stand-in holds no process and no pid, and is NEVER signalled:
  ``_cleanup_dead_sessions`` leaves it be (its old pid may now belong to a
  stranger -- CLAUDE.md rule 3) and does not drop it, and ``execute_command``
  returns the existing "no longer running" error without probing it;
* a live session round-trips through disk: create -> persist -> a fresh manager
  reloads it as a stand-in, with no pid or process handle ever serialised;
* ``destroy``/``destroy_all`` persist the removal, and neither signals a
  stand-in on the way out;
* an unwritable state dir degrades to ``persisted=False`` and never fails a
  session operation -- the same honest degradation job_manager already makes.

``metasploit_manager`` imports ``core.pty_session``, which imports ``pty``, so on
Windows the pty import boundary is stubbed the way ``test_tool_timeouts.py`` does
it; the manager is then driven through ordinary construction with a ``StateStore``
pointed at a tmp dir. No PTY is ever opened: every session here is a disk-seeded
stand-in or a ``start()``-stubbed create.
"""

import json
import os
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# metasploit_manager -> core.pty_session -> import pty, which does not exist on
# Windows. Stub only that import boundary; nothing in these tests opens a PTY.
if os.name == "nt":
    _pty_stub = ModuleType("pty")
    _pty_stub.openpty = lambda: (0, 0)
    sys.modules.setdefault("pty", _pty_stub)

from core.state_store import StateStore  # noqa: E402

try:
    from core import metasploit_manager as msf_module  # noqa: E402
except ImportError:  # pragma: no cover - no pty and no stub
    msf_module = None

requires_msf = pytest.mark.skipif(
    msf_module is None,
    reason="core.metasploit_manager imports pty, which does not exist on Windows",
)


def _seed(state_dir, sessions):
    """Write a prior process's msf_sessions.json into ``state_dir``."""
    StateStore(os.path.join(state_dir, "msf_sessions.json")).save(
        {"sessions": sessions}
    )


def _read_file(state_dir):
    return json.loads(
        (Path(state_dir) / "msf_sessions.json").read_text(encoding="utf-8")
    )


# ---------------------------------------------------------------------------
# A session the previous process left running reloads as a dead stand-in and is
# shown by list_sessions, not dropped -- the headline failure this fixes.
# ---------------------------------------------------------------------------


@requires_msf
def test_seeded_session_reloads_as_a_dead_standin_and_is_listed(tmp_path):
    _seed(
        str(tmp_path),
        {"s1": {"session_id": "s1", "created_at": 100.0, "is_ready": True}},
    )

    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    listed = manager.list_sessions()
    assert listed["success"] is True
    assert listed["count"] == 1
    entry = listed["sessions"][0]
    assert entry["session_id"] == "s1"
    assert entry["is_alive"] is False
    assert entry["is_ready"] is False
    assert entry["restored"] is True
    # It had reached a prompt before the drop; that is recorded, but it is not
    # claimed to be ready now.
    assert entry["last_known_ready"] is True
    assert entry["created_at"] == 100.0

    # The stand-in holds no process: is_alive() is answered without a probe,
    # and there is nothing to signal.
    standin = manager.sessions["s1"]
    assert standin.process is None
    assert standin.is_alive() is False


@requires_msf
def test_cleanup_does_not_drop_a_restored_standin(tmp_path):
    """list_sessions runs _cleanup_dead_sessions first; a stand-in is dead but
    must survive it, or the session the whole feature exists to surface vanishes
    on the first listing."""
    _seed(
        str(tmp_path),
        {"s1": {"session_id": "s1", "created_at": 100.0, "is_ready": False}},
    )
    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    manager._cleanup_dead_sessions()

    assert "s1" in manager.sessions
    assert manager.sessions["s1"].restored is True
    # last_known_ready was False in the seed, so the stand-in neither claims nor
    # fabricates readiness.
    assert manager.sessions["s1"].last_known_ready is False


# ---------------------------------------------------------------------------
# A reloaded stand-in is never signalled, and execute never probes it.
# ---------------------------------------------------------------------------


@requires_msf
def test_no_reloaded_pid_is_ever_signalled(tmp_path, monkeypatch):
    _seed(
        str(tmp_path),
        {"s1": {"session_id": "s1", "created_at": 100.0, "is_ready": True}},
    )
    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    # Tripwires on the two syscalls that could carry a signal to a pid. The
    # persisted record never even held a pid, and the stand-in holds no process,
    # so nothing here may reach either -- a reused pid from the dead process
    # could now belong to a stranger (rule 3).
    def tripwire(*args, **kwargs):
        pytest.fail("a reloaded MSF session must never be signalled")

    monkeypatch.setattr(msf_module.os, "killpg", tripwire, raising=False)
    monkeypatch.setattr(msf_module.os, "kill", tripwire, raising=False)
    # execute() writes to the console fd; a stand-in must be refused before it
    # is reached, not probed.
    monkeypatch.setattr(
        manager.sessions["s1"], "execute", tripwire, raising=False
    )

    # Every read-path entry point an operator can reach against a stand-in.
    manager._cleanup_dead_sessions()
    manager.list_sessions()
    result = manager.execute_command("s1", "whoami")

    assert result["success"] is False
    assert result["console_exited"] is True
    assert "no longer running" in result["error"]
    # The stand-in is kept, not deleted, so it stays visible until an operator
    # destroys it explicitly.
    assert "s1" in manager.sessions


# ---------------------------------------------------------------------------
# A live session round-trips through disk: create -> persist -> reload.
# ---------------------------------------------------------------------------


@requires_msf
def test_live_session_persists_on_create_and_reloads_as_a_standin(
    tmp_path, monkeypatch
):
    # Stand in for a real msfconsole spawn: no PTY, just a session that reports
    # itself ready. create_session only needs start() to return True.
    def fake_start(self):
        self.is_ready = True
        return True

    monkeypatch.setattr(msf_module.MetasploitSession, "start", fake_start)

    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))
    created = manager.create_session()
    assert created["success"] is True
    assert created["persisted"] is True
    sid = created["session_id"]

    on_disk = _read_file(str(tmp_path))
    assert sid in on_disk["sessions"]
    record = on_disk["sessions"][sid]
    assert record["is_ready"] is True
    # The process handle, the fd and the pid are never serialised -- a new
    # process cannot re-adopt them.
    assert "pid" not in record
    assert "process" not in record
    assert "master_fd" not in record

    # A fresh manager on the same dir == a backend restart.
    restarted = msf_module.MetasploitManager(state_dir=str(tmp_path))
    reloaded = restarted.sessions[sid]
    assert reloaded.restored is True
    assert reloaded.is_alive() is False
    assert reloaded.is_ready is False
    assert reloaded.last_known_ready is True

    entry = next(
        e for e in restarted.list_sessions()["sessions"] if e["session_id"] == sid
    )
    assert entry["restored"] is True
    assert entry["is_alive"] is False


# ---------------------------------------------------------------------------
# destroy / destroy_all persist the removal and never signal a stand-in.
# ---------------------------------------------------------------------------


@requires_msf
def test_destroy_persists_the_removal_without_signalling_a_standin(
    tmp_path, monkeypatch
):
    _seed(
        str(tmp_path),
        {
            "s1": {"session_id": "s1", "created_at": 100.0, "is_ready": True},
            "s2": {"session_id": "s2", "created_at": 200.0, "is_ready": False},
        },
    )
    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    def tripwire(*args, **kwargs):
        pytest.fail("destroying a stand-in must not signal a pid")

    monkeypatch.setattr(msf_module.os, "killpg", tripwire, raising=False)
    monkeypatch.setattr(msf_module.os, "kill", tripwire, raising=False)

    result = manager.destroy_session("s1")
    assert result["success"] is True
    assert result["persisted"] is True
    assert "s1" not in manager.sessions

    on_disk = _read_file(str(tmp_path))
    assert "s1" not in on_disk["sessions"]
    assert "s2" in on_disk["sessions"]


@requires_msf
def test_destroy_all_clears_the_persisted_registry(tmp_path):
    _seed(
        str(tmp_path),
        {
            "s1": {"session_id": "s1", "created_at": 100.0, "is_ready": True},
            "s2": {"session_id": "s2", "created_at": 200.0, "is_ready": False},
        },
    )
    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    result = manager.destroy_all_sessions()
    assert result["success"] is True
    assert result["persisted"] is True
    assert manager.sessions == {}

    assert _read_file(str(tmp_path))["sessions"] == {}


# ---------------------------------------------------------------------------
# An unwritable state dir degrades to persisted=False and never fails a session
# operation.
# ---------------------------------------------------------------------------


@requires_msf
def test_unwritable_state_dir_degrades_to_persisted_false(tmp_path):
    # A file where the state directory's parent should be: the directory cannot
    # be created and msf_sessions.json can never be opened.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")

    # Construction (which loads state) must not raise on the unusable dir.
    manager = msf_module.MetasploitManager(state_dir=str(blocker / "state"))
    assert manager._persisted is False
    assert manager.list_sessions()["success"] is True

    # A session operation still succeeds; it just cannot be persisted. Inject a
    # stand-in (nothing could be seeded, the dir is unwritable) and destroy it.
    standin = msf_module.MetasploitSession("x")
    standin.restored = True
    manager.sessions["x"] = standin

    result = manager.destroy_session("x")
    assert result["success"] is True
    assert result["persisted"] is False
    assert "x" not in manager.sessions

    # And destroy_all on the degraded manager is equally non-fatal.
    assert manager.destroy_all_sessions()["success"] is True


# ---------------------------------------------------------------------------
# A graceful restart (SIGTERM) must STOP live sessions but keep the registry,
# so _load_sessions can rehydrate them as dead stand-ins -- the old handler
# called destroy_all_sessions, which cleared + re-persisted an EMPTY file and
# wiped the records before the new process could read them.
# ---------------------------------------------------------------------------


@requires_msf
def test_shutdown_keeps_the_persisted_registry(tmp_path):
    """The SIGTERM handler calls manager.shutdown(). It must stop each LIVE
    session's process yet leave both ``self.sessions`` and msf_sessions.json
    intact, so the records survive the restart and reload as stand-ins. The old
    handler called ``destroy_all_sessions``, which clears the dict and persists
    an EMPTY file -- so the restart wiped the registry and the whole persistence
    feature did nothing on the one path (a restart) that matters. A restored
    stand-in is skipped (it holds no process and no pid, rule 3), so a live
    session is injected to prove stop() is actually driven. ``destroy_all_sessions``
    itself is unchanged: it is the operator tool msf_session_destroy_all, where
    emptying the registry is correct."""
    _seed(
        str(tmp_path),
        {
            "s1": {"session_id": "s1", "created_at": 100.0, "is_ready": True},
            "s2": {"session_id": "s2", "created_at": 200.0, "is_ready": False},
        },
    )
    manager = msf_module.MetasploitManager(state_dir=str(tmp_path))

    # A live (non-restored) session whose stop() we can observe. The two seeded
    # sessions reloaded as restored stand-ins and shutdown() skips those.
    class _RecordingSession:
        def __init__(self, session_id):
            self.session_id = session_id
            self.restored = False
            self.stopped = False

        def stop(self):
            self.stopped = True

    live = _RecordingSession("live1")
    manager.sessions["live1"] = live

    manager.shutdown()

    # The live session was stopped ...
    assert live.stopped is True
    # ... but nothing was cleared: every entry -- seeded stand-in and live
    # alike -- is still in the in-memory registry.
    assert set(manager.sessions) == {"s1", "s2", "live1"}
    # ... and the on-disk file was NOT re-persisted empty: the seeded records
    # survive for _load_sessions to rehydrate after the restart (live1 was
    # injected directly and so was never written to disk).
    on_disk = _read_file(str(tmp_path))
    assert set(on_disk["sessions"]) == {"s1", "s2"}
