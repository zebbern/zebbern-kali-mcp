"""`_save_state` must not leave an orphan `state.json.tmp` when the write fails.

The atomic write (write a sibling `.tmp`, then `os.replace` it into place --
added for review #8) protects the live `state.json` from a mid-write crash, but
`open(tmp_file, 'w')` has already created an empty `.tmp` by the time `json.dump`
raises. Left behind, that zero-byte `.tmp` accumulates on every failed save and,
worse, a later successful save's `os.replace` is the only thing that ever clears
it. The fix unlinks the partial `.tmp` best-effort on the exception path and
re-raises, so a failed write leaves nothing beside an intact `state.json`.

This guard seeds a valid `state.json`, makes `json.dump` raise, calls
`_save_state`, and asserts no `*.tmp` lingers in the state dir and the original
`state.json` is untouched. Under the mutation that drops the tmp-unlink, the
orphan `.tmp` survives and the no-`.tmp` assertion fails.

The manager is built with `object.__new__` so nothing real is opened; only the
attributes `_save_state` reads are set. `network_pivot.py` is import-safe on
Windows.
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402


def _manager(tmp_path):
    mgr = object.__new__(np.NetworkPivotManager)
    mgr.output_dir = str(tmp_path)
    mgr.tunnels = {}
    mgr.pivots = {}
    mgr.proxy_chains = []
    return mgr


def _seed_state(tmp_path):
    state = {"tunnels": {}, "pivots": {}, "proxy_chains": [{"name": "keep_me"}]}
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state_file


class TestSaveStateTmpCleanup:
    def test_a_failed_write_leaves_no_orphan_tmp(self, tmp_path, monkeypatch):
        state_file = _seed_state(tmp_path)
        mgr = _manager(tmp_path)

        def boom(*args, **kwargs):
            raise OSError("disk full mid-write")

        monkeypatch.setattr(np.json, "dump", boom)

        with pytest.raises(OSError):
            mgr._save_state()

        # The partial .tmp must be cleaned up on the exception path.
        leftover = list(tmp_path.glob("*.tmp"))
        assert leftover == [], f"orphan temp file(s) left behind: {leftover}"

        # ...and the pre-existing state.json is still intact.
        assert state_file.exists()
        reloaded = json.loads(state_file.read_text(encoding="utf-8"))
        assert reloaded["proxy_chains"] == [{"name": "keep_me"}]

    def test_a_successful_write_still_leaves_no_tmp(self, tmp_path):
        _seed_state(tmp_path)
        mgr = _manager(tmp_path)
        mgr.proxy_chains = [{"name": "chain_b"}]

        mgr._save_state()

        assert list(tmp_path.glob("*.tmp")) == []
        reloaded = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert reloaded["proxy_chains"] == [{"name": "chain_b"}]
