"""`_save_state` must not destroy the state it is replacing when a write fails.

`state.json` is the one cross-restart guarantee the pivot manager keeps -- on a
routine `docker compose up -d --force-recreate` the SIGTERM can land mid-write,
and an in-place `open(state_file, 'w')` truncates the live file the instant it
opens, before a single byte of the new JSON is written. If the write then dies,
`_load_state` meets a truncated file, swallows the parse error, and silently
boots with zero pivots.

The fix writes a sibling temp file in the same directory and `os.replace`s it
into place, so a failed write damages only the throwaway temp and the previous
`state.json` survives intact. These tests drive `_save_state` with a `json.dump`
that raises mid-write and assert the original file is still there and still
parses -- which is true under the atomic write and false under the in-place one.

The manager is built with `object.__new__` so nothing is opened and no real
pivoting directory is touched; only the attributes `_save_state` reads are set.
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
    """A manager that writes into `tmp_path`, built without running __init__."""
    mgr = object.__new__(np.NetworkPivotManager)
    mgr.output_dir = str(tmp_path)
    mgr.tunnels = {}
    mgr.pivots = {}
    mgr.proxy_chains = []
    return mgr


def _write_original_state(tmp_path):
    """A valid `state.json` already on disk, holding one pivot to lose."""
    state = {
        "tunnels": {},
        "pivots": {
            "piv_1": {
                "id": "piv_1",
                "name": "dmz",
                "host": "10.0.0.5",
                "internal_network": "10.0.0.0/24",
                "tunnels": [],
                "created_at": "2026-01-01T00:00:00",
                "notes": "",
                "method": "ssh",
            }
        },
        "proxy_chains": [],
    }
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state_file


class TestSaveStateIsAtomic:
    def test_a_failed_write_leaves_the_existing_state_intact(
        self, tmp_path, monkeypatch
    ):
        state_file = _write_original_state(tmp_path)
        mgr = _manager(tmp_path)

        def boom(*args, **kwargs):
            raise OSError("disk full mid-write")

        monkeypatch.setattr(np.json, "dump", boom)

        with pytest.raises(OSError):
            mgr._save_state()

        # An in-place open(state_file, 'w') would have truncated this before
        # json.dump raised; the atomic write damages only the temp sibling.
        assert state_file.exists()
        reloaded = json.loads(state_file.read_text(encoding="utf-8"))
        assert "piv_1" in reloaded["pivots"]
        assert reloaded["pivots"]["piv_1"]["host"] == "10.0.0.5"

    def test_a_successful_write_replaces_the_file_and_leaves_no_temp(
        self, tmp_path
    ):
        _write_original_state(tmp_path)
        mgr = _manager(tmp_path)
        mgr.pivots = {}
        mgr.proxy_chains = [{"name": "chain_a"}]

        mgr._save_state()

        state_file = tmp_path / "state.json"
        reloaded = json.loads(state_file.read_text(encoding="utf-8"))
        assert reloaded["proxy_chains"] == [{"name": "chain_a"}]
        # os.replace renames the temp away; nothing lingers beside state.json.
        assert not (tmp_path / "state.json.tmp").exists()
