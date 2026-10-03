"""`NetworkPivotManager` must resolve the ligolo binary the image actually ships.

The image installs `/usr/local/bin/ligolo-proxy` (the `install_commands` in
`ligolo_proxy_start` end with `sudo mv proxy /usr/local/bin/ligolo-proxy`), but
`__init__` used to resolve `_find_tool("ligolo-ng")` -- a name that is never on
disk -- so `ligolo_path` was permanently `None` and `ligolo_proxy_start` always
returned its "not found" error. The fix passes `"ligolo-proxy"` instead.

This guard builds the real manager (so it exercises the resolver argument on the
`__init__` line, which is the thing that regressed) with a fake `os.path.exists`
that resolves `/usr/local/bin/ligolo-proxy` and nothing ligolo-named else, and
asserts `ligolo_path` is that path and not `None`. Under the mutation that
reverts the argument to `"ligolo-ng"`, `exists` never answers True for it and
`ligolo_path` falls through to `None`, so the assertion fails.

`network_pivot.py` is import-safe on Windows (no `pty`/`termios`).
"""

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402

LIGOLO_PROXY_PATH = "/usr/local/bin/ligolo-proxy"


class _FakeRun:
    """A `subprocess.run` stand-in whose `which` lookups always miss."""

    returncode = 1
    stdout = ""


def _resolve_only_ligolo_proxy(real_exists):
    """exists() that answers True only for the installed ligolo-proxy binary."""

    def fake_exists(path):
        if path == LIGOLO_PROXY_PATH:
            return True
        # Any ligolo-named path other than the real one must miss, so the
        # resolver cannot accidentally succeed on the wrong name.
        if "ligolo" in os.path.basename(str(path)):
            return False
        return real_exists(path)

    return fake_exists


class TestLigoloBinaryResolution:
    def test_manager_resolves_ligolo_proxy_not_ligolo_ng(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            np.os.path, "exists", _resolve_only_ligolo_proxy(os.path.exists)
        )
        monkeypatch.setattr(np.subprocess, "run", lambda *a, **k: _FakeRun())

        mgr = np.NetworkPivotManager(output_dir=str(tmp_path))

        assert mgr.ligolo_path is not None
        assert mgr.ligolo_path == LIGOLO_PROXY_PATH

    def test_ligolo_ng_name_is_never_what_resolves(self, tmp_path, monkeypatch):
        # Belt-and-braces: if the image only had the old 'ligolo-ng' name on
        # disk, the manager must NOT pick it up -- the fix is about the name the
        # resolver asks for, and that name is 'ligolo-proxy'. Defer to the real
        # exists for everything non-ligolo so os.makedirs still works.
        real_exists = os.path.exists

        def only_ligolo_ng(path):
            base = os.path.basename(str(path))
            if "ligolo" in base:
                return path == "/usr/local/bin/ligolo-ng"
            return real_exists(path)

        monkeypatch.setattr(np.os.path, "exists", only_ligolo_ng)
        monkeypatch.setattr(np.subprocess, "run", lambda *a, **k: _FakeRun())

        mgr = np.NetworkPivotManager(output_dir=str(tmp_path))

        assert mgr.ligolo_path is None
