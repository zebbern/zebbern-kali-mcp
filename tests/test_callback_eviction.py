"""Callback eviction must not lose data.

CallbackCatcher's in-memory list is clipped to the newest ``_max_size``
entries (``self._callbacks = self._callbacks[-self._max_size:]``), so once
more than ``_max_size`` callbacks arrive the oldest fall out of memory. Rule 2
(CLAUDE.md) says output is never discarded to bound memory -- it spills to
disk. The per-session ``.jsonl`` tee is that spill: it holds 100% of
callbacks, the in-memory ring is only a bounded polling window, and
``status()`` surfaces a monotonic ``callbacks_received`` plus
``callbacks_dropped`` so an operator who sees a non-zero drop knows to read
the log rather than conclude the evicted callbacks never arrived.

callback_catcher is import-safe on Windows (socket / http.server /
socketserver / threading, no pty), so the real class is driven directly.
JOB_OUTPUT_DIR points the tee at a tmp_path, exactly as job_manager derives
its own log dir.
"""

import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.callback_catcher import CallbackCatcher  # noqa: E402

MAX = 3
N = 4  # how many past the window we overflow by


def _entry(i):
    """A callback entry shaped like the real HTTP/DNS ones."""
    return {
        "id": f"cb{i:04d}",
        "type": "http",
        "timestamp": f"2026-10-02T00:00:{i:02d}+00:00",
        "path": f"/cb/{i}",
        "source_ip": "10.0.0.9",
    }


def _build(tmp_path, monkeypatch):
    """A catcher whose tee writes under tmp_path, with a tiny window."""
    monkeypatch.setenv("JOB_OUTPUT_DIR", str(tmp_path))
    catcher = CallbackCatcher()
    catcher._max_size = MAX
    return catcher


def test_received_counts_every_callback_not_just_the_survivors(tmp_path, monkeypatch):
    """The monotonic counter must not plateau when the ring evicts."""
    catcher = _build(tmp_path, monkeypatch)
    for i in range(MAX + N):
        catcher._store_callback(_entry(i))

    status = catcher.status()
    assert status["callbacks_received"] == MAX + N
    assert status["callbacks_total"] == MAX, "the ring is clipped to the window"
    assert status["callbacks_dropped"] == N, "received minus the survivors"
    assert status["max_storage"] == MAX


def test_jsonl_holds_every_callback_including_the_evicted_oldest(tmp_path, monkeypatch):
    """The .jsonl is the 100% spill: the entries evicted from memory are on disk."""
    catcher = _build(tmp_path, monkeypatch)
    for i in range(MAX + N):
        catcher._store_callback(_entry(i))

    status = catcher.status()
    assert status["callbacks_logged"] is True, "the tmp_path tee is writable"
    log_path = Path(status["callback_log_path"])
    assert log_path.exists()

    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == MAX + N, (
        f"the .jsonl must hold every callback; expected {MAX + N} lines, "
        f"got {len(lines)}"
    )

    logged_ids = [json.loads(ln)["id"] for ln in lines]
    assert logged_ids == [f"cb{i:04d}" for i in range(MAX + N)], (
        "the log is append-only, one line per callback, in arrival order"
    )

    # The earliest N were evicted from the in-memory ring but survive on disk.
    survivors = {c["id"] for c in catcher.get_callbacks(limit=MAX + N)}
    for i in range(N):
        ident = f"cb{i:04d}"
        assert ident not in survivors, f"{ident} should have been evicted from memory"
        assert ident in logged_ids, f"{ident} must survive in the .jsonl"
