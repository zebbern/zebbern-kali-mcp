"""`StateStore` persists a dict atomically and never hands back a torn file.

`core/state_store.py` generalises the pivot manager's atomic write (temp file
then `os.replace`) so the other session registries can reuse it. These tests
pin the contract that matters:

* round-trip -- what was saved loads back equal;
* an absent file loads as `{}` (the normal "nothing saved yet" case);
* a corrupt file loads as `{}` rather than raising (degrade, don't crash);
* a `json.dump` that fails mid-write leaves NO orphan temp and does NOT clobber
  the intact previous file -- the atomicity guarantee;
* two threads writing distinct payloads concurrently never let a reader observe
  a half-written file -- every successful read is one whole payload or the
  other.

`state_store.py` is pure and import-safe on Windows, so it imports by path like
the other backend-core tests here.
"""

import json
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import state_store as ss  # noqa: E402


class TestRoundTrip:
    def test_save_then_load_returns_equal_dict(self, tmp_path):
        store = ss.StateStore(tmp_path / "state.json")
        payload = {
            "jobs": {"job_1": {"status": "running", "cmd": "nmap"}},
            "count": 1,
            "unicode": "naïve — café",
        }
        store.save(payload)
        assert store.load() == payload

    def test_save_overwrites_a_previous_value(self, tmp_path):
        store = ss.StateStore(tmp_path / "state.json")
        store.save({"gen": 1})
        store.save({"gen": 2})
        assert store.load() == {"gen": 2}

    def test_accepts_a_str_path_too(self, tmp_path):
        store = ss.StateStore(str(tmp_path / "state.json"))
        store.save({"ok": True})
        assert store.load() == {"ok": True}


class TestLoadDegradesGracefully:
    def test_absent_file_loads_as_empty_dict(self, tmp_path):
        store = ss.StateStore(tmp_path / "does_not_exist.json")
        assert store.load() == {}

    def test_corrupt_json_loads_as_empty_dict(self, tmp_path, caplog):
        target = tmp_path / "state.json"
        target.write_text("{not: valid json", encoding="utf-8")
        store = ss.StateStore(target)
        with caplog.at_level("ERROR"):
            assert store.load() == {}
        assert any("corrupt JSON" in r.message for r in caplog.records)

    def test_non_object_json_loads_as_empty_dict(self, tmp_path, caplog):
        # Valid JSON, but a list violates the load()->dict contract.
        target = tmp_path / "state.json"
        target.write_text("[1, 2, 3]", encoding="utf-8")
        store = ss.StateStore(target)
        with caplog.at_level("ERROR"):
            assert store.load() == {}
        assert any("non-object JSON" in r.message for r in caplog.records)


class TestSaveIsAtomic:
    def test_failed_write_leaves_no_orphan_tmp_and_keeps_old_file(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "state.json"
        store = ss.StateStore(target)
        store.save({"keep": "me"})

        def boom(*args, **kwargs):
            raise OSError("disk full mid-write")

        # Patched after the temp file has already been opened for writing, so
        # this reproduces a dump that dies with an empty temp on disk.
        monkeypatch.setattr(ss.json, "dump", boom)

        with pytest.raises(OSError):
            store.save({"new": "value"})

        # No orphan temp accumulates on the exception path...
        assert list(tmp_path.glob("*.tmp")) == []
        # ...and the pre-existing file is byte-for-byte untouched.
        assert json.loads(target.read_text(encoding="utf-8")) == {"keep": "me"}


class TestConcurrentWriters:
    def test_two_writers_never_publish_a_half_written_file(self, tmp_path):
        """Drive two writer threads with distinct payloads while a reader
        samples the file; every successful read must be one whole payload or
        the other, never a torn or interleaved one.

        The integrity assertions here are the load-bearing ones. On Windows
        `os.replace` raises `PermissionError` when a reader holds the file open
        at that instant (a documented platform artifact, not a store defect, and
        a no-op on the POSIX target); the writer loop tolerates exactly that one
        error so the race keeps running, and fails loudly on any other.
        """
        store = ss.StateStore(tmp_path / "state.json")
        payload_a = {"who": "A", "body": ["a"] * 128}
        payload_b = {"who": "B", "body": ["b"] * 128}
        store.save(payload_a)  # seed so the first reads always find a file

        iterations = 600
        stop = threading.Event()
        writer_errors = []

        def writer(payload):
            for _ in range(iterations):
                if stop.is_set():
                    return
                try:
                    store.save(payload)
                except PermissionError:
                    # Windows reader-lock race; retry on the next loop.
                    continue
                except Exception as exc:  # pragma: no cover - a real defect
                    writer_errors.append(repr(exc))
                    return

        torn = []
        observed = set()

        def reader():
            while not stop.is_set():
                try:
                    obj = store.load()
                except PermissionError:
                    # Windows reader-lock race (mirror of the writer's): the
                    # file could not be opened while a replace was mid-flight.
                    # Not a torn read -- os.replace is atomic, so a read that
                    # does succeed sees a whole file. Skip and sample again.
                    continue
                except Exception as exc:  # pragma: no cover - a real defect
                    torn.append("load raised: %r" % (exc,))
                    continue
                if obj == {}:
                    # The seed guarantees a file exists; {} would mean load saw
                    # a corrupt/torn file and degraded. Treat as a violation.
                    torn.append("empty while writers active")
                elif obj == payload_a:
                    observed.add("A")
                elif obj == payload_b:
                    observed.add("B")
                else:
                    torn.append("neither payload: %r" % (obj,))

        tw1 = threading.Thread(target=writer, args=(payload_a,))
        tw2 = threading.Thread(target=writer, args=(payload_b,))
        tr = threading.Thread(target=reader)
        tr.start()
        tw1.start()
        tw2.start()
        tw1.join()
        tw2.join()
        stop.set()
        tr.join()

        assert writer_errors == [], (
            "a writer failed with something other than the tolerated Windows "
            "PermissionError: %s" % writer_errors
        )
        # The core guarantee: no reader ever saw a torn, interleaved, empty, or
        # otherwise non-whole file.
        assert torn == [], "reader observed non-whole state: %s" % torn[:5]
        # And the reader genuinely overlapped both writers, so the guarantee was
        # exercised against real interleaving rather than a static file.
        assert observed == {"A", "B"}, (
            "expected to observe both whole payloads, saw %s" % observed
        )
