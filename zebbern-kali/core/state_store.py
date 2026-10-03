"""Atomic on-disk JSON state store.

Generalised from ``network_pivot.NetworkPivotManager._save_state`` /
``_load_state``. The write discipline is unchanged in spirit: serialise into a
sibling temp file, then ``os.replace`` it over the destination, so a reader
only ever sees the previous whole file or the next whole file -- never a
half-written one -- and a crash mid-write damages only the throwaway temp while
the previous file survives intact.

Two things differ from the pivot original, each on its own merits:

* **A unique temp name per write.** The pivot manager uses a fixed
  ``state.json.tmp``, which is safe only because pivot operations are
  serialised by the operator. The job registry mutates its state from more than
  one thread at once (status is written from both the start path and the
  watcher). Two concurrent writers sharing one temp path would interleave their
  bytes into it and then race to ``os.replace`` the same file -- one replace
  moving a temp the other is still filling, or finding it already renamed away.
  A temp name carrying the writer's pid and thread id is distinct for any two
  writers that can run at the same instant (concurrent writers are by
  definition different threads, or different processes), so each ``os.replace``
  publishes one writer's complete file atomically and the two never contend for
  a source. The store therefore needs no external lock for *integrity*; a
  caller may still hold one if it wants a defined last-writer-wins order, but
  correctness does not depend on it.

* **Explicit ``encoding="utf-8"``.** The pivot original opens with the platform
  default, which on the Windows dev/test host is cp1252 -- the exact decode
  that has corrupted tool output here before. State is always written and read
  as UTF-8 so a non-ASCII byte round-trips the same on every host.

Measured platform note (not a defect): on Windows, ``os.replace`` raises
``PermissionError`` if another process has the destination open for reading at
that instant, so a ``save`` racing a concurrent reader can fail there. On the
POSIX container this store actually runs in, the replace over an open file
always succeeds. Integrity is unaffected either way -- a failed ``save`` leaves
the previous file whole and is simply retried by the next write; it never
publishes a partial file. A caller that must land a write under concurrent
Windows reads should retry ``save`` on ``PermissionError``.

Pure and importable on every platform (no ``pty`` / ``termios``), so it is
usable from the Windows test host with no stub.
"""

import json
import logging
import os
import threading

logger = logging.getLogger(__name__)


class StateStore:
    """Load and save a JSON-serialisable ``dict`` atomically.

    The destination's parent directory must already exist (the caller owns the
    directory, as the pivot manager does); ``save`` does not create it.
    """

    def __init__(self, path):
        # os.fspath accepts str and os.PathLike alike; keep it as a str so the
        # temp-name concatenation below is unambiguous.
        self.path = os.fspath(path)

    def _tmp_path(self):
        # pid + thread id makes the temp distinct for any two writers that can
        # execute concurrently, so no two os.replace calls ever share a source
        # file. Saves on one thread are serial and may reuse the name safely:
        # the previous replace has already consumed the temp.
        return "{0}.{1}.{2}.tmp".format(
            self.path, os.getpid(), threading.get_ident()
        )

    def save(self, data):
        """Write ``data`` as JSON and publish it with an atomic replace.

        On any failure before the replace completes (the open, ``json.dump``,
        or the replace itself) the partial temp is unlinked best-effort so no
        orphan accumulates beside the intact previous file, and the original
        exception is re-raised unchanged.
        """
        tmp_path = self._tmp_path()
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self.path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load(self):
        """Return the stored dict, or ``{}`` if there is nothing usable to load.

        An absent file is the normal "nothing saved yet" case and returns ``{}``
        silently. A file that is present but holds unparseable JSON, or JSON
        that is not an object, is logged at error level and treated as empty, so
        a corrupt file degrades to a fresh start rather than crashing the
        caller -- the same choice the pivot manager makes. A genuine I/O error
        (a permission fault, a disappearing mount) is deliberately *not*
        swallowed: it propagates so a real infrastructure fault surfaces instead
        of masquerading as empty state.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as exc:
            logger.error(
                "StateStore: ignoring corrupt JSON at %s: %s", self.path, exc
            )
            return {}
        if not isinstance(data, dict):
            logger.error(
                "StateStore: ignoring non-object JSON at %s (got %s)",
                self.path,
                type(data).__name__,
            )
            return {}
        return data
