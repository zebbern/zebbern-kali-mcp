"""The reverse-shell session listing must iterate a snapshot of the dict.

``list_shell_sessions`` walks ``active_sessions`` and calls ``get_status()`` on
each manager, which runs a ~2s ``netstat`` per entry. A concurrent
start/stop that mutates the module-level ``active_sessions`` mid-walk raised
``RuntimeError: dictionary changed size during iteration``, surfacing as an
HTTP 500 from a read-only listing endpoint. The fix iterates
``list(active_sessions.items())`` so the walk runs over a snapshot taken
before the per-entry ``netstat``.

This is a SOURCE-TEXT guard. ``api.blueprints.reverse_shell`` pulls in
``metasploit_manager`` -> ``pty`` -> ``termios`` through the package
``__init__`` and cannot be imported on Windows, so the loop is asserted
against the file text rather than by exercising the route.
"""

from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
BLUEPRINT_PATH = BACKEND_ROOT / "api" / "blueprints" / "reverse_shell.py"

# The listing loop, snapshotted (fixed) and bare (the regression).
FIXED_LOOP = "for session_id, shell_manager in list(active_sessions.items()):"
BARE_LOOP = "for session_id, shell_manager in active_sessions.items():"


def _list_shell_sessions_body():
    """The text of ``list_shell_sessions``, from its def to the next route."""
    source = BLUEPRINT_PATH.read_text(encoding="utf-8")
    start = source.index("def list_shell_sessions(")
    nxt = source.index("@bp.route", start)
    return source[start:nxt]


def test_listing_iterates_a_snapshot_not_the_live_dict():
    body = _list_shell_sessions_body()
    assert FIXED_LOOP in body, (
        "list_shell_sessions must iterate list(active_sessions.items()) so a "
        "concurrent start/stop cannot raise 'dictionary changed size during "
        "iteration' during the per-entry netstat"
    )
    assert BARE_LOOP not in body, (
        "the listing loop iterates the live dict directly; a concurrent "
        "mutation during the per-entry get_status() netstat raises "
        "RuntimeError -> HTTP 500"
    )
