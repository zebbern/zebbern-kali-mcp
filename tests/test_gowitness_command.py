"""tools_gowitness built a command the installed gowitness rejects.

Three independent faults, each hidden behind the previous one:

1. `gowitness single <url>` -- v3 moved the verb under `scan` and takes the
   target as a flag. Live, this returned `unknown command "single" for
   "gowitness"`, which is tidy enough to read as "found nothing".
2. With the syntax fixed it could not start a browser: the image installs
   chromium through Playwright, which lands outside PATH, so gowitness's own
   lookup for `google-chrome` failed with "failed to initialize chrome
   context".
3. With a browser it reached the target (status 200, real title) but reported
   `have-screenshot=false` and wrote nothing -- a screenshot tool taking no
   screenshot -- until given an explicit --screenshot-path.

The command asserted here is the one verified live to produce a 291KB PNG.
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from tools import kali_tools  # noqa: E402


def _built_argv(monkeypatch, params):
    captured = {}
    monkeypatch.setattr(
        kali_tools, "execute_command_argv",
        lambda argv, **kw: captured.update(argv=list(argv), kw=kw) or {"job_id": "j"},
    )
    monkeypatch.setattr(kali_tools, "_which_or_go", lambda tool: "/root/go/bin/gowitness")
    monkeypatch.setattr(kali_tools.os.path, "exists", lambda p: True)
    monkeypatch.setattr(kali_tools.os, "makedirs", lambda p, exist_ok=False: None)
    monkeypatch.setattr(
        kali_tools, "_gowitness_chrome",
        lambda: "/root/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
    )
    kali_tools.run_gowitness(params)
    return captured["argv"]


def test_gowitness_uses_the_v3_scan_subcommand(monkeypatch):
    argv = _built_argv(monkeypatch, {"url": "http://lab:8888"})

    assert argv[1:3] == ["scan", "single"], (
        f"v3 rejects the bare verb with 'unknown command': {argv!r}"
    )
    assert "--url" in argv and "http://lab:8888" in argv
    assert argv[3] != "http://lab:8888", "the target is a flag, not positional"


def test_gowitness_is_pointed_at_the_browser_the_image_actually_has(monkeypatch):
    argv = _built_argv(monkeypatch, {"url": "http://lab:8888"})

    assert "--chrome-path" in argv, (
        "without this it fails with 'failed to initialize chrome context', "
        "because the image's chromium is a Playwright install outside PATH"
    )
    assert "/chrome-linux64/chrome" in argv[argv.index("--chrome-path") + 1]


def test_gowitness_saves_the_screenshot_somewhere_findable(monkeypatch):
    argv = _built_argv(monkeypatch, {"url": "http://lab:8888"})

    assert "--screenshot-path" in argv, (
        "the CWD-relative default produced have-screenshot=false and no file"
    )
    path = argv[argv.index("--screenshot-path") + 1]
    assert path.startswith("/"), f"an absolute path is what the caller can find: {path}"


def test_gowitness_uses_the_renamed_window_flags(monkeypatch):
    argv = _built_argv(monkeypatch, {"url": "http://lab:8888", "resolution": "1920x1080"})

    assert "--chrome-window-x" in argv and "1920" in argv
    assert "--chrome-window-y" in argv and "1080" in argv
    assert "--resolution-x" not in argv, "v3 renamed these; the old ones are rejected"


def test_gowitness_always_sends_threads(monkeypatch):
    """The wrapper documents a default of 4 while gowitness's own is 6, so
    omitting it when it 'looks default' silently gave 6."""
    argv = _built_argv(monkeypatch, {"url": "http://lab:8888", "threads": 4})

    assert "--threads" in argv
    assert argv[argv.index("--threads") + 1] == "4"
