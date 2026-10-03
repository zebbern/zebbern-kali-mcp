"""fingerprint_url hid an absent whatweb the way fingerprint_waf hid wafw00f.

_run_whatweb returned a bare Optional[Dict] and swallowed FileNotFoundError /
TimeoutExpired, so an absent whatweb key could not be told apart from "whatweb
ran and found nothing". detect_waf already emits wafw00f_status for exactly
this reason (see test_reporting_honesty); fingerprint() now always carries a
whatweb_status beside it, and keeps the whatweb payload only when it ran.
"""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core import web_fingerprinter as wf  # noqa: E402


class _Response:
    def __init__(self, headers=None, text="", status=200, url="http://t/"):
        self.headers = headers or {}
        self.text = text
        self.status_code = status
        self.url = url
        self.history = []
        self.cookies = {}
        self.content = text.encode()


@pytest.fixture
def finger():
    # __init__ opens a requests.Session; build without it and supply a fake.
    tool = object.__new__(wf.WebFingerprinter)
    tool.session = type(
        "_S", (), {"get": staticmethod(lambda *a, **kw: _Response())}
    )()
    return tool


def _whatweb_absent(monkeypatch):
    monkeypatch.setattr(
        wf.subprocess, "run",
        lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("whatweb")),
    )


class TestWhatwebStatusSaysWhatItChecked:
    def test_a_missing_whatweb_is_reported_not_swallowed(self, monkeypatch, finger):
        _whatweb_absent(monkeypatch)

        result = finger.fingerprint("http://t/")

        detected = result.get("fingerprint", result)
        assert detected["whatweb_status"] == "not_installed", (
            "a bare None cannot be told from 'ran and found nothing'"
        )

    def test_the_status_key_is_always_present(self, monkeypatch, finger):
        """Even when whatweb never ran, the field states that it did not."""
        _whatweb_absent(monkeypatch)

        result = finger.fingerprint("http://t/")

        detected = result.get("fingerprint", result)
        assert "whatweb_status" in detected
        # The payload key is absent precisely because whatweb did not run.
        assert "whatweb" not in detected
