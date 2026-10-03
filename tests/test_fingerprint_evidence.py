"""fingerprint() used to assert a technology from a bare body-text mention.

A signature's `patterns` were matched as plain substrings against the response
body, so a page that merely *named* a technology -- a blog post about
Cloudflare, a bundle whose filename contains "jquery" -- was reported as
*running* it, in `technologies`/`js_libraries` beside a vuln list. The loop now
separates evidence by strength: a header, a cookie, or a resource/path/CDN
reference (RESOURCE_PATTERNS) is strong and promotes the tech; a bare body
substring is weak and reported under `body_mentions`, which is not a claim the
tech runs here. Every match is recorded under `evidence[tech]` with its
provenance ('header:'/'cookie:'/'body:'/'meta:').
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
def finger(monkeypatch):
    # __init__ opens a requests.Session; build without it and supply a fake.
    tool = object.__new__(wf.WebFingerprinter)
    tool.session = type(
        "_S", (), {"get": staticmethod(lambda *a, **kw: _Response())}
    )()
    # whatweb is irrelevant here and not installed in CI; keep it from running
    # so the behaviour under test does not depend on the environment.
    monkeypatch.setattr(
        wf.subprocess, "run",
        lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("whatweb")),
    )
    return tool


def _fp(finger, *, headers=None, text=""):
    finger.session = type(
        "_S", (),
        {"get": staticmethod(lambda *a, **kw: _Response(headers or {}, text))},
    )()
    result = finger.fingerprint("http://t/")
    return result.get("fingerprint", result)


class TestBodyMentionIsNotAClaim:
    def test_a_bare_body_mention_is_not_reported_as_running(self, finger):
        # A page that merely writes the words -- no CF-RAY header, no
        # jquery.min.js resource, just prose.
        detected = _fp(
            finger,
            text="a blog post about cloudflare and the jquery library",
        )

        assert "cloudflare" not in detected["technologies"]
        assert "jquery" not in detected["js_libraries"]
        assert "cloudflare" in detected["body_mentions"]
        assert "jquery" in detected["body_mentions"]
        # provenance is recorded, and it is body-only for both
        assert detected["evidence"]["cloudflare"] == ["body:cloudflare"]
        assert detected["evidence"]["jquery"] == ["body:jquery"]
        # a weak-only match adds no vuln claims
        assert detected["potential_vulns"] == []

    def test_the_note_explains_body_mentions(self, finger):
        detected = _fp(finger, text="mentions cloudflare")
        assert "body_mentions" in detected["detection_note"]
        assert "not proof" in detected["detection_note"]


class TestStrongEvidencePromotes:
    def test_a_header_promotes_the_tech_with_header_provenance(self, finger):
        detected = _fp(finger, headers={"CF-RAY": "7a1b2c3d"})

        assert "cloudflare" in detected["technologies"]
        assert "cloudflare" not in detected["body_mentions"]
        assert "header:cf-ray" in detected["evidence"]["cloudflare"]

    def test_a_resource_reference_promotes_the_tech(self, finger):
        detected = _fp(
            finger,
            text='<link href="/wp-content/themes/x/style.css">'
                 '<script src="/js/jquery.min.js"></script>',
        )

        assert detected["cms"] == "wordpress"
        assert "jquery" in detected["js_libraries"]
        assert "wordpress" not in detected["body_mentions"]
        assert "jquery" not in detected["body_mentions"]
        # the strong body evidence is recorded with body: provenance
        assert "body:wp-content" in detected["evidence"]["wordpress"]
        assert "body:jquery.min.js" in detected["evidence"]["jquery"]
