"""Three tools stated more than they had established.

None of them invented a finding the way ad_password_spray did, which is why
they sat on the list a while, but each said something it had not checked.

fingerprint_waf returned `waf_present: false` with `wafw00f: null`. The image
has no wafw00f, the FileNotFoundError was swallowed by a bare `pass`, and the
null was indistinguishable from "wafw00f ran and found nothing" -- so the only
real WAF detector never ran and nothing said so, while the reply read as a
conclusion about the target.

fingerprint_url returned `server: null` while `headers_of_interest.server` held
"openresty/1.27.1.2". The field was only set for apache/nginx/iis/tomcat, so
anything else reported null next to the answer.

parse_tool_output returned `success: true` alongside `parsed.error` --
"No valid nmap XML found in output" -- so a caller checking success believed it
had a parse when it had an error message and an empty list. Its output_format
also accepted any string and read none of them.
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
    tool = object.__new__(wf.WebFingerprinter)
    tool.session = type("_S", (), {"get": staticmethod(lambda *a, **kw: _Response())})()
    return tool


class TestWafDetectionSaysWhatItChecked:
    def _run(self, monkeypatch, finger, *, wafw00f, headers=None):
        finger.session = type(
            "_S", (), {"get": staticmethod(lambda *a, **kw: _Response(headers or {}))}
        )()
        if wafw00f == "missing":
            monkeypatch.setattr(
                wf.subprocess, "run",
                lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("wafw00f")),
            )
        else:
            class _P:
                returncode = 0
                stdout = "is behind Cloudflare"
            monkeypatch.setattr(wf.subprocess, "run", lambda *a, **kw: _P())
        return finger.detect_waf("http://t/")

    def test_a_missing_wafw00f_is_reported_not_swallowed(self, monkeypatch, finger):
        result = self._run(monkeypatch, finger, wafw00f="missing")

        assert result["wafw00f_status"] == "not_installed", (
            "a bare None cannot be told from 'ran and found nothing'"
        )

    def test_only_the_methods_that_ran_are_listed(self, monkeypatch, finger):
        result = self._run(monkeypatch, finger, wafw00f="missing")

        assert result["detection_methods"] == ["header_signatures"]

    def test_a_negative_says_what_it_is_a_negative_about(self, monkeypatch, finger):
        """waf_present: false on a header heuristic alone is not 'no WAF'."""
        result = self._run(monkeypatch, finger, wafw00f="missing")

        assert result["waf_present"] is False
        assert "note" in result
        assert "not that the target has no WAF" in result["note"]

    def test_a_header_signature_still_reports_a_waf(self, monkeypatch, finger):
        result = self._run(
            monkeypatch, finger, wafw00f="missing",
            headers={"CF-RAY": "abc123", "Server": "cloudflare"},
        )

        assert result["waf_present"] is True
        assert "cloudflare" in result["wafs_detected"]

    def test_no_scary_note_when_wafw00f_actually_ran(self, monkeypatch, finger):
        result = self._run(monkeypatch, finger, wafw00f="present")

        assert "wafw00f" in result["detection_methods"]
        assert result.get("note", "") == ""


class TestTheServerFieldHoldsTheServer:
    def test_an_unrecognised_server_comes_from_the_header(self, finger, monkeypatch):
        """openresty is not in the apache/nginx/iis/tomcat list, and used to
        leave server null while the header said exactly what it was."""
        finger.session = type("_S", (), {"get": staticmethod(
            lambda *a, **kw: _Response({"Server": "openresty/1.27.1.2"})
        )})()

        result = finger.fingerprint("http://t/")

        detected = result.get("fingerprint", result)
        assert detected["server"] == "openresty/1.27.1.2"

    def test_no_server_header_leaves_it_unset(self, finger):
        finger.session = type("_S", (), {"get": staticmethod(
            lambda *a, **kw: _Response({})
        )})()

        result = finger.fingerprint("http://t/")

        detected = result.get("fingerprint", result)
        assert not detected["server"], "nothing said so, so claim nothing"


class TestParseOutputDoesNotContradictItself:
    def _parser(self):
        from unittest.mock import MagicMock
        import mcp_tools.output_parser as op

        registered = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda f: registered.setdefault(f.__name__, f) or f)
        op.register(mcp, MagicMock())
        return registered["parse_tool_output"]

    def test_a_parse_error_is_not_a_success(self):
        result = self._parser()(output="not xml at all", tool_name="nmap")

        assert result["success"] is False
        assert "No valid nmap XML" in result["error"]

    def test_the_parser_output_is_still_returned_on_failure(self):
        """Whatever it managed is worth keeping; only the claim changes."""
        result = self._parser()(output="not xml at all", tool_name="nmap")

        assert result["parsed"] is not None

    def test_an_unknown_output_format_is_rejected(self):
        """It used to be accepted and never read, so a typo looked honoured."""
        result = self._parser()(
            output="x", tool_name="nmap", output_format="not-a-format"
        )

        assert result["success"] is False
        assert "output_format" in result["error"]

    @pytest.mark.parametrize("fmt", ["auto", "xml", "jsonl", "text"])
    def test_the_documented_formats_are_accepted(self, fmt):
        line = '{"template-id":"t","info":{"name":"N","severity":"info"},"host":"h"}'

        result = self._parser()(output=line, tool_name="nuclei", output_format=fmt)

        assert result["success"] is True, f"{fmt} is documented and must work"

    def test_a_real_parse_still_succeeds(self):
        line = '{"template-id":"t","info":{"name":"N","severity":"info"},"host":"h"}'

        result = self._parser()(output=line, tool_name="nuclei")

        assert result["success"] is True
        assert result["parsed"]["finding_count"] == 1
