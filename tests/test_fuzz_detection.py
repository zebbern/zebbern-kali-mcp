"""api_fuzz_endpoint reported ten HIGH command injections against a static page.

It fetched a baseline response and then never looked at it, while treating the
bare substring "root" as evidence of command injection. Every React app ships
`<div id="root">`, so a single-page app that returned byte-identical HTML to
every payload came back as ten confirmed HIGH findings. A bare "49" did the
same for SSTI, and "/etc/passwd" was an indicator of traversal while also being
the payload, so any app that echoed its input looked exploited.

Confidently wrong is worse than silent: an agent acts on it.

Two properties have to hold together, and the second is why these tests exist
at all -- suppressing false positives by detecting nothing is the failure mode
this whole exercise has been about:

  1. anything the target says WITHOUT provocation is not evidence
  2. what a genuinely vulnerable target says still is
"""

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import api_security  # noqa: E402

# Every word that used to trigger a false positive, in an ordinary page.
NOISY_BASELINE = (
    "<!doctype html><html><body><div id='root'></div>"
    "<span>49 items</span><script>var x = undefined;</script></body></html>"
)


class _Resp:
    status_code = 200

    def __init__(self, text):
        self.text = text


def _run(monkeypatch, responder, baseline=NOISY_BASELINE):
    """Drive a fuzz run where the target answers `responder(payload)`."""

    def fake_get(url, params=None, **kwargs):
        values = [v for v in (params or {}).values() if v not in ("", "1")]
        if not values:
            return _Resp(baseline)
        return _Resp(responder(values[0]))

    monkeypatch.setattr(api_security.requests, "get", fake_get)
    return api_security.api_tester.api_fuzz_endpoint(
        url="http://t/", method="GET", params={"id": "1"}
    )


def _kinds(result):
    return {f["vulnerability"] for f in result["findings"]}


class TestNoiseIsNotEvidence:
    def test_a_page_that_ignores_every_payload_yields_nothing(self):
        """The whole bug in one case: identical HTML for every payload."""
        def unchanged(_payload):
            return NOISY_BASELINE

        result = _run(pytest.MonkeyPatch(), unchanged)

        assert result["findings"] == [], (
            "a page containing id='root' and '49' is not ten vulnerabilities"
        )
        assert result["parameters_tested"] == ["id"], "but it was still tested"

    def test_the_word_root_alone_is_not_command_injection(self, monkeypatch):
        """Deliberately NOT in the baseline: this has to fail on the indicator
        being too loose, not on the baseline happening to contain it too.
        Otherwise re-adding a bare "root" indicator passes every test."""
        result = _run(
            monkeypatch,
            lambda p: "<div id='root'>you sent " + p + "</div>",
            baseline="<html><body>nothing to see</body></html>",
        )

        assert "command_injection" not in _kinds(result), (
            "id='root' is markup; only uid=/gid= with digits is id(1) output"
        )

    def test_echoing_the_traversal_path_back_is_not_traversal(self, monkeypatch):
        """"/etc/passwd" was both the payload and the indicator."""
        result = _run(
            monkeypatch,
            lambda p: "No such file: " + p,
            baseline="<html><body>nothing to see</body></html>",
        )

        assert "path_traversal" not in _kinds(result)

    def test_a_template_returned_verbatim_was_not_evaluated(self, monkeypatch):
        """Reflecting {{7*7}} is not SSTI. Returning 49 without it is."""
        result = _run(
            monkeypatch,
            lambda p: "<p>searched for " + p + " (49 results)</p>",
            baseline="<html><body>nothing to see</body></html>",
        )

        assert "ssti" not in _kinds(result)

    def test_a_bare_number_in_the_page_is_not_a_confirmed_ssti(self, monkeypatch):
        """A page with 49 in it -- a count, a price, a version -- is consistent
        with 7*7 having been evaluated, and equally consistent with nothing
        having happened. Worth surfacing, not worth claiming."""
        result = _run(
            monkeypatch,
            lambda p: "<p>49 results found</p>",
            baseline="<html><body>nothing to see</body></html>",
        )

        ssti = [f for f in result["findings"] if f["vulnerability"] == "ssti"]
        assert ssti, "it is still a lead"
        assert all(f["confirmed"] is False for f in ssti), (
            "49 alone does not confirm template evaluation"
        )
        assert all(f["severity"] == "LOW" for f in ssti)
        assert "not proof" in ssti[0]["note"]


class TestRealVulnerabilitiesStillFire:
    def test_a_sql_error_is_still_found(self, monkeypatch):
        def vulnerable(payload):
            if "'" in payload:
                return "You have an error in your SQL syntax near '%s'" % payload
            return NOISY_BASELINE

        result = _run(monkeypatch, vulnerable)

        sqli = [f for f in result["findings"] if f["vulnerability"] == "sqli"]
        assert sqli, "a verbatim SQL error must still be reported"
        assert sqli[0]["severity"] == "HIGH"
        assert sqli[0]["confirmed"] is True

    def test_id_output_is_still_command_injection_even_beside_the_noise(self, monkeypatch):
        """The exact discrimination: real evidence in a response that ALSO
        carries every word that used to cause a false positive."""
        def vulnerable(payload):
            if ";" in payload or "`" in payload:
                return "uid=0(root) gid=0(root) groups=0(root)\n" + NOISY_BASELINE
            return NOISY_BASELINE

        result = _run(monkeypatch, vulnerable)

        cmdi = [f for f in result["findings"] if f["vulnerability"] == "command_injection"]
        assert cmdi, "uid=0(root) is command injection regardless of the markup around it"
        assert cmdi[0]["severity"] == "HIGH"

    def test_real_passwd_content_is_still_traversal(self, monkeypatch):
        def vulnerable(payload):
            if "../" in payload:
                return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/nologin"
            return NOISY_BASELINE

        result = _run(monkeypatch, vulnerable)

        assert "path_traversal" in _kinds(result)

    def test_an_evaluated_template_is_still_ssti(self, monkeypatch):
        """7777777 is 7*'7' evaluated -- not a number a page says by accident,
        so unlike a bare 49 this one is reported as confirmed."""
        def vulnerable(payload):
            if "7*7" in payload:
                return "<p>Result: 7777777</p>"
            return NOISY_BASELINE

        result = _run(monkeypatch, vulnerable)

        ssti = [f for f in result["findings"] if f["vulnerability"] == "ssti"]
        assert ssti
        assert any(f["confirmed"] for f in ssti), "7777777 is strong evidence"


class TestReflectionIsNotConfirmation:
    def test_a_reflected_script_tag_is_reported_but_not_claimed(self, monkeypatch):
        """Whether it executes depends on context and escaping, and neither is
        visible from a substring match."""
        result = _run(monkeypatch, lambda p: "<html>You searched for: " + p + "</html>")

        xss = [f for f in result["findings"] if f["vulnerability"] == "xss_reflection"]
        assert xss, "reflection is still worth surfacing"
        assert xss[0]["confirmed"] is False
        assert xss[0]["severity"] == "MEDIUM"
        assert "escaping" in xss[0]["note"]
        assert "xss" not in _kinds(result), "it must not be reported as confirmed XSS"


def test_every_finding_says_whether_it_is_confirmed(monkeypatch):
    """A caller filtering on `confirmed` read a missing key as neither true nor
    false. information_disclosure was the one shape that omitted it."""
    def noisy(payload):
        if "'" in payload:
            return "Traceback: You have an error in your SQL syntax near '%s'" % payload
        return "<html>You searched for: %s</html>" % payload

    result = _run(monkeypatch, noisy, baseline="<html><body>quiet</body></html>")

    assert result["findings"], "this target should produce findings"
    kinds = _kinds(result)
    assert "information_disclosure" in kinds, "the traceback should be surfaced"
    for finding in result["findings"]:
        assert isinstance(finding.get("confirmed"), bool), (
            f"{finding['vulnerability']} left confirmed unset: {finding!r}"
        )
        assert "note" in finding
