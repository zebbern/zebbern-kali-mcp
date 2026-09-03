"""crt.sh returns a certificate's whole SAN list in one field.

name_value is newline-separated when a certificate covers several names, and
run_crtsh took each field whole. A multi-SAN certificate therefore became one
"subdomain" -- literally "*.anthropic.com\nanthropic.com" -- which no resolver,
httpx run or wordlist can take, and the dedupe missed every name that appeared
both alone and inside a blob. Against anthropic.com, 514 of 4037 certificates
carried more than one name.

It looked fine from outside: 200, success true, a long plausible list, and a
unique_subdomains count that was simply counting the wrong thing.
"""

import json
import sys
import urllib.request
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from tools import kali_tools  # noqa: E402

FUTURE = "2099-01-01T00:00:00"
PAST = "2000-01-01T00:00:00"


class _Response:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run(monkeypatch, entries, **params):
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **kw: _Response(entries)
    )
    return kali_tools.run_crtsh({"domain": "example.com", **params})


def test_a_multi_san_certificate_yields_one_entry_per_name(monkeypatch):
    result = _run(
        monkeypatch,
        [{"name_value": "*.example.com\nexample.com\napi.example.com", "not_after": FUTURE}],
    )

    assert result["subdomains"] == ["*.example.com", "api.example.com", "example.com"], (
        f"the SAN list came back as blobs: {result['subdomains']!r}"
    )
    assert result["unique_subdomains"] == 3


def test_a_name_seen_alone_and_inside_a_blob_is_not_counted_twice(monkeypatch):
    result = _run(
        monkeypatch,
        [
            {"name_value": "example.com", "not_after": FUTURE},
            {"name_value": "example.com\napi.example.com", "not_after": FUTURE},
        ],
    )

    assert result["subdomains"] == ["api.example.com", "example.com"]
    assert result["unique_subdomains"] == 2


def test_expired_certificates_are_still_dropped_wholesale(monkeypatch):
    """The expiry test is per-certificate, so it has to run before the split --
    otherwise an expired multi-SAN cert contributes names anyway."""
    result = _run(
        monkeypatch,
        [
            {"name_value": "live.example.com", "not_after": FUTURE},
            {"name_value": "dead.example.com\nalso-dead.example.com", "not_after": PAST},
        ],
    )

    assert result["subdomains"] == ["live.example.com"]


def test_expired_certificates_are_kept_when_asked_for(monkeypatch):
    result = _run(
        monkeypatch,
        [{"name_value": "old.example.com\nolder.example.com", "not_after": PAST}],
        include_expired=True,
    )

    assert result["subdomains"] == ["old.example.com", "older.example.com"]


def test_total_certificates_still_counts_certificates_not_names(monkeypatch):
    result = _run(
        monkeypatch,
        [{"name_value": "a.example.com\nb.example.com\nc.example.com", "not_after": FUTURE}],
    )

    assert result["total_certificates"] == 1, "one certificate, three names"
    assert result["unique_subdomains"] == 3
