"""The three in-process api-security scanners cannot orphan past the abort.

graphql_fuzz, api_fuzz_endpoint and rate_limit_test post with ``requests`` in a
loop INSIDE the Flask handler, so job_manager -- which launches shell commands,
not Python callables -- cannot adopt, tee or cancel them. Past the ~60s MCP
harness abort an unbounded loop keeps firing at the target with nobody
listening and nothing teed to disk: the orphan CLAUDE.md forbids. Each loop now
breaks on a count ceiling (API_REQUEST_CEILING) or a wall-clock deadline
(API_LOOP_BUDGET_SECONDS) and reports requests_capped / time_capped; the
reported total is the count ACTUALLY sent, never the old
``len(variables) * sum(len(p) ...)`` product.

core.api_security imports on Windows -- it reaches only core.logging_utils,
core.tool_config and core.command_executor, none of which pull in termios -- so
these drive the real methods with ``requests`` monkeypatched rather than
asserting on source text.
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import api_security  # noqa: E402


class _Resp:
    """A fast, harmless 200 that trips no rate-limit or finding path."""

    status_code = 200
    text = "ok"
    headers: dict = {}

    class _Elapsed:
        @staticmethod
        def total_seconds():
            return 0.0

    elapsed = _Elapsed()

    def json(self):
        return {"data": {}}


def _count_posts(monkeypatch):
    """Count every requests.post and answer each one instantly."""
    sent = []
    monkeypatch.setattr(
        api_security.requests, "post",
        lambda *a, **kw: sent.append(1) or _Resp(),
    )
    return sent


def _count_gets(monkeypatch):
    """Count every requests.get / requests.request and answer instantly."""
    sent = []

    def _get(*a, **kw):
        sent.append(1)
        return _Resp()

    monkeypatch.setattr(api_security.requests, "get", _get)
    monkeypatch.setattr(api_security.requests, "request",
                        lambda method, *a, **kw: _get())
    return sent


def test_both_bound_constants_exist():
    assert isinstance(api_security.API_REQUEST_CEILING, int)
    assert api_security.API_REQUEST_CEILING > 0
    assert isinstance(api_security.API_LOOP_BUDGET_SECONDS, (int, float))
    # The wall-clock deadline is the one that actually bounds orphan time, and
    # it only does so if it lands below the ~60s harness abort (and under the
    # 55s the reverse shell / callback defaults are held to).
    assert 0 < api_security.API_LOOP_BUDGET_SECONDS < 55


def test_graphql_fuzz_count_ceiling_caps_requests_sent(monkeypatch):
    sent = _count_posts(monkeypatch)
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 5)
    # One attack type with far more payloads than the ceiling, so a loop with
    # its break removed blows well past it.
    monkeypatch.setattr(api_security.api_tester, "fuzz_payloads",
                        {"sqli": [str(i) for i in range(100)]})
    result = api_security.api_tester.graphql_fuzz(
        url="http://t", query="query($x: String){ f(x: $x) }",
        variables={"x": "1"},
    )
    assert len(sent) <= 5, "the count ceiling must stop the loop"
    assert result["requests_capped"] is True
    assert result["time_capped"] is False
    # Honest total: what was sent, not len(variables) * sum(payloads).
    assert result["total_requests"] == len(sent)


def test_api_fuzz_endpoint_count_ceiling_caps_requests_sent(monkeypatch):
    sent = _count_gets(monkeypatch)
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 5)
    monkeypatch.setattr(api_security.api_tester, "fuzz_payloads",
                        {"sqli": [str(i) for i in range(100)]})
    result = api_security.api_tester.api_fuzz_endpoint(
        url="http://t", method="GET", params={"q": "1"},
    )
    assert result["requests_capped"] is True
    assert result["time_capped"] is False
    assert result["total_requests"] <= 5, "the count ceiling must stop the loop"
    # Honest total: the actual sent counter, not a params * payloads product.
    # One baseline GET runs before the loop and is not counted into the total.
    assert result["total_requests"] == len(sent) - 1


def test_rate_limit_test_count_ceiling_caps_requests_sent(monkeypatch):
    sent = _count_gets(monkeypatch)
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 5)
    result = api_security.api_tester.rate_limit_test(
        url="http://t", requests_count=200, delay=0,
    )
    assert result["requests_sent"] <= 5, "the count ceiling must stop the loop"
    assert result["requests_capped"] is True
    assert result["time_capped"] is False
    # requests_sent is len(results), already the honest count actually sent.
    assert len(sent) == result["requests_sent"]


def test_graphql_fuzz_wall_clock_deadline_stops_the_loop(monkeypatch):
    sent = _count_posts(monkeypatch)
    # A deadline below any real elapsed: the wall-clock break -- not the count
    # ceiling -- must be what stops it, which is the bound that actually caps
    # orphan time.
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 10_000)
    monkeypatch.setattr(api_security, "API_LOOP_BUDGET_SECONDS", -1)
    result = api_security.api_tester.graphql_fuzz(
        url="http://t", query="query($x: String){ f(x: $x) }",
        variables={"x": "1"},
    )
    assert result["time_capped"] is True
    assert result["requests_capped"] is False
    assert result["total_requests"] == len(sent)


def test_api_fuzz_endpoint_wall_clock_deadline_stops_the_loop(monkeypatch):
    _count_gets(monkeypatch)
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 10_000)
    monkeypatch.setattr(api_security, "API_LOOP_BUDGET_SECONDS", -1)
    result = api_security.api_tester.api_fuzz_endpoint(
        url="http://t", method="GET", params={"q": "1"},
    )
    assert result["time_capped"] is True
    assert result["requests_capped"] is False
    assert result["total_requests"] == 0


def test_rate_limit_test_wall_clock_deadline_stops_the_loop(monkeypatch):
    _count_gets(monkeypatch)
    monkeypatch.setattr(api_security, "API_REQUEST_CEILING", 10_000)
    monkeypatch.setattr(api_security, "API_LOOP_BUDGET_SECONDS", -1)
    result = api_security.api_tester.rate_limit_test(
        url="http://t", requests_count=200, delay=0,
    )
    assert result["time_capped"] is True
    assert result["requests_capped"] is False
    assert result["requests_sent"] == 0
