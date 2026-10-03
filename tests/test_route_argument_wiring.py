"""Routes must actually pass on what the wrappers send.

Both cases here were found by calling the tool and reading the reply, not by
any test: each looked fine to the suite and to the probe.

- tools_ssh_audit mapped scan_type to -1/-2, flags ssh-audit removed along with
  SSH1. scan_type defaults to "ssh2", so every default call died on
  "unrecognized arguments: -2" before it reached the target.
- api_fuzz_endpoint's wrapper sends "parameters" as a comma-separated string;
  the route read "params" and expected a dict, so the parameter list, the
  wordlist and the headers were all dropped. It fuzzed nothing and still
  answered success with parameters_tested empty.

The blueprints import flask and core.* but not the api.blueprints package, so
they load by path on Windows where the dotted import cannot.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


_PKG = "bp_under_test"


def _load(name):
    """Load a blueprint by path, with a package so its relative imports work.

    tools.py does `from ._helpers import streaming_tool_response`, which needs a
    parent package; the real api.blueprints package cannot be imported on
    Windows because its __init__ chain reaches termios.
    """
    blueprints = BACKEND_ROOT / "api" / "blueprints"
    if _PKG not in sys.modules:
        pkg = types.ModuleType(_PKG)
        pkg.__path__ = [str(blueprints)]
        sys.modules[_PKG] = pkg
    full = f"{_PKG}.{name}"
    spec = importlib.util.spec_from_file_location(full, str(blueprints / f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


def _client(mod):
    app = Flask(__name__)
    app.register_blueprint(mod.bp)
    return app.test_client()


def test_ssh_audit_no_longer_sends_the_flag_ssh_audit_removed(monkeypatch):
    mod = _load("tools")
    seen = {}

    class _Completed:
        returncode = 0
        stdout = "{}"
        stderr = ""

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        return _Completed()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    resp = _client(mod).post("/api/tools/ssh-audit", json={"target": "10.0.0.5"})

    assert resp.status_code == 200
    cmd = seen["cmd"]
    assert "-2" not in cmd, f"ssh-audit rejects -2: {cmd!r}"
    assert "-1" not in cmd
    assert "10.0.0.5" in cmd


def test_ssh_audit_says_ssh1_is_unsupported_rather_than_emitting_a_dead_flag():
    mod = _load("tools")
    resp = _client(mod).post(
        "/api/tools/ssh-audit", json={"target": "10.0.0.5", "scan_type": "ssh1"}
    )

    assert resp.status_code == 400
    assert "SSH1" in resp.get_json()["error"]


def test_fuzz_route_reads_the_key_the_wrapper_actually_sends(monkeypatch):
    mod = _load("api_security")
    seen = {}

    class _Tester:
        def api_fuzz_endpoint(self, **kwargs):
            seen.update(kwargs)
            return {"success": True}

    monkeypatch.setattr(mod, "api_tester", _Tester())
    resp = _client(mod).post(
        "/api/api-security/fuzz",
        json={"url": "http://t", "parameters": "id, q", "headers": "X-A: 1"},
    )

    assert resp.status_code == 200
    assert set(seen["params"]) == {"id", "q"}, (
        f"the wrapper's parameters were dropped: {seen!r}"
    )
    assert seen["headers"] == {"X-A": "1"}, "the header string was dropped"


def test_fuzz_route_still_accepts_a_dict_from_a_direct_caller(monkeypatch):
    mod = _load("api_security")
    seen = {}

    class _Tester:
        def api_fuzz_endpoint(self, **kwargs):
            seen.update(kwargs)
            return {"success": True}

    monkeypatch.setattr(mod, "api_tester", _Tester())
    _client(mod).post(
        "/api/api-security/fuzz",
        json={"url": "http://t", "params": {"id": "1"}, "headers": {"X-A": "1"}},
    )

    assert seen["params"] == {"id": "1"}
    assert seen["headers"] == {"X-A": "1"}


def test_graphql_fuzz_route_no_longer_demands_the_query_it_promised_to_generate(monkeypatch):
    """The wrapper documented query as "auto-generated from schema if empty"
    while the route answered 400 to exactly that call."""
    mod = _load("api_security")
    seen = {}

    class _Tester:
        def graphql_fuzz(self, **kwargs):
            seen.update(kwargs)
            return {"success": True}

    monkeypatch.setattr(mod, "api_tester", _Tester())
    resp = _client(mod).post("/api/api-security/graphql/fuzz", json={"url": "http://t"})

    assert resp.status_code == 200, resp.get_json()
    assert seen["query"] == ""


def test_graphql_fuzz_route_forwards_depth_and_variables(monkeypatch):
    """depth rode in the request body and was never read; variables are the
    only thing the fuzzer substitutes into."""
    mod = _load("api_security")
    seen = {}

    class _Tester:
        def graphql_fuzz(self, **kwargs):
            seen.update(kwargs)
            return {"success": True}

    monkeypatch.setattr(mod, "api_tester", _Tester())
    _client(mod).post(
        "/api/api-security/graphql/fuzz",
        json={"url": "http://t", "depth": 5, "variables": {"id": "1"}},
    )

    assert seen["depth"] == 5
    assert seen["variables"] == {"id": "1"}


def test_graphql_fuzz_route_still_requires_a_url(monkeypatch):
    mod = _load("api_security")
    resp = _client(mod).post("/api/api-security/graphql/fuzz", json={})

    assert resp.status_code == 400


def test_auth_bypass_route_normalizes_header_string_and_forwards_method(monkeypatch):
    """The wrapper sends headers as a "k: v" string and a method; the route
    used to pass the raw string through (crashing dict.update in the runner)
    and never forwarded method. Mirror the fuzz route: normalize to a dict and
    thread method."""
    mod = _load("api_security")
    seen = {}

    class _Tester:
        def auth_bypass_test(self, **kwargs):
            seen.update(kwargs)
            return {"success": True}

    monkeypatch.setattr(mod, "api_tester", _Tester())
    resp = _client(mod).post(
        "/api/api-security/auth-bypass",
        json={
            "url": "http://t",
            "headers": "X-Forwarded-For: 127.0.0.1",
            "method": "POST",
        },
    )

    assert resp.status_code == 200, resp.get_json()
    assert seen["headers"] == {"X-Forwarded-For": "127.0.0.1"}, (
        f"the header string was not normalized to a dict: {seen!r}"
    )
    assert seen["method"] == "POST", f"method was dropped: {seen!r}"


def test_auth_bypass_core_threads_method_and_survives_a_header_dict(monkeypatch):
    """The runner used to probe with a hardcoded requests.get and had no method
    param: a genuinely open POST endpoint read as no bypass. The no-auth and
    token-bypass probes must go through requests.request(method, ...), and
    req_headers.update on a real dict must not raise."""
    import core.api_security as cas

    request_calls = []
    get_calls = []

    class _Resp:
        status_code = 404

    def fake_request(method, url, **kwargs):
        request_calls.append((method, url))
        return _Resp()

    def fake_get(url, **kwargs):
        get_calls.append(url)
        return _Resp()

    def fake_post(url, **kwargs):
        return _Resp()

    monkeypatch.setattr(cas.requests, "request", fake_request)
    monkeypatch.setattr(cas.requests, "get", fake_get)
    monkeypatch.setattr(cas.requests, "post", fake_post)

    result = cas.api_tester.auth_bypass_test(
        "http://t", headers={"X-Forwarded-For": "127.0.0.1"}, method="POST"
    )

    assert result["success"] is True
    assert request_calls, "the no-auth/bypass probes never went through requests.request"
    assert all(m == "POST" for m, _ in request_calls), (
        f"method was not threaded into the probes: {request_calls!r}"
    )
    # No valid_token, so the baseline GET is skipped; both the no-auth and the
    # token-bypass probes must use requests.request, never requests.get.
    assert get_calls == [], f"a probe fell back to requests.get: {get_calls!r}"
