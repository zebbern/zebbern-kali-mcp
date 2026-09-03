"""api_graphql_fuzz could not send a request, and said the target was clean.

Payloads are substituted into a query's variables. The runner only ever looped
over `variables`, the MCP wrapper had no way to pass them, and the route
required a `query` while the wrapper documented it as "auto-generated from
schema if empty". So the documented call was a 400, and the working call
returned this, against an endpoint that echoes a SQL error straight back:

    {"success": true, "variables_tested": [], "findings": [],
     "total_requests": 0}

Zero requests, reported as a clean scan. `depth` was accepted and dropped.

Variables are now derived from the query's own declarations, or from the schema
when there is no query, and a run with nothing to fuzz is a failure with a
reason rather than an empty finding list.
"""

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import api_security  # noqa: E402
from core.api_security import build_query_from_schema, declared_variables  # noqa: E402

SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {
            "name": "Query",
            "kind": "OBJECT",
            "fields": [
                {"name": "version", "args": [], "type": {"name": "String", "kind": "SCALAR"}},
                {
                    "name": "user",
                    "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}],
                    "type": {"name": "User", "kind": "OBJECT"},
                },
            ],
        },
        {
            "name": "User",
            "kind": "OBJECT",
            "fields": [
                {"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR"}},
                {"name": "name", "args": [], "type": {"name": "String", "kind": "SCALAR"}},
            ],
        },
    ],
}


class TestDeclaredVariables:
    def test_a_query_declaring_variables_needs_no_second_argument(self):
        got = declared_variables("query($term: String, $limit: Int){ search(term: $term) }")

        assert set(got) == {"term", "limit"}

    def test_wrapped_types_still_parse(self):
        assert set(declared_variables("query($ids: [ID!]!){ x }")) == {"ids"}

    def test_a_query_with_no_variables_yields_none(self):
        assert declared_variables("{ version }") == {}


class TestGeneratedQuery:
    def test_a_field_taking_an_argument_becomes_a_fuzzable_query(self):
        query, variables = build_query_from_schema(SCHEMA, depth=3)

        assert variables == {"id": "1"}
        assert "$id: ID" in query
        assert "user(id: $id)" in query

    def test_the_generated_query_selects_something(self):
        """GraphQL rejects a bare object field, so a query without a selection
        set is a syntax error rather than a scan."""
        query, _ = build_query_from_schema(SCHEMA, depth=3)

        assert "{ id name }" in query

    def test_argument_free_fields_are_skipped(self):
        """`version` takes nothing, so there is nowhere to put a payload."""
        query, _ = build_query_from_schema(SCHEMA, depth=3)

        assert "version" not in query

    def test_a_schema_with_nothing_fuzzable_generates_nothing(self):
        bare = {"queryType": {"name": "Query"}, "types": [
            {"name": "Query", "kind": "OBJECT",
             "fields": [{"name": "version", "args": [], "type": {"name": "String"}}]}]}

        assert build_query_from_schema(bare, depth=3) == (None, {})


class TestNeverSilentlyEmpty:
    def test_a_query_with_variables_is_actually_fuzzed(self, monkeypatch):
        sent = []

        class _Resp:
            status_code = 200
            text = "ok"

        monkeypatch.setattr(
            api_security.requests, "post",
            lambda url, **kw: sent.append(kw.get("json")) or _Resp(),
        )
        result = api_security.api_tester.graphql_fuzz(
            url="http://t", query="query($term: String){ search(term: $term) }"
        )

        assert result["variables_tested"] == ["term"]
        assert result["total_requests"] > 0
        assert len(sent) > 0, "reported a result without sending a request"

    def test_a_query_with_no_variables_is_an_error_not_a_clean_scan(self, monkeypatch):
        monkeypatch.setattr(
            api_security.requests, "post",
            lambda *a, **kw: pytest.fail("should not have sent anything"),
        )
        result = api_security.api_tester.graphql_fuzz(url="http://t", query="{ version }")

        assert result["success"] is False, "zero requests must not read as clean"
        assert result["total_requests"] == 0
        assert "variable" in result["error"]

    def test_an_endpoint_that_is_not_graphql_is_an_error(self, monkeypatch):
        class _Resp:
            status_code = 404
            text = "nope"

            def json(self):
                return {}

        monkeypatch.setattr(api_security.requests, "post", lambda *a, **kw: _Resp())
        result = api_security.api_tester.graphql_fuzz(url="http://t")

        assert result["success"] is False
        assert result["introspection_enabled"] is False

    def test_the_query_actually_used_comes_back(self, monkeypatch):
        """A generated query the caller never saw makes "no findings"
        uninterpretable."""
        class _Resp:
            status_code = 200
            text = "ok"

            def json(self):
                return {"data": {"__schema": SCHEMA}}

        monkeypatch.setattr(api_security.requests, "post", lambda *a, **kw: _Resp())
        result = api_security.api_tester.graphql_fuzz(url="http://t")

        assert result["query_generated"] is True
        assert "user(id: $id)" in result["query"]
        assert result["variables_tested"] == ["id"]
