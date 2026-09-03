"""API security testing tools."""

import json
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP

from ._autopromote import run_promotable


def register(mcp: FastMCP, kali_client) -> None:
    """Register API security tools."""

    @mcp.tool()
    def api_graphql_introspect(url: str) -> Dict[str, Any]:
        """
        Introspect a GraphQL endpoint to discover schema, types, and queries.

        Args:
            url: GraphQL endpoint URL
        """
        data = {"url": url}
        return kali_client.safe_post("api/api-security/graphql/introspect", data)

    @mcp.tool()
    def api_graphql_fuzz(url: str, query: str = "", variables: str = "",
                         depth: int = 3) -> Dict[str, Any]:
        """
        Fuzz a GraphQL endpoint for injection vulnerabilities.

        Payloads are substituted into the query's VARIABLES, so a query with no
        variables is fuzzed with nothing. url alone is enough: the schema is
        introspected and a query built against the first field taking an
        argument. If nothing fuzzable can be found you get an error saying so,
        never an empty finding list -- check `variables_tested` and
        `total_requests` to see what was actually sent.

        Args:
            url: GraphQL endpoint URL
            query: Query to fuzz, e.g. 'query($term: String){ search(term: $term)
                { title } }'. Generated from the schema when empty.
            variables: Variables to fuzz as comma-separated names ("id,term") or
                a JSON object ('{"term": "abc"}'). Taken from the query's own
                $name declarations when empty, which is usually what you want.
            depth: Nesting depth of a generated query's selection set (default 3).
                Ignored when you pass your own query.

        Returns:
            findings, plus the query actually used and query_generated.
        """
        parsed: Dict[str, Any] = {}
        text = (variables or "").strip()
        if text.startswith("{"):
            try:
                loaded = json.loads(text)
                if isinstance(loaded, dict):
                    parsed = loaded
            except ValueError:
                parsed = {}
        elif text:
            parsed = {name.strip(): "1" for name in text.split(",") if name.strip()}
        data = {"url": url, "query": query, "variables": parsed, "depth": depth}
        return kali_client.safe_post("api/api-security/graphql/fuzz", data)

    @mcp.tool()
    def api_jwt_analyze(token: str) -> Dict[str, Any]:
        """
        Analyze a JWT token for weaknesses.

        Args:
            token: The JWT token string to analyze

        Returns:
            Decoded header/payload, algorithm analysis, and potential vulnerabilities
        """
        data = {"token": token}
        return kali_client.safe_post("api/api-security/jwt/analyze", data)

    @mcp.tool()
    def api_jwt_crack(token: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        """
        Attempt to crack a JWT token's signing secret.

        Args:
            token: The JWT token to crack
            wordlist: Path to wordlist on the Kali server
        """
        data = {"token": token, "wordlist": wordlist}
        return kali_client.safe_post("api/api-security/jwt/crack", data)

    @mcp.tool()
    def api_fuzz_endpoint(
        url: str, method: str = "GET", parameters: str = "",
        wordlist: str = "", headers: str = "",
    ) -> Dict[str, Any]:
        """
        Fuzz an API endpoint with various payloads.

        Args:
            url: Target API endpoint URL
            method: HTTP method (GET, POST, PUT, DELETE)
            parameters: Comma-separated parameter names to fuzz
            wordlist: Custom wordlist path (default: built-in)
            headers: Custom headers as key:value pairs, comma-separated
        """
        data = {
            "url": url, "method": method, "parameters": parameters,
            "wordlist": wordlist, "headers": headers,
        }
        return kali_client.safe_post("api/api-security/fuzz", data)

    @mcp.tool()
    def api_rate_limit_test(url: str, requests_count: int = 100, method: str = "GET") -> Dict[str, Any]:
        """
        Test API rate limiting controls.

        Args:
            url: Target API endpoint
            requests_count: Number of requests to send (default: 100)
            method: HTTP method (default: GET)
        """
        data = {"url": url, "requests_count": requests_count, "method": method}
        return kali_client.safe_post("api/api-security/rate-limit", data)

    @mcp.tool()
    def api_auth_bypass_test(url: str, method: str = "GET", headers: str = "") -> Dict[str, Any]:
        """
        Test for authentication bypass vulnerabilities.

        Args:
            url: Target API endpoint
            method: HTTP method
            headers: Custom headers as key:value pairs
        """
        data = {"url": url, "method": method, "headers": headers}
        return kali_client.safe_post("api/api-security/auth-bypass", data)

    @mcp.tool()
    def api_ffuf_fuzz(
        url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        method: str = "GET", mc: str = "200,301,302,403",
        headers: str = "", data_str: str = "",
        background: bool = False,
    ) -> Dict[str, Any]:
        """
        Fuzz using ffuf for content discovery and parameter brute-forcing.

        Args:
            url: Target URL with FUZZ keyword (e.g., http://target/FUZZ)
            wordlist: Wordlist path on Kali server
            method: HTTP method
            mc: Match HTTP status codes (comma-separated)
            headers: Custom headers (key:value, comma-separated)
            data_str: POST data with FUZZ keyword
            background: Optional. This tool auto-promotes to a background job and
                waits inline up to ~50s; if it finishes you get the full result,
                otherwise you get {finished: false, status: "running", job_id, ...}
                to drive with job_status / job_output / job_cancel. Set
                background=True only to skip the inline wait and get the job_id
                immediately. Default False (auto-promote). Findings stream as
                newline-delimited JSON on stdout and are teed in full to the
                job's output_path.
        """
        data = {
            "url": url, "wordlist": wordlist, "method": method,
            "match_codes": mc, "headers": headers, "data": data_str,
        }
        return run_promotable(
            kali_client, "api/api-security/ffuf", data,
            heavy=False, background=background,
        )

    @mcp.tool()
    def api_kiterunner_scan(url: str, wordlist: str = "") -> Dict[str, Any]:
        """
        Scan API endpoints using Kiterunner for route discovery.

        Args:
            url: Target base URL
            wordlist: Custom wordlist or kiterunner routes file
        """
        data = {"target": url, "wordlist": wordlist}
        return kali_client.safe_post("api/api-security/kiterunner", data)

    @mcp.tool()
    def api_nuclei_scan(
        url: str, tags: str = "api", severity: str = "",
        background: bool = False,
    ) -> Dict[str, Any]:
        """
        Run Nuclei templates against API endpoints.

        Args:
            url: Target URL
            tags: Nuclei template tags (default: api)
            severity: Filter by severity (critical, high, medium, low)
            background: Optional. This tool auto-promotes to a background job and
                waits inline up to ~50s; if it finishes you get the full result,
                otherwise you get {finished: false, status: "running", job_id, ...}
                to drive with job_status / job_output / job_cancel. Set
                background=True only to skip the inline wait and get the job_id
                immediately. Default False (auto-promote). Findings are written
                as newline-delimited JSON on stdout and teed in full to the
                job's output_path -- but nuclei does not emit them
                incrementally: measured against a live target, template loading
                and its update check dominated and the findings appeared only at
                completion, around three minutes in, after minutes of nothing
                but a banner on stderr. Expect an empty-looking job for a while;
                that is startup, not a stall.
        """
        data = {"target": url, "tags": tags, "severity": severity}
        return run_promotable(
            kali_client, "api/api-security/nuclei", data,
            heavy=True, background=background,
        )

    @mcp.tool()
    def api_newman_run(collection: str, environment: str = "") -> Dict[str, Any]:
        """
        Run a Postman/Newman collection against API endpoints.

        Args:
            collection: Path to Postman collection JSON file
            environment: Path to Postman environment JSON file
        """
        data = {"collection": collection, "environment": environment}
        return kali_client.safe_post("api/api-security/newman", data)

