"""API security testing tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


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
    def api_graphql_fuzz(url: str, query: str = "", depth: int = 3) -> Dict[str, Any]:
        """
        Fuzz a GraphQL endpoint for vulnerabilities.

        Args:
            url: GraphQL endpoint URL
            query: Specific query to fuzz (auto-generated from schema if empty)
            depth: Fuzzing depth (default: 3)
        """
        data = {"url": url, "query": query, "depth": depth}
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
        data = {"url": url, "requests": requests_count, "method": method}
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
        """
        data = {
            "url": url, "wordlist": wordlist, "method": method,
            "mc": mc, "headers": headers, "data": data_str,
        }
        return kali_client.safe_post("api/api-security/ffuf", data)

    @mcp.tool()
    def api_kiterunner_scan(url: str, wordlist: str = "") -> Dict[str, Any]:
        """
        Scan API endpoints using Kiterunner for route discovery.

        Args:
            url: Target base URL
            wordlist: Custom wordlist or kiterunner routes file
        """
        data = {"url": url, "wordlist": wordlist}
        return kali_client.safe_post("api/api-security/kiterunner", data)

    @mcp.tool()
    def api_apifuzzer_scan(url: str, spec_url: str = "", method: str = "GET") -> Dict[str, Any]:
        """
        Fuzz an API using APIFuzzer with OpenAPI/Swagger spec.

        Args:
            url: Target API base URL
            spec_url: OpenAPI/Swagger specification URL
            method: HTTP method
        """
        data = {"url": url, "spec_url": spec_url, "method": method}
        return kali_client.safe_post("api/api-security/apifuzzer", data)

    @mcp.tool()
    def api_nuclei_scan(url: str, tags: str = "api", severity: str = "") -> Dict[str, Any]:
        """
        Run Nuclei templates against API endpoints.

        Args:
            url: Target URL
            tags: Nuclei template tags (default: api)
            severity: Filter by severity (critical, high, medium, low)
        """
        data = {"url": url, "tags": tags, "severity": severity}
        return kali_client.heavy_tool_post("api/api-security/nuclei", data)

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

    @mcp.tool()
    def api_full_scan(url: str) -> Dict[str, Any]:
        """
        Run a comprehensive API security scan combining multiple tools.

        Args:
            url: Target API base URL

        Returns:
            Combined results from multiple API security tests
        """
        data = {"url": url}
        return kali_client.safe_post("api/api-security/full-scan", data)
