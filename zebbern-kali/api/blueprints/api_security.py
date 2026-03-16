"""API security testing endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.api_security import api_tester

bp = Blueprint("api_security", __name__)


@bp.route("/api/api-security/graphql/introspect", methods=["POST"])
def graphql_introspect():
    """Perform GraphQL introspection to discover schema."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = api_tester.graphql_introspect(
            url=url,
            headers=params.get("headers", {}),
            auth_token=params.get("auth_token", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"GraphQL introspection error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/graphql/fuzz", methods=["POST"])
def graphql_fuzz():
    """Fuzz a GraphQL endpoint with injection payloads."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        query = params.get("query", "")
        if not url or not query:
            return jsonify({"error": "url and query are required", "success": False}), 400

        result = api_tester.graphql_fuzz(
            url=url,
            query=query,
            variables=params.get("variables", {}),
            headers=params.get("headers", {}),
            auth_token=params.get("auth_token", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"GraphQL fuzz error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/jwt/analyze", methods=["POST"])
def jwt_analyze():
    """Analyze a JWT token for vulnerabilities."""
    try:
        params = request.json or {}
        token = params.get("token", "")
        if not token:
            return jsonify({"error": "token is required", "success": False}), 400

        result = api_tester.jwt_analyze(token=token)
        return jsonify(result)
    except Exception as e:
        logger.error(f"JWT analysis error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/jwt/crack", methods=["POST"])
def jwt_crack():
    """Attempt to crack a JWT secret."""
    try:
        params = request.json or {}
        token = params.get("token", "")
        if not token:
            return jsonify({"error": "token is required", "success": False}), 400

        result = api_tester.jwt_crack(
            token=token,
            wordlist=params.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
            max_attempts=params.get("max_attempts", 10000)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"JWT crack error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/fuzz", methods=["POST"])
def api_fuzz():
    """Fuzz a REST API endpoint."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = api_tester.api_fuzz_endpoint(
            url=url,
            method=params.get("method", "GET"),
            params=params.get("params", {}),
            data=params.get("data", {}),
            headers=params.get("headers", {})
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"API fuzz error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/rate-limit", methods=["POST"])
def rate_limit_test():
    """Test rate limiting on an endpoint."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = api_tester.rate_limit_test(
            url=url,
            method=params.get("method", "GET"),
            requests_count=params.get("requests_count", 100),
            delay=params.get("delay", 0)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Rate limit test error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/auth-bypass", methods=["POST"])
def auth_bypass_test():
    """Test authentication bypass techniques."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = api_tester.auth_bypass_test(
            url=url,
            valid_token=params.get("valid_token", ""),
            headers=params.get("headers", {})
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Auth bypass test error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/ffuf", methods=["POST"])
def ffuf_fuzz():
    """Fuzz API endpoints using FFUF."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url with FUZZ keyword is required", "success": False}), 400

        result = api_tester.ffuf_fuzz(
            url=url,
            wordlist=params.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
            method=params.get("method", "GET"),
            data=params.get("data", ""),
            headers=params.get("headers", {}),
            match_codes=params.get("match_codes", "200,201,204,301,302,307,401,403,405,500"),
            filter_codes=params.get("filter_codes", ""),
            rate=params.get("rate", 100),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"FFUF error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/arjun", methods=["POST"])
def arjun_discover():
    """Discover hidden API parameters using Arjun."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = api_tester.arjun_discover(
            url=url,
            method=params.get("method", "GET"),
            wordlist=params.get("wordlist", ""),
            headers=params.get("headers", {}),
            include_json=params.get("include_json", True),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Arjun error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/kiterunner", methods=["POST"])
def kiterunner_scan():
    """Discover API paths using Kiterunner."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        if not target:
            return jsonify({"error": "target is required", "success": False}), 400

        result = api_tester.kiterunner_scan(
            target=target,
            wordlist=params.get("wordlist", ""),
            assetnote=params.get("assetnote", True),
            content_types=params.get("content_types", "json"),
            max_connection_per_host=params.get("max_connection_per_host", 3),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Kiterunner error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/apifuzzer", methods=["POST"])
def apifuzzer_scan():
    """Fuzz API using OpenAPI/Swagger specification."""
    try:
        params = request.json or {}
        spec_url = params.get("spec_url", "")
        if not spec_url:
            return jsonify({"error": "spec_url is required", "success": False}), 400

        result = api_tester.apifuzzer_scan(
            spec_url=spec_url,
            target_url=params.get("target_url", ""),
            auth_header=params.get("auth_header", ""),
            test_level=params.get("test_level", 1),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"APIFuzzer error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/nuclei", methods=["POST"])
def nuclei_api_scan():
    """Scan API with Nuclei templates."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        if not target:
            return jsonify({"error": "target is required", "success": False}), 400

        result = api_tester.nuclei_api_scan(
            target=target,
            templates=params.get("templates", ""),
            severity=params.get("severity", ""),
            tags=params.get("tags", "api"),
            rate_limit=params.get("rate_limit", 150),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Nuclei API scan error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/newman", methods=["POST"])
def newman_run():
    """Run Postman collection with Newman."""
    try:
        params = request.json or {}
        collection = params.get("collection", "")
        if not collection:
            return jsonify({"error": "collection is required", "success": False}), 400

        result = api_tester.newman_run(
            collection=collection,
            environment=params.get("environment", ""),
            globals_file=params.get("globals_file", ""),
            iterations=params.get("iterations", 1),
            delay=params.get("delay", 0),
            additional_args=params.get("additional_args", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Newman error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/api-security/full-scan", methods=["POST"])
def full_api_scan():
    """Perform comprehensive API security scan."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        if not target:
            return jsonify({"error": "target is required", "success": False}), 400

        result = api_tester.full_api_scan(
            target=target,
            openapi_spec=params.get("openapi_spec", ""),
            wordlist=params.get("wordlist", ""),
            auth_header=params.get("auth_header", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Full API scan error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
