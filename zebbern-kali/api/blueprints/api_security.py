"""API security testing endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.api_security import header_pairs, api_tester

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
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        # query used to be required here while the wrapper documented it as
        # "auto-generated from schema if empty", so the documented call was a
        # 400. The runner generates it now, and depth was accepted and dropped
        # on the floor the whole time.
        headers = params.get("headers") or {}
        if isinstance(headers, str):
            headers = dict(header_pairs(headers))
        result = api_tester.graphql_fuzz(
            url=url,
            query=params.get("query", ""),
            variables=params.get("variables") or {},
            headers=headers,
            auth_token=params.get("auth_token", ""),
            depth=int(params.get("depth", 3) or 3),
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

        # The wrapper sends "parameters" as the comma-separated string its
        # docstring describes, plus "headers" as a "k: v, k: v" string. This
        # route read "params" and expected dicts, so every one of them was
        # dropped on the floor: api_fuzz_endpoint fuzzed nothing at all and
        # still answered success with an empty parameters_tested.
        names = params.get("parameters") or params.get("params") or {}
        if isinstance(names, str):
            names = {n.strip(): "1" for n in names.split(",") if n.strip()}
        headers = params.get("headers") or {}
        if isinstance(headers, str):
            headers = dict(header_pairs(headers))

        result = api_tester.api_fuzz_endpoint(
            url=url,
            method=params.get("method", "GET"),
            params=names,
            data=params.get("data", {}),
            headers=headers,
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
            additional_args=params.get("additional_args", ""),
            background=params.get("background", False),
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
            additional_args=params.get("additional_args", ""),
            background=params.get("background", False),
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

