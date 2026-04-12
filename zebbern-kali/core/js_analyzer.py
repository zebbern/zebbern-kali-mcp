#!/usr/bin/env python3
"""
JavaScript Analyzer - Professional JS security analysis using industry tools
Tools integrated:
- Katana: ProjectDiscovery's web crawler for JS discovery
- SecretFinder: Dedicated JS secret finder by m4ll0k
- Nuclei: Template-based vulnerability scanning
- TruffleHog: High-entropy secret detection
- Custom regex patterns as fallback
"""

import os
import re
import json
import hashlib
import shutil
import subprocess
import logging
import requests
import tempfile
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class JSAnalyzer:
    """Professional JavaScript security analyzer using industry tools"""

    def __init__(self, output_dir: str = "/opt/zebbern-kali/js_analysis"):
        self.output_dir = output_dir
        self._ensure_dirs()

        # Tool paths — resolve via PATH instead of hardcoding
        self.katana_path = shutil.which("katana") or "/usr/local/bin/katana"
        self.secretfinder_path = "/opt/SecretFinder/SecretFinder.py"
        self.nuclei_path = shutil.which("nuclei") or "/usr/bin/nuclei"
        self.trufflehog_path = shutil.which("trufflehog") or "/usr/local/bin/trufflehog"

        # Check available tools
        self.available_tools = self._check_tools()

        # Fallback regex patterns for when tools aren't available
        self.secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
            "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
            "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "github_token": r"(?i)(gh[pous]_[A-Za-z0-9_]{36,255}|github[_\-]?token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_]{35,40}['\"])",
            "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
            "stripe_key": r"(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24,34}['\"]",
            "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
            "firebase_api": r"(?i)firebase(.{0,20})?['\"][A-Za-z0-9_]{39}['\"]",
            "heroku_api": r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
            "mailgun_key": r"key-[0-9a-zA-Z]{32}",
            "twilio_sid": r"AC[a-zA-Z0-9_\-]{32}",
            "twilio_token": r"(?i)twilio(.{0,20})?['\"][a-zA-Z0-9_\-]{32}['\"]",
            "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "square_token": r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
            "paypal_braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "azure_storage": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;",
            "basic_auth": r"(?i)(basic\s+)[a-zA-Z0-9=:_\+\/-]{5,100}",
            "bearer_token": r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.=]+",
            "api_key_generic": r"(?i)(api[_\-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,64}['\"]",
            "password_field": r"(?i)(password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"][^'\"]{4,64}['\"]",
            "connection_string": r"(?i)(mongodb|mysql|postgres|redis|amqp)://[^\s'\"]+",
            "private_ip": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "s3_bucket": r"(?i)(s3\.amazonaws\.com/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.s3\.amazonaws\.com)",
        }

        # Endpoint extraction patterns
        self.endpoint_patterns = [
            r'["\'](/api/[^"\'>\s]+)["\']',
            r'["\'](/v[0-9]+/[^"\'>\s]+)["\']',
            r'["\']https?://[^"\'>\s]+["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'baseURL\s*:\s*["\']([^"\']+)["\']',
        ]

    def _ensure_dirs(self):
        """Ensure output directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "downloads"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "reports"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "secretfinder"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "nuclei"), exist_ok=True)

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        tools = {}

        # Check Katana
        try:
            result = subprocess.run([self.katana_path, "-version"],
                                   capture_output=True, timeout=5)
            tools["katana"] = result.returncode == 0
        except:
            tools["katana"] = False

        # Check SecretFinder
        tools["secretfinder"] = os.path.exists(self.secretfinder_path)

        # Check Nuclei
        try:
            result = subprocess.run([self.nuclei_path, "-version"],
                                   capture_output=True, timeout=5)
            tools["nuclei"] = result.returncode == 0
        except:
            tools["nuclei"] = False

        # Check TruffleHog
        try:
            result = subprocess.run(["trufflehog", "--help"],
                                   capture_output=True, timeout=5)
            tools["trufflehog"] = result.returncode == 0
        except:
            tools["trufflehog"] = False

        # Check gau
        try:
            result = subprocess.run(["gau", "--version"],
                                   capture_output=True, timeout=5)
            tools["gau"] = True
        except:
            tools["gau"] = False

        # Check waybackurls
        try:
            result = subprocess.run(["waybackurls", "-h"],
                                   capture_output=True, timeout=5)
            tools["waybackurls"] = True
        except:
            tools["waybackurls"] = False

        logger.info(f"Available tools: {[k for k,v in tools.items() if v]}")
        return tools

    def discover_js_files(self, url: str, depth: int = 2,
                          use_tools: bool = True) -> Dict[str, Any]:
        """
        Discover all JavaScript files on a target using Katana and other tools.

        Args:
            url: Target URL to scan
            depth: Crawl depth (default: 2)
            use_tools: Use external tools for discovery

        Returns:
            List of discovered JS files with metadata
        """
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            domain = parsed.netloc

            discovered_js: Set[str] = set()
            discovered_endpoints: Set[str] = set()
            tools_used = []

            # Method 1: Use Katana (preferred)
            if use_tools and self.available_tools.get("katana"):
                katana_js = self._run_katana(url, depth)
                discovered_js.update(katana_js)
                tools_used.append("katana")

            # Method 2: Use gau for historical JS
            if use_tools and self.available_tools.get("gau"):
                gau_js = self._run_gau(domain)
                discovered_js.update(gau_js)
                tools_used.append("gau")

            # Method 3: Use waybackurls
            if use_tools and self.available_tools.get("waybackurls"):
                wayback_js = self._run_waybackurls(domain)
                discovered_js.update(wayback_js)
                tools_used.append("waybackurls")

            # Method 4: Fallback to manual spider
            if not tools_used:
                visited = set()
                self._spider_for_js(url, base_url, discovered_js,
                                   discovered_endpoints, visited, depth, 10)
                tools_used.append("builtin_spider")

            # Categorize JS files
            internal_js = []
            external_js = []

            for js_url in discovered_js:
                if domain in js_url:
                    internal_js.append(js_url)
                else:
                    external_js.append(js_url)

            result = {
                "success": True,
                "target": url,
                "tools_used": tools_used,
                "js_files": {
                    "total": len(discovered_js),
                    "internal": sorted(internal_js),
                    "external": sorted(external_js)
                },
                "endpoints": sorted(list(discovered_endpoints))[:100],
                "timestamp": datetime.now().isoformat()
            }

            # Save report
            report_file = os.path.join(
                self.output_dir, "reports",
                f"discovery_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(report_file, 'w') as f:
                json.dump(result, f, indent=2)

            result["report_file"] = report_file
            return result

        except Exception as e:
            logger.error(f"Error discovering JS files: {e}")
            return {"success": False, "error": str(e)}

    def _run_katana(self, url: str, depth: int = 2) -> Set[str]:
        """Use Katana for JS discovery."""
        discovered = set()
        try:
            cmd = [
                self.katana_path,
                "-u", url,
                "-d", str(depth),
                "-jc",  # JS crawl
                "-ef", "png,jpg,gif,css,woff,woff2,ttf,svg,ico",  # Exclude
                "-silent",
                "-nc",  # No color
                "-timeout", "10"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and ('.js' in line or 'javascript' in line.lower()):
                    # Filter out non-JS URLs
                    if not any(x in line.lower() for x in ['.json', '.jsp', '.css']):
                        discovered.add(line)

            logger.info(f"Katana found {len(discovered)} JS files")

        except subprocess.TimeoutExpired:
            logger.warning("Katana timed out")
        except Exception as e:
            logger.error(f"Katana error: {e}")

        return discovered

    def _run_gau(self, domain: str) -> Set[str]:
        """Use gau for historical URL discovery."""
        discovered = set()
        try:
            cmd = ["gau", "--subs", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and '.js' in line:
                    if not any(x in line.lower() for x in ['.json', '.jsp']):
                        discovered.add(line)

            logger.info(f"gau found {len(discovered)} JS URLs")

        except subprocess.TimeoutExpired:
            logger.warning("gau timed out")
        except Exception as e:
            logger.debug(f"gau error: {e}")

        return discovered

    def _run_waybackurls(self, domain: str) -> Set[str]:
        """Use waybackurls for historical JS discovery."""
        discovered = set()
        try:
            process = subprocess.Popen(
                ["waybackurls", domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = process.communicate(timeout=120)

            for line in stdout.strip().split('\n'):
                line = line.strip()
                if line and '.js' in line:
                    if not any(x in line.lower() for x in ['.json', '.jsp']):
                        discovered.add(line)

            logger.info(f"waybackurls found {len(discovered)} JS URLs")

        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning("waybackurls timed out")
        except Exception as e:
            logger.debug(f"waybackurls error: {e}")

        return discovered

    def _spider_for_js(self, url: str, base_url: str,
                       discovered_js: Set[str], discovered_endpoints: Set[str],
                       visited: Set[str], depth: int, timeout: int):
        """Fallback spider for JS discovery."""
        if depth <= 0 or url in visited:
            return

        visited.add(url)

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            content = response.text

            # Find script tags
            for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', content, re.I):
                js_url = match.group(1)
                if not js_url.startswith(('http://', 'https://')):
                    js_url = urljoin(url, js_url)
                discovered_js.add(js_url)

            # Extract endpoints
            for pattern in self.endpoint_patterns:
                for match in re.finditer(pattern, content):
                    endpoint = match.group(1) if match.lastindex else match.group(0)
                    if endpoint.startswith('/') or endpoint.startswith('http'):
                        discovered_endpoints.add(endpoint)

            # Follow links
            if depth > 1:
                for match in re.finditer(r'<a[^>]*href=["\']([^"\'#]+)["\']', content, re.I):
                    link = match.group(1)
                    if not link.startswith(('http://', 'https://')):
                        link = urljoin(url, link)
                    if base_url in link and link not in visited:
                        self._spider_for_js(link, base_url, discovered_js,
                                           discovered_endpoints, visited, depth - 1, timeout)

        except Exception as e:
            logger.debug(f"Spider error for {url}: {e}")

    def analyze_js_file(self, url: str, download: bool = True) -> Dict[str, Any]:
        """
        Analyze a JavaScript file for secrets using SecretFinder, TruffleHog, and Nuclei.

        Args:
            url: URL of the JS file to analyze
            download: Save a local copy

        Returns:
            Analysis results with secrets, endpoints, risk assessment
        """
        try:
            # Download the JS file
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            response = requests.get(url, headers=headers, timeout=30, verify=False)

            if response.status_code != 200:
                return {"success": False, "error": f"HTTP {response.status_code}"}

            content = response.text
            file_hash = hashlib.md5(content.encode()).hexdigest()[:16]

            # Save locally
            local_path = None
            if download:
                filename = url.split('/')[-1].split('?')[0] or "script.js"
                local_path = os.path.join(self.output_dir, "downloads", f"{file_hash}_{filename}")
                with open(local_path, 'w', encoding='utf-8') as f:
                    f.write(content)

            # Collect results from all tools
            all_secrets = []
            all_endpoints = []
            tools_used = []

            # Tool 1: SecretFinder (best for JS secrets)
            if self.available_tools.get("secretfinder") and local_path:
                sf_results = self._run_secretfinder(local_path)
                all_secrets.extend(sf_results.get("secrets", []))
                all_endpoints.extend(sf_results.get("endpoints", []))
                tools_used.append("secretfinder")

            # Tool 2: TruffleHog (entropy-based detection)
            if self.available_tools.get("trufflehog") and local_path:
                th_results = self._run_trufflehog(local_path)
                all_secrets.extend(th_results)
                tools_used.append("trufflehog")

            # Tool 3: Nuclei JS templates
            if self.available_tools.get("nuclei"):
                nuclei_results = self._run_nuclei_js(url)
                all_secrets.extend(nuclei_results)
                tools_used.append("nuclei")

            # Fallback: Custom regex if no tools available or as supplement
            regex_secrets = self._regex_scan(content)
            regex_endpoints = self._extract_endpoints(content)

            if not tools_used:
                all_secrets = regex_secrets
                all_endpoints = regex_endpoints
                tools_used.append("regex_patterns")
            else:
                # Merge without duplicates
                existing_values = {s.get("value", s.get("match", "")) for s in all_secrets}
                for s in regex_secrets:
                    if s.get("match") not in existing_values:
                        all_secrets.append(s)

            # Deduplicate endpoints
            all_endpoints = list(set(all_endpoints + regex_endpoints))

            # Detect frameworks
            frameworks = self._detect_frameworks(content)

            # Calculate risk score
            risk_score = self._calculate_risk(all_secrets)

            result = {
                "success": True,
                "url": url,
                "hash": file_hash,
                "size": len(content),
                "tools_used": tools_used,
                "secrets": all_secrets,
                "endpoints": sorted(all_endpoints)[:50],
                "frameworks": frameworks,
                "risk_score": risk_score,
                "risk_level": self._risk_level(risk_score),
                "timestamp": datetime.now().isoformat()
            }

            if local_path:
                result["local_path"] = local_path

            return result

        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            return {"success": False, "error": str(e), "url": url}

    def _run_secretfinder(self, file_path: str) -> Dict[str, Any]:
        """Run SecretFinder on a JS file."""
        results = {"secrets": [], "endpoints": []}

        try:
            output_file = os.path.join(
                self.output_dir, "secretfinder",
                f"sf_{os.path.basename(file_path)}_{datetime.now().strftime('%H%M%S')}.html"
            )

            cmd = [
                "python3", self.secretfinder_path,
                "-i", file_path,
                "-o", output_file
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            # Parse SecretFinder output (it outputs to both stdout and file)
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue

                # SecretFinder outputs in format: [TYPE] value
                if line.startswith('['):
                    bracket_end = line.find(']')
                    if bracket_end > 0:
                        secret_type = line[1:bracket_end]
                        value = line[bracket_end+1:].strip()

                        if secret_type.lower() in ['link', 'linkfinder', 'endpoint']:
                            results["endpoints"].append(value)
                        else:
                            results["secrets"].append({
                                "type": secret_type,
                                "value": value,
                                "source": "secretfinder"
                            })

            logger.info(f"SecretFinder found {len(results['secrets'])} secrets")

        except subprocess.TimeoutExpired:
            logger.warning("SecretFinder timed out")
        except Exception as e:
            logger.error(f"SecretFinder error: {e}")

        return results

    def _run_trufflehog(self, file_path: str) -> List[Dict[str, Any]]:
        """Run TruffleHog on a JS file."""
        secrets = []

        try:
            # Create a temp git repo for trufflehog (it expects git repos)
            # Or use filesystem mode if available
            cmd = [
                "trufflehog",
                "--regex",
                "--entropy=True",
                "--json",
                file_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            # Parse JSON output
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        finding = json.loads(line)
                        secrets.append({
                            "type": finding.get("reason", "high_entropy"),
                            "value": finding.get("stringsFound", [""])[0][:100],
                            "source": "trufflehog",
                            "path": finding.get("path", "")
                        })
                    except json.JSONDecodeError:
                        pass

            logger.info(f"TruffleHog found {len(secrets)} secrets")

        except subprocess.TimeoutExpired:
            logger.warning("TruffleHog timed out")
        except Exception as e:
            logger.debug(f"TruffleHog error: {e}")

        return secrets

    def _run_nuclei_js(self, url: str) -> List[Dict[str, Any]]:
        """Run Nuclei with JS-specific templates."""
        secrets = []

        try:
            # Use exposures and tokens templates
            cmd = [
                self.nuclei_path,
                "-u", url,
                "-t", "http/exposures/",
                "-t", "http/token-spray/",
                "-t", "javascript/",
                "-silent",
                "-json",
                "-timeout", "30"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        finding = json.loads(line)
                        secrets.append({
                            "type": finding.get("template-id", "nuclei_finding"),
                            "value": finding.get("matched-at", url),
                            "severity": finding.get("info", {}).get("severity", "info"),
                            "source": "nuclei",
                            "description": finding.get("info", {}).get("name", "")
                        })
                    except json.JSONDecodeError:
                        pass

            logger.info(f"Nuclei found {len(secrets)} findings")

        except subprocess.TimeoutExpired:
            logger.warning("Nuclei timed out")
        except Exception as e:
            logger.debug(f"Nuclei error: {e}")

        return secrets

    def _regex_scan(self, content: str) -> List[Dict[str, Any]]:
        """Fallback regex-based secret scanning."""
        secrets = []

        for pattern_name, pattern in self.secret_patterns.items():
            for match in re.finditer(pattern, content):
                matched_text = match.group(0)
                # Avoid duplicates
                if not any(s.get("match") == matched_text for s in secrets):
                    secrets.append({
                        "type": pattern_name,
                        "match": matched_text[:200],
                        "source": "regex",
                        "line": content[:match.start()].count('\n') + 1
                    })

        return secrets

    def _extract_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from JS content."""
        endpoints = set()

        for pattern in self.endpoint_patterns:
            for match in re.finditer(pattern, content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip('"\'')
                if endpoint and len(endpoint) > 1:
                    endpoints.add(endpoint)

        return list(endpoints)

    def _detect_frameworks(self, content: str) -> List[str]:
        """Detect JavaScript frameworks/libraries."""
        frameworks = []

        patterns = {
            "React": r"React\.|ReactDOM|useState|useEffect|createElement",
            "Angular": r"@angular|ng-|angular\.module",
            "Vue": r"Vue\.|new Vue|createApp|v-bind|v-if|v-for",
            "jQuery": r"\$\(|jQuery\(",
            "Lodash": r"_\.|lodash",
            "Axios": r"axios\.",
            "Moment": r"moment\(",
            "D3": r"d3\.",
            "Three.js": r"THREE\.",
            "Express": r"express\(",
            "Next.js": r"next/|__NEXT_DATA__",
            "Nuxt": r"nuxt|__NUXT__",
            "Webpack": r"webpackJsonp|__webpack_require__",
            "Gatsby": r"gatsby",
        }

        for name, pattern in patterns.items():
            if re.search(pattern, content):
                frameworks.append(name)

        return frameworks

    def _calculate_risk(self, secrets: List[Dict]) -> int:
        """Calculate risk score based on findings."""
        score = 0

        high_risk = ["aws_access_key", "aws_secret_key", "private_key",
                     "connection_string", "github_token", "stripe_key"]
        medium_risk = ["api_key_generic", "password_field", "firebase_api",
                       "slack_token", "jwt_token"]

        for secret in secrets:
            secret_type = secret.get("type", "").lower()
            severity = secret.get("severity", "").lower()

            if any(h in secret_type for h in high_risk) or severity == "critical":
                score += 30
            elif any(m in secret_type for m in medium_risk) or severity == "high":
                score += 15
            elif severity == "medium":
                score += 10
            else:
                score += 5

        return min(score, 100)

    def _risk_level(self, score: int) -> str:
        """Convert risk score to level."""
        if score >= 70:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"

    def analyze_multiple(self, urls: List[str], max_workers: int = 5) -> Dict[str, Any]:
        """Analyze multiple JS files in parallel."""
        results = []
        all_secrets = []
        total_risk = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.analyze_js_file, url): url for url in urls}

            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    results.append(result)

                    if result.get("success"):
                        all_secrets.extend(result.get("secrets", []))
                        total_risk = max(total_risk, result.get("risk_score", 0))

                except Exception as e:
                    results.append({"url": url, "success": False, "error": str(e)})

        return {
            "success": True,
            "files_analyzed": len(results),
            "total_secrets": len(all_secrets),
            "max_risk_score": total_risk,
            "max_risk_level": self._risk_level(total_risk),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }



# Create singleton instance
js_analyzer = JSAnalyzer()
