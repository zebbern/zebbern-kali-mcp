#!/usr/bin/env python3
"""Web Application Fingerprinter - identifies technologies, CMS, and frameworks."""

import subprocess
import re
import json
import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from core.config import logger


class WebFingerprinter:
    """Fingerprint web applications to identify technologies."""
    
    # Technology signatures (headers, patterns)
    TECH_SIGNATURES = {
        # Web Servers
        "apache": {
            "headers": ["server:apache", "x-powered-by:php"],
            "patterns": ["apache", "mod_ssl", "mod_php"]
        },
        "nginx": {
            "headers": ["server:nginx"],
            "patterns": ["nginx"]
        },
        "iis": {
            "headers": ["server:microsoft-iis", "x-powered-by:asp.net"],
            "patterns": ["microsoft-iis", "asp.net"]
        },
        "tomcat": {
            "headers": ["server:apache-coyote"],
            "patterns": ["tomcat", "apache-coyote", "catalina"]
        },
        
        # CMS
        "wordpress": {
            "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
            "patterns": ["wp-content", "wp-includes", "wordpress"],
            "meta": ["generator:wordpress"]
        },
        "drupal": {
            "paths": ["/sites/default/", "/core/misc/drupal.js"],
            "patterns": ["drupal", "sites/all/", "sites/default/"],
            "meta": ["generator:drupal"]
        },
        "joomla": {
            "paths": ["/administrator/", "/components/", "/modules/"],
            "patterns": ["joomla", "com_content"],
            "meta": ["generator:joomla"]
        },
        "magento": {
            "paths": ["/skin/frontend/", "/js/mage/", "/app/etc/local.xml"],
            "patterns": ["magento", "mage/", "varien"]
        },
        
        # Frameworks
        "laravel": {
            "headers": ["x-powered-by:laravel"],
            "cookies": ["laravel_session"],
            "patterns": ["laravel"]
        },
        "django": {
            "headers": ["x-frame-options:deny"],
            "cookies": ["csrftoken", "sessionid"],
            "patterns": ["django", "__debug__"]
        },
        "rails": {
            "headers": ["x-runtime", "x-request-id"],
            "cookies": ["_session_id"],
            "patterns": ["rails", "action_controller"]
        },
        "express": {
            "headers": ["x-powered-by:express"],
            "patterns": ["express"]
        },
        "flask": {
            "cookies": ["session"],
            "patterns": ["werkzeug", "flask"]
        },
        "spring": {
            "headers": ["x-application-context"],
            "patterns": ["spring", "springframework"]
        },
        
        # JavaScript Frameworks
        "react": {
            "patterns": ["react", "__react", "reactdom", "_reactroot"]
        },
        "angular": {
            "patterns": ["ng-app", "ng-controller", "angular.js", "angular.min.js"]
        },
        "vue": {
            "patterns": ["vue.js", "vue.min.js", "__vue__", "v-bind", "v-model"]
        },
        "jquery": {
            "patterns": ["jquery", "jquery.min.js", "jquery-"]
        },
        
        # E-commerce
        "shopify": {
            "patterns": ["shopify", "cdn.shopify.com"],
            "meta": ["generator:shopify"]
        },
        "woocommerce": {
            "patterns": ["woocommerce", "wc-", "add-to-cart"]
        },
        
        # Other
        "cloudflare": {
            "headers": ["cf-ray", "server:cloudflare"],
            "patterns": ["cloudflare"]
        },
        "aws": {
            "headers": ["x-amz-", "server:amazons3"],
            "patterns": ["amazonaws.com", "aws-"]
        },
        "php": {
            "headers": ["x-powered-by:php"],
            "patterns": [".php", "phpsessid"]
        }
    }
    
    # Known vulnerability mappings
    VULN_MAPPINGS = {
        "wordpress": ["wpscan", "CVE-2023-xxxx"],
        "drupal": ["drupalgeddon", "CVE-2018-7600"],
        "joomla": ["joomscan", "com_fields sqli"],
        "apache": ["mod_ssl", "CVE-2021-41773"],
        "nginx": ["nginx off-by-slash"],
        "tomcat": ["ghostcat", "CVE-2020-1938"],
        "iis": ["webdav", "CVE-2017-7269"],
        "php": ["php-cgi", "type juggling"]
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def fingerprint(self, url: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Fingerprint a web application.
        
        Args:
            url: Target URL
            deep_scan: Perform more thorough scanning (slower)
            
        Returns:
            Detected technologies and potential vulnerabilities
        """
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            detected = {
                "technologies": [],
                "cms": None,
                "server": None,
                "frameworks": [],
                "js_libraries": [],
                "headers_of_interest": {},
                "potential_vulns": [],
                "paths_found": []
            }
            
            # Fetch main page
            try:
                response = self.session.get(url, timeout=15, allow_redirects=True)
                html = response.text.lower()
                headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                cookies = {k.lower(): v for k, v in response.cookies.items()}
            except Exception as e:
                return {"success": False, "error": f"Could not fetch URL: {e}"}
            
            # Analyze response
            detected["status_code"] = response.status_code
            detected["final_url"] = response.url
            
            # Check technologies
            for tech, signatures in self.TECH_SIGNATURES.items():
                found = False
                
                # Check headers
                for header_sig in signatures.get("headers", []):
                    key, val = header_sig.split(":", 1) if ":" in header_sig else (header_sig, "")
                    if key in headers and (not val or val in headers[key]):
                        found = True
                        break
                
                # Check cookies
                for cookie_sig in signatures.get("cookies", []):
                    if cookie_sig.lower() in cookies:
                        found = True
                        break
                
                # Check patterns in HTML
                for pattern in signatures.get("patterns", []):
                    if pattern.lower() in html:
                        found = True
                        break
                
                # Check meta tags
                for meta in signatures.get("meta", []):
                    if meta.lower() in html:
                        found = True
                        break
                
                if found:
                    # Categorize the technology
                    if tech in ["wordpress", "drupal", "joomla", "magento", "shopify"]:
                        detected["cms"] = tech
                        detected["technologies"].append(tech)
                    elif tech in ["apache", "nginx", "iis", "tomcat"]:
                        detected["server"] = tech
                        detected["technologies"].append(tech)
                    elif tech in ["react", "angular", "vue", "jquery"]:
                        detected["js_libraries"].append(tech)
                    elif tech in ["laravel", "django", "rails", "express", "flask", "spring"]:
                        detected["frameworks"].append(tech)
                    else:
                        detected["technologies"].append(tech)
                    
                    # Add potential vulnerabilities
                    if tech in self.VULN_MAPPINGS:
                        for vuln in self.VULN_MAPPINGS[tech]:
                            if vuln not in detected["potential_vulns"]:
                                detected["potential_vulns"].append(vuln)
            
            # Extract interesting headers
            interesting_headers = [
                "server", "x-powered-by", "x-aspnet-version", "x-generator",
                "x-drupal-cache", "x-runtime", "x-frame-options", "content-security-policy",
                "strict-transport-security", "x-xss-protection", "x-content-type-options"
            ]
            for h in interesting_headers:
                if h in headers:
                    detected["headers_of_interest"][h] = headers[h]
            
            # Deep scan - check for common paths
            if deep_scan:
                common_paths = [
                    "/robots.txt", "/sitemap.xml", "/.git/", "/.env",
                    "/admin/", "/login/", "/wp-admin/", "/administrator/",
                    "/phpmyadmin/", "/server-status", "/.htaccess",
                    "/api/", "/swagger/", "/graphql", "/console/"
                ]
                
                for path in common_paths:
                    try:
                        check_url = f"{base_url}{path}"
                        r = self.session.head(check_url, timeout=5, allow_redirects=False)
                        if r.status_code < 400:
                            detected["paths_found"].append({
                                "path": path,
                                "status": r.status_code
                            })
                    except:
                        continue
            
            # Try whatweb if available
            whatweb_result = self._run_whatweb(url)
            if whatweb_result:
                detected["whatweb"] = whatweb_result
            
            return {
                "success": True,
                "url": url,
                "fingerprint": detected
            }
            
        except Exception as e:
            logger.error(f"Fingerprint failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _run_whatweb(self, url: str) -> Optional[Dict]:
        """Run whatweb tool if available."""
        try:
            result = subprocess.run(
                ["whatweb", "--color=never", "-a", "3", url],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout:
                return {"raw": result.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None
    
    def scan_multiple(self, urls: List[str]) -> Dict[str, Any]:
        """Fingerprint multiple URLs."""
        results = {}
        for url in urls:
            results[url] = self.fingerprint(url)
        return {
            "success": True,
            "results": results,
            "scanned": len(urls)
        }
    
    def detect_waf(self, url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall.
        
        Args:
            url: Target URL
            
        Returns:
            WAF detection results
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            wafs_detected = []
            
            # Check headers for WAF signatures
            try:
                response = self.session.get(url, timeout=15)
                headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            except Exception as e:
                return {"success": False, "error": str(e)}
            
            waf_signatures = {
                "cloudflare": ["cf-ray", "server:cloudflare", "__cfduid"],
                "akamai": ["akamai", "x-akamai-"],
                "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
                "imperva": ["x-cdn:imperva", "incap_ses"],
                "sucuri": ["x-sucuri-", "sucuri-"],
                "f5_big_ip": ["x-wa-info", "bigipserver"],
                "barracuda": ["barra_counter_session"],
                "fortinet": ["fortiwafsid"],
                "modsecurity": ["mod_security", "modsec"]
            }
            
            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if ":" in sig:
                        key, val = sig.split(":", 1)
                        if key in headers and val in headers[key]:
                            wafs_detected.append(waf)
                            break
                    else:
                        for h, v in headers.items():
                            if sig in h or sig in v:
                                wafs_detected.append(waf)
                                break
            
            # Try wafw00f if available
            wafw00f_result = None
            try:
                result = subprocess.run(
                    ["wafw00f", "-a", url],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    wafw00f_result = result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            return {
                "success": True,
                "url": url,
                "wafs_detected": list(set(wafs_detected)),
                "waf_present": len(wafs_detected) > 0,
                "wafw00f": wafw00f_result
            }
            
        except Exception as e:
            logger.error(f"WAF detection failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_headers(self, url: str) -> Dict[str, Any]:
        """Get all response headers for analysis."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            response = self.session.get(url, timeout=15)
            
            # Analyze security headers
            security_headers = {
                "x-frame-options": "Protects against clickjacking",
                "x-content-type-options": "Prevents MIME-type sniffing",
                "x-xss-protection": "XSS filter",
                "strict-transport-security": "Enforces HTTPS",
                "content-security-policy": "Controls resource loading",
                "referrer-policy": "Controls referrer information",
                "permissions-policy": "Controls browser features"
            }
            
            headers_dict = dict(response.headers)
            security_analysis = {}
            missing_security = []
            
            for header, desc in security_headers.items():
                found = False
                for h in headers_dict:
                    if h.lower() == header:
                        security_analysis[header] = {
                            "present": True,
                            "value": headers_dict[h],
                            "description": desc
                        }
                        found = True
                        break
                if not found:
                    missing_security.append({"header": header, "description": desc})
            
            return {
                "success": True,
                "url": url,
                "status_code": response.status_code,
                "headers": headers_dict,
                "security_analysis": security_analysis,
                "missing_security_headers": missing_security
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global instance
web_fingerprinter = WebFingerprinter()
