"""Browser automation endpoints using Playwright."""

import os
import json
import base64
import traceback
import subprocess
from flask import Blueprint, request, jsonify
from core.config import logger

bp = Blueprint("browser", __name__)

# Lazy-load Playwright to avoid import errors if not installed
_pw = None
_browser = None


def _get_browser():
    """Lazily initialize Playwright and a persistent Chromium browser."""
    global _pw, _browser
    if _browser is not None:
        try:
            # Check if the browser is still connected
            _browser.contexts  # noqa: B018 — access to check liveness
            return _browser
        except Exception:
            _browser = None
            _pw = None

    try:
        from playwright.sync_api import sync_playwright
        _pw = sync_playwright().start()
        _browser = _pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        return _browser
    except Exception as e:
        logger.error(f"Failed to start Playwright browser: {e}")
        raise


@bp.route("/api/browser/navigate", methods=["POST"])
def browser_navigate():
    """Navigate to a URL and return page content, title, and cookies.

    Body:
        url: Target URL
        wait_for: CSS selector to wait for (optional)
        timeout: Page load timeout ms (default 30000)
        headers: Extra HTTP headers dict (optional)
        cookies: Cookies to set before navigation (optional list of dicts)
    """
    try:
        params = request.json or {}
        url = params.get("url")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        wait_for = params.get("wait_for")
        timeout = params.get("timeout", 30000)
        headers = params.get("headers")
        cookies = params.get("cookies")

        browser = _get_browser()
        context = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=headers or {},
        )
        if cookies:
            context.add_cookies(cookies)

        page = context.new_page()
        page.set_default_timeout(timeout)

        response = page.goto(url, wait_until="networkidle", timeout=timeout)

        if wait_for:
            page.wait_for_selector(wait_for, timeout=timeout)

        result = {
            "success": True,
            "url": page.url,
            "title": page.title(),
            "status": response.status if response else None,
            "content": page.content(),
            "cookies": context.cookies(),
        }

        page.close()
        context.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in browser_navigate: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/browser/screenshot", methods=["POST"])
def browser_screenshot():
    """Take a screenshot of a URL.

    Body:
        url: Target URL
        full_page: Capture full page (default True)
        output_path: Where to save (default /app/tmp/screenshot.png)
        viewport_width: Browser width (default 1280)
        viewport_height: Browser height (default 720)
    """
    try:
        params = request.json or {}
        url = params.get("url")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        full_page = params.get("full_page", True)
        output_path = params.get("output_path", "/app/tmp/screenshot.png")
        vw = params.get("viewport_width", 1280)
        vh = params.get("viewport_height", 720)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        browser = _get_browser()
        context = browser.new_context(
            viewport={"width": vw, "height": vh},
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.screenshot(path=output_path, full_page=full_page)

        # Also return base64 for convenience
        with open(output_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        file_size = os.path.getsize(output_path)

        page.close()
        context.close()

        return jsonify({
            "success": True,
            "output_path": output_path,
            "size_bytes": file_size,
            "base64_preview": b64[:500] + "..." if len(b64) > 500 else b64,
        })
    except Exception as e:
        logger.error(f"Error in browser_screenshot: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/browser/execute-js", methods=["POST"])
def browser_execute_js():
    """Navigate to a URL and execute JavaScript.

    Body:
        url: Target URL
        script: JavaScript code to execute
        cookies: Cookies to set before navigation (optional)
    """
    try:
        params = request.json or {}
        url = params.get("url")
        script = params.get("script")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400
        if not script:
            return jsonify({"error": "script is required", "success": False}), 400

        cookies = params.get("cookies")

        browser = _get_browser()
        context = browser.new_context(ignore_https_errors=True)
        if cookies:
            context.add_cookies(cookies)

        page = context.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)

        result = page.evaluate(script)

        output = {
            "success": True,
            "url": page.url,
            "result": result,
        }

        page.close()
        context.close()
        return jsonify(output)
    except Exception as e:
        logger.error(f"Error in browser_execute_js: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/browser/intercept", methods=["POST"])
def browser_intercept():
    """Navigate and capture all network requests/responses.

    Body:
        url: Target URL
        filter_types: List of resource types to capture (optional, e.g. ["xhr", "fetch", "document"])
    """
    try:
        params = request.json or {}
        url = params.get("url")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        filter_types = params.get("filter_types")
        captured = []

        browser = _get_browser()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        def on_response(response):
            rtype = response.request.resource_type
            if filter_types and rtype not in filter_types:
                return
            try:
                body_text = ""
                try:
                    body_text = response.text()[:2000]
                except Exception:
                    pass
                captured.append({
                    "url": response.url,
                    "status": response.status,
                    "method": response.request.method,
                    "resource_type": rtype,
                    "headers": dict(response.headers),
                    "body_preview": body_text,
                })
            except Exception:
                pass

        page.on("response", on_response)
        page.goto(url, wait_until="networkidle", timeout=30000)

        output = {
            "success": True,
            "url": page.url,
            "title": page.title(),
            "requests_captured": len(captured),
            "requests": captured,
        }

        page.close()
        context.close()
        return jsonify(output)
    except Exception as e:
        logger.error(f"Error in browser_intercept: {e}")
        return jsonify({"error": str(e), "success": False}), 500
