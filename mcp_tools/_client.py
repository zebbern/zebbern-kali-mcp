"""HTTP client for communicating with the Kali Linux Tools API Server."""

import logging
import os
import threading
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlsplit

import requests

logger = logging.getLogger(__name__)

# requests read timeout for every synchronous tool call. The invariant: THE
# CLIENT ALWAYS OUTLIVES THE BACKEND. Set below a backend budget it does not cap
# that budget, it destroys the answer -- requests raises ReadTimeout before the
# backend can serialize its reply, safe_post returns {"error": "... ReadTimeout"}
# and every byte of partial output is gone, so the timed_out/partial_results
# contract becomes unreachable. Worse, the backend never notices: it keeps
# running the subprocess with nobody listening, so the scan is orphaned rather
# than cancelled. This sat at 14400 while the table's longest entries (hydra,
# john) were 86400, which inverted exactly that.
#
# 90000 is 25 hours: strictly above max(TOOL_TIMEOUTS.values()) == 86400, with
# margin for the executor's 5s terminate window plus serializing the output.
# Raise it whenever a TOOL_TIMEOUTS entry grows past it -- the guard in
# tests/test_tool_timeouts.py enforces the ordering. It is not a practical
# hazard: the MCP client applies its own far shorter per-tool deadline, and an
# unreachable server still fails in DEFAULT_CONNECT_TIMEOUT seconds.
# mcp_server.py's --timeout defaults to this; keep the two in step.
DEFAULT_REQUEST_TIMEOUT = 90000  # 25 hours

# Connect phase only: an unreachable server must fail fast, so this stays short
# no matter how long the read timeout gets.
DEFAULT_CONNECT_TIMEOUT = 10


def _origin(url: str) -> tuple[str, str, Optional[int]]:
    """Return the normalized network origin for a URL."""
    parsed = urlsplit(url)
    default_ports = {"http": 80, "https": 443}
    scheme = parsed.scheme.lower()
    return (
        scheme,
        (parsed.hostname or "").lower(),
        parsed.port or default_ports.get(scheme),
    )


def _safe_origin(url: str) -> str:
    """Return ``scheme://host:port`` with any embedded credentials stripped."""
    scheme, host, port = _origin(url)
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def _server_reason(response) -> str:
    """Pull the backend's own explanation out of an error response, if it gave one."""
    if response is None:
        return ""
    try:
        body = response.json()
    except Exception:
        return ""
    if not isinstance(body, dict):
        return ""
    return str(body.get("error") or body.get("message") or "").strip()


def _request_failure(
    method: str,
    endpoint: str,
    error: Exception,
    *,
    unexpected: bool = False,
    server: Optional[str] = None,
) -> Dict[str, Any]:
    """Return useful failure metadata without logging URLs or request values."""
    response = getattr(error, "response", None)
    detail = (
        f"HTTP {response.status_code}"
        if response is not None
        else type(error).__name__
    )
    path = urlsplit(f"/{endpoint.lstrip('/')}").path or "/"
    label = "Unexpected request error" if unexpected else "Request failed"
    logger.error("%s %s failed: %s", method, path, detail)
    if server and isinstance(error, requests.exceptions.ConnectionError):
        # An agent cannot act on a bare "ConnectionError"; name the backend and
        # the remedy. ``server`` is the origin only, so no token or path leaks.
        return {
            "error": (
                f"{label}: {detail} - cannot reach the Kali API server at {server}. "
                "Start it with 'docker compose up -d', or point KALI_API_URL at a "
                "running server."
            ),
            "success": False,
        }
    reason = _server_reason(response)
    if reason:
        # The backend answers most failures with a body explaining exactly what
        # went wrong, then serves it with a non-2xx status. raise_for_status
        # fires first, so that explanation used to be discarded and the caller
        # saw only the status code.
        return {"error": f"{label}: {detail} - {reason}", "success": False}
    return {"error": f"{label}: {detail}", "success": False}


class _OriginBoundSession(requests.Session):
    """Strip the API token before Requests follows a cross-origin redirect."""

    def __init__(self):
        super().__init__()
        self.blocked_cross_origin_body_redirect = False

    def get_redirect_target(self, response):
        target = super().get_redirect_target(response)
        if target is None:
            return None
        next_url = urljoin(response.url, target)
        if (
            response.status_code in {307, 308}
            and response.request.body is not None
            and _origin(response.url) != _origin(next_url)
        ):
            self.blocked_cross_origin_body_redirect = True
            return None
        return target

    def rebuild_auth(self, prepared_request, response):
        super().rebuild_auth(prepared_request, response)
        if _origin(response.request.url) != _origin(prepared_request.url):
            prepared_request.headers.pop("X-API-Key", None)


class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server."""

    MAX_HEAVY_TASKS: int = 5
    MAX_REDIRECTS: int = 10

    def __init__(
        self,
        server_url: str,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
        api_token: Optional[str] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.api_token = (
            api_token if api_token is not None else os.environ.get("KALI_API_TOKEN", "")
        )
        self._connect_timeout = DEFAULT_CONNECT_TIMEOUT
        self._heavy_semaphore = threading.Semaphore(self.MAX_HEAVY_TASKS)
        logger.info("Initialized Kali Tools Client connecting to %s", server_url)

    def request_headers(
        self,
        additional: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Return request headers without exposing the configured token to logs."""
        headers: Dict[str, str] = {}
        if self.api_token:
            headers["X-API-Key"] = self.api_token
        if additional:
            headers.update(additional)
        return headers

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout=None,
        **kwargs,
    ) -> requests.Response:
        """Send a request while binding the configured API token to one origin."""
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        request_timeout = (
            timeout
            if timeout is not None
            else (self._connect_timeout, self.timeout)
        )
        with _OriginBoundSession() as session:
            session.max_redirects = self.MAX_REDIRECTS
            response = session.request(
                method,
                url,
                headers=self.request_headers(headers),
                timeout=request_timeout,
                **kwargs,
            )
            if session.blocked_cross_origin_body_redirect:
                response.close()
                raise requests.exceptions.RequestException(
                    "Refused a cross-origin redirect that would forward the request body",
                    response=response,
                )

        endpoint_path = urlsplit(url).path or "/"
        logger.debug(
            "%s %s -> %s", method.upper(), endpoint_path, response.status_code
        )
        return response

    def safe_get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        read_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """GET a JSON endpoint.

        ``read_timeout`` is opt-in and defaults to None, which leaves
        ``request`` to apply ``(connect, self.timeout)`` -- the unbounded
        behaviour every tool call depends on. Pass it only for a request that
        genuinely returns fast (a job poll, a job start), never for one that
        carries a tool's own budget.
        """
        if params is None:
            params = {}
        try:
            response = self.request(
                "GET",
                endpoint,
                params=params,
                timeout=(
                    (self._connect_timeout, read_timeout)
                    if read_timeout is not None
                    else None
                ),
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("GET", endpoint, e, server=_safe_origin(self.server_url))
        except Exception as e:
            return _request_failure("GET", endpoint, e, unexpected=True, server=_safe_origin(self.server_url))

    def safe_post(
        self,
        endpoint: str,
        json_data: Dict[str, Any],
        read_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """POST JSON and read the JSON reply.

        See ``safe_get`` for what ``read_timeout`` is for and when not to use it.
        """
        try:
            response = self.request(
                "POST",
                endpoint,
                json=json_data,
                timeout=(
                    (self._connect_timeout, read_timeout)
                    if read_timeout is not None
                    else None
                ),
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("POST", endpoint, e, server=_safe_origin(self.server_url))
        except Exception as e:
            return _request_failure("POST", endpoint, e, unexpected=True, server=_safe_origin(self.server_url))

    def heavy_tool_post(
        self,
        endpoint: str,
        json_data: Dict[str, Any],
        semaphore_timeout: int = 120,
        read_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        acquired = self._heavy_semaphore.acquire(timeout=semaphore_timeout)
        if not acquired:
            logger.warning(
                f"Semaphore timeout after {semaphore_timeout}s — too many concurrent heavy tasks"
            )
            return {
                "error": (
                    f"Too many concurrent heavy tasks (max {self.MAX_HEAVY_TASKS}). "
                    f"Timed out after {semaphore_timeout}s waiting for a slot."
                ),
                "success": False,
            }
        try:
            return self.safe_post(endpoint, json_data, read_timeout=read_timeout)
        finally:
            self._heavy_semaphore.release()

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = self.request("DELETE", endpoint)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("DELETE", endpoint, e, server=_safe_origin(self.server_url))
        except Exception as e:
            return _request_failure("DELETE", endpoint, e, unexpected=True, server=_safe_origin(self.server_url))

    def execute_command(self, command: str) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")
