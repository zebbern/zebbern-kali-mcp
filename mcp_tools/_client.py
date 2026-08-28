"""HTTP client for communicating with the Kali Linux Tools API Server."""

import logging
import os
import threading
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlsplit

import requests

logger = logging.getLogger(__name__)


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


def _request_failure(
    method: str,
    endpoint: str,
    error: Exception,
    *,
    unexpected: bool = False,
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
        timeout: int = 300,
        api_token: Optional[str] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.api_token = (
            api_token if api_token is not None else os.environ.get("KALI_API_TOKEN", "")
        )
        self._connect_timeout = 10
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
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if params is None:
            params = {}
        try:
            response = self.request(
                "GET",
                endpoint,
                params=params,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("GET", endpoint, e)
        except Exception as e:
            return _request_failure("GET", endpoint, e, unexpected=True)

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = self.request(
                "POST",
                endpoint,
                json=json_data,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("POST", endpoint, e)
        except Exception as e:
            return _request_failure("POST", endpoint, e, unexpected=True)

    def heavy_tool_post(
        self, endpoint: str, json_data: Dict[str, Any], semaphore_timeout: int = 120
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
            return self.safe_post(endpoint, json_data)
        finally:
            self._heavy_semaphore.release()

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = self.request("DELETE", endpoint)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return _request_failure("DELETE", endpoint, e)
        except Exception as e:
            return _request_failure("DELETE", endpoint, e, unexpected=True)

    def execute_command(self, command: str) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")
